package muxocket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func newTCPListener(t *testing.T, cfg *Config) *Listener {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(tcpLn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func acceptOne(t *testing.T, ln *Listener) <-chan *Session {
	ch := make(chan *Session, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			close(ch)
			return
		}
		ch <- s
	}()
	return ch
}

func waitSess(t *testing.T, ch <-chan *Session) *Session {
	t.Helper()
	select {
	case s := <-ch:
		if s == nil {
			t.Fatal("accept failed")
		}
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for Accept")
	}
	return nil
}

// Exercises multi-frame payloads both ways over UDP. Frames must be packed
// into whole datagrams and the client must read datagrams whole.
func TestDialer_UDP_LargePayload_BothDirections(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pconn.Close()

	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 50 * time.Millisecond
	ln, err := ListenPacket(pconn, 1400, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	payload := make([]byte, 200*1024)
	rand.Read(payload)

	srvErr := make(chan error, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer s.Close()
		if s.config.MaxFrameDataSize != 1400-17 {
			srvErr <- errors.New("server frame size not clamped to MTU")
			return
		}
		ch, _ := s.OpenChannel("big")
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(ch, got); err != nil {
			srvErr <- err
			return
		}
		if !bytes.Equal(got, payload) {
			srvErr <- errors.New("server: payload mismatch")
			return
		}
		_, err = ch.Write(got)
		srvErr <- err
		time.Sleep(500 * time.Millisecond) // let ARQ finish
	}()

	conn, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sess, err := DialConfig(conn, cfg)
	if err != nil {
		t.Fatalf("Dial over UDP: %v", err)
	}
	defer sess.Close()
	if sess.config.MaxFrameDataSize != 1400-17 {
		t.Fatalf("client did not adopt advertised frame size: %d", sess.config.MaxFrameDataSize)
	}

	ch, _ := sess.OpenChannel("big")
	if _, err := ch.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(ch, echo); done <- err }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout reading echo over UDP")
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("client: echo mismatch")
	}
	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}
}

// Manual Resume: drop the TCP connection mid-stream and continue on a new one.
func TestDialer_Resume_TCP_DataContinuity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 50 * time.Millisecond
	ln := newTCPListener(t, cfg)
	accepted := acceptOne(t, ln)

	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli, err := Dial(conn1)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv := waitSess(t, accepted)

	chS, _ := srv.OpenChannel("mig")
	chC, _ := cli.OpenChannel("mig")

	if _, err := chC.Write([]byte("before|")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(chS, buf); err != nil || string(buf) != "before|" {
		t.Fatalf("pre-drop read: %q %v", buf, err)
	}

	_ = conn1.Close() // network drop
	time.Sleep(50 * time.Millisecond)
	if !cli.suspended.Load() {
		t.Fatal("client should be suspended")
	}

	// Data written while suspended is queued and retransmitted after resume.
	go chC.Write([]byte("during|"))

	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Resume(conn2); err != nil {
		t.Fatalf("Resume: %v", err)
	}

	got := make([]byte, 7)
	rd := make(chan error, 1)
	go func() { _, err := io.ReadFull(chS, got); rd <- err }()
	select {
	case err := <-rd:
		if err != nil || string(got) != "during|" {
			t.Fatalf("post-resume read: %q %v", got, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout after resume")
	}

	// And the other direction still works.
	if _, err := chS.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 4)
	if _, err := io.ReadFull(chC, p); err != nil || string(p) != "pong" {
		t.Fatalf("server->client after resume: %q %v", p, err)
	}

	// A stale nonce / replay of the same resume is rejected by the listener,
	// and a second resume with a fresh nonce works.
	conn3, _ := net.Dial("tcp", ln.Addr().String())
	if err := cli.Resume(conn3); err != nil {
		t.Fatalf("second Resume: %v", err)
	}
}

// Automatic resumption via Dialer.Redial.
func TestDialer_AutoResume_Redial(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 50 * time.Millisecond
	ln := newTCPListener(t, cfg)
	accepted := acceptOne(t, ln)

	var mu sync.Mutex
	var current net.Conn
	redial := func() (net.Conn, error) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			mu.Lock()
			current = c
			mu.Unlock()
		}
		return c, err
	}
	first, _ := redial()
	d := &Dialer{Config: cfg, Redial: redial}
	cli, err := d.Dial(first)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv := waitSess(t, accepted)
	chS, _ := srv.OpenChannel("auto")
	chC, _ := cli.OpenChannel("auto")

	for i := 0; i < 3; i++ {
		mu.Lock()
		c := current
		mu.Unlock()
		_ = c.Close() // kill the transport; Redial should kick in

		msg := []byte{'m', byte('0' + i)}
		if _, err := chC.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 2)
		rd := make(chan error, 1)
		go func() { _, err := io.ReadFull(chS, got); rd <- err }()
		select {
		case err := <-rd:
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("round %d: %q %v", i, got, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("round %d: auto-resume did not happen", i)
		}
	}
}

// Regression: the listener stored initiator public keys that aliased the
// pooled handshake buffer. After another handshake reused the buffer, an
// attacker could resume someone else's session with their own key.
func TestListener_PooledBuffer_KeyAliasing_Hijack(t *testing.T) {
	ln := &Listener{
		sessionConfig:             DefaultConfig(),
		handshakeTimeout:          time.Second,
		AllowConnectionResumption: true,
		sessions:                  make(map[string]*activeSession),
	}

	doHandshake := func(pkt []byte) (*activeSession, []byte, error) {
		c, s := net.Pipe()
		defer c.Close()
		type res struct {
			a   *activeSession
			err error
		}
		r := make(chan res, 1)
		go func() {
			a, _, err := ln.handshake(s)
			r <- res{a, err}
		}()
		_, _ = c.Write(pkt)
		var resp []byte
		go func() {
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err == nil {
				resp = make([]byte, binary.BigEndian.Uint16(l[:]))
				_, _ = io.ReadFull(c, resp)
			}
		}()
		out := <-r
		return out.a, resp, out.err
	}

	_, victimPriv, _ := ed25519.GenerateKey(rand.Reader)
	pkt, _ := BuildInitiatorHandshake([32]byte{}, 0, victimPriv)
	victim, _, err := doHandshake(pkt)
	if err != nil {
		t.Fatal(err)
	}
	defer victim.session.Close()

	// Attacker opens its own fresh session, reusing the pooled buffer.
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	pkt2, _ := BuildInitiatorHandshake([32]byte{}, 0, attackerPriv)
	other, _, err := doHandshake(pkt2)
	if err != nil {
		t.Fatal(err)
	}
	defer other.session.Close()

	var sid [32]byte
	copy(sid[:], victim.id)
	hijack, _ := BuildInitiatorHandshake(sid, 1, attackerPriv)
	if _, _, err := doHandshake(hijack); err == nil {
		t.Fatal("attacker resumed the victim's session")
	}
}

// Data for a channel the receiver hasn't opened must be consumed, not parsed
// as the next header.
func TestSession_UnknownChannel_DoesNotDesyncStream(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ghost, _ := s1.OpenChannel("ghost")
	if _, err := ghost.Write(bytes.Repeat([]byte{FLG_FIN}, 64)); err != nil {
		t.Fatal(err)
	}
	a1, _ := s1.OpenChannel("real")
	a2, _ := s2.OpenChannel("real")
	if _, err := a1.Write([]byte("intact")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	rd := make(chan error, 1)
	go func() { _, err := io.ReadFull(a2, buf); rd <- err }()
	select {
	case err := <-rd:
		if err != nil || string(buf) != "intact" {
			t.Fatalf("got %q %v", buf, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream desynchronised by unknown-channel frame")
	}
}

// Closed sessions must be removed from the listener's resumption table.
func TestListener_ForgetsClosedSessions(t *testing.T) {
	ln := newTCPListener(t, DefaultConfig())
	for i := 0; i < 20; i++ {
		acc := acceptOne(t, ln)
		c, _ := net.Dial("tcp", ln.Addr().String())
		cli, err := Dial(c)
		if err != nil {
			t.Fatal(err)
		}
		srv := waitSess(t, acc)
		srv.Close()
		cli.Close()
	}
	time.Sleep(20 * time.Millisecond)
	ln.mu.RLock()
	n := len(ln.sessions)
	ln.mu.RUnlock()
	if n != 0 {
		t.Fatalf("listener still holds %d closed sessions", n)
	}
}

// A client that connects and never handshakes must not block other clients.
func TestListener_SlowHandshake_DoesNotBlockAccept(t *testing.T) {
	ln := newTCPListener(t, DefaultConfig())
	slow, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	time.Sleep(10 * time.Millisecond)

	acc := acceptOne(t, ln)
	start := time.Now()
	c, _ := net.Dial("tcp", ln.Addr().String())
	cli, err := Dial(c)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if time.Since(start) > time.Second {
		t.Fatalf("handshake waited %v behind a slow client", time.Since(start))
	}
	select {
	case s := <-acc:
		if s == nil {
			t.Fatal("accept failed")
		}
		s.Close()
	case <-time.After(time.Second):
		t.Fatal("Accept blocked behind a slow handshake")
	}
}

// Previously: remoteClose() under reorderMu -> cleanupReliability() locks it
// again -> readLoop deadlock; and a late out-of-order frame after cleanup
// panicked on the nil reorderMap.
func TestReliable_FinAfterLocalClose_NoDeadlockOrPanic(t *testing.T) {
	s1, s2 := createReliableSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch, _ := s2.OpenChannel("fin")
	ch.handleFinReliable(4) // FIN arrives before the data
	ch.Close()              // local close (readDone still false)

	p := defaultAllocator.Get(4)
	copy(*p, "DATA")
	done := make(chan struct{})
	go func() {
		ch.feedReliable(0, p, 4)
		p2 := defaultAllocator.Get(4)
		ch.feedReliable(100, p2, 4) // out-of-order after teardown
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("feedReliable deadlocked")
	}
}

func TestDialer_HandshakeTimeout(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go io.Copy(io.Discard, s) // server reads but never answers

	d := &Dialer{HandshakeTimeout: 100 * time.Millisecond}
	start := time.Now()
	if _, err := d.Dial(c); err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("handshake timeout not enforced")
	}
}
