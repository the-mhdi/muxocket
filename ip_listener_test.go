package muxocket

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

//needs suod privileges run : sudo $(which go) test -v -run=TestIPListener_ .
//							  sudo $(which go) test -run=^$ -bench=BenchmarkThroughput_RawIP -benchmem .

// IANA Protocol 253 (RFC 3692: Reserved for Experimentation & Testing)
const testIPProtocol = "ip4:253"

// ============================================================================
// FIXTURES & HELPERS
// ============================================================================

// skipUnlessRawIP checks if the process has privileges to open raw IP sockets.
func skipUnlessRawIP(t testing.TB) {
	t.Helper()
	pc, err := net.ListenPacket(testIPProtocol, "127.0.0.1")
	if err != nil {
		t.Skipf("skipping raw IP test: %v (requires root or CAP_NET_RAW)", err)
	}
	_ = pc.Close()
}

func createIPSessionPair(t testing.TB, mtu int, cfg *Config, clientIP string) (*Listener, *Session, *Session, func()) {
	t.Helper()
	skipUnlessRawIP(t)

	// Server binds to 127.0.0.1
	pconn, err := net.ListenPacket(testIPProtocol, "127.0.0.1")
	if err != nil {
		t.Fatalf("ListenPacket %s failed: %v", testIPProtocol, err)
	}

	ln, err := ListenPacket(pconn, mtu, cfg)
	if err != nil {
		_ = pconn.Close()
		t.Fatalf("ListenPacket constructor failed: %v", err)
	}

	// Client binds to a unique loopback alias (e.g. 127.0.0.2) to distinguish peers
	laddr := &net.IPAddr{IP: net.ParseIP(clientIP)}
	raddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	cliConn, err := net.DialIP(testIPProtocol, laddr, raddr)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("DialIP from %s to 127.0.0.1 failed: %v", clientIP, err)
	}

	sessCli, err := DialConfig(cliConn, cfg)
	if err != nil {
		_ = cliConn.Close()
		_ = ln.Close()
		t.Fatalf("Client DialConfig over raw IP failed: %v", err)
	}

	sessSrv, err := ln.Accept()
	if err != nil {
		_ = sessCli.Close()
		_ = cliConn.Close()
		_ = ln.Close()
		t.Fatalf("Listener Accept failed over raw IP: %v", err)
	}

	cleanup := func() {
		_ = sessCli.Close()
		_ = sessSrv.Close()
		_ = cliConn.Close()
		_ = ln.Close()
	}

	return ln, sessSrv, sessCli, cleanup
}

// ============================================================================
// 1. FUNCTIONAL TESTS (REAL RAW IP4 SOCKETS)
// ============================================================================

// TestIPListener_SingleChannel_Echo tests basic bidirectional transmission over Raw IP.
func TestIPListener_SingleChannel_Echo(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 40 * time.Millisecond

	// 1480 MTU = 1500 (Ethernet) - 20 (IPv4 Header)
	_, srv, cli, cleanup := createIPSessionPair(t, 1480, cfg, "127.0.0.2")
	defer cleanup()

	chSrv, err := srv.OpenChannel("ipecho")
	if err != nil {
		t.Fatalf("server OpenChannel failed: %v", err)
	}
	chCli, err := cli.OpenChannel("ipecho")
	if err != nil {
		t.Fatalf("client OpenChannel failed: %v", err)
	}

	msg := []byte("hello over raw ip4 protocol 253!")
	go func() {
		_, _ = chCli.Write(msg)
	}()

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(chSrv, recv); err != nil {
		t.Fatalf("Server ReadFull failed: %v", err)
	}
	if !bytes.Equal(recv, msg) {
		t.Fatalf("got %q, want %q", recv, msg)
	}

	// Echo back
	go func() {
		_, _ = chSrv.Write(recv)
	}()

	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(chCli, echo); err != nil {
		t.Fatalf("Client ReadFull echo failed: %v", err)
	}
	if !bytes.Equal(echo, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", echo, msg)
	}
}

// TestIPListener_MultipleClients_DifferentLoopbackIPs tests multiple peers
// connecting to the same raw IP socket, separated by source IP (127.0.0.2, 127.0.0.3, ...).
func TestIPListener_MultipleClients_DifferentLoopbackIPs(t *testing.T) {
	skipUnlessRawIP(t)

	pconn, err := net.ListenPacket(testIPProtocol, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer pconn.Close()

	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 40 * time.Millisecond

	ln, err := ListenPacket(pconn, 1480, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const numClients = 4
	var wg sync.WaitGroup
	wg.Add(numClients)

	// Server acceptance loop
	go func() {
		for i := 0; i < numClients; i++ {
			s, err := ln.Accept()
			if err != nil {
				return
			}
			go func(sess *Session) {
				defer sess.Close()
				ch, err := sess.OpenChannel("multi")
				if err != nil {
					return
				}
				buf := make([]byte, 128)
				n, _ := ch.Read(buf)
				_, _ = ch.Write(buf[:n])
			}(s)
		}
	}()

	for i := 0; i < numClients; i++ {
		go func(id int) {
			defer wg.Done()
			clientIP := fmt.Sprintf("127.0.0.%d", id+2)
			laddr := &net.IPAddr{IP: net.ParseIP(clientIP)}
			raddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}

			cliConn, err := net.DialIP(testIPProtocol, laddr, raddr)
			if err != nil {
				t.Errorf("DialIP %s failed: %v", clientIP, err)
				return
			}
			defer cliConn.Close()

			sess, err := DialConfig(cliConn, cfg)
			if err != nil {
				t.Errorf("DialConfig from %s failed: %v", clientIP, err)
				return
			}
			defer sess.Close()

			ch, err := sess.OpenChannel("multi")
			if err != nil {
				t.Errorf("OpenChannel failed: %v", err)
				return
			}

			payload := []byte(fmt.Sprintf("data-from-raw-ip-%s", clientIP))
			if _, err := ch.Write(payload); err != nil {
				t.Errorf("Write error: %v", err)
				return
			}

			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(ch, echo); err != nil {
				t.Errorf("ReadFull echo failed: %v", err)
				return
			}
			if !bytes.Equal(echo, payload) {
				t.Errorf("payload mismatch on %s: got %q, want %q", clientIP, echo, payload)
			}
		}(i)
	}

	wg.Wait()
}

// TestIPListener_LargePayload_ChunkingAcrossIPMTU verifies fragmentation
// and datagram boundaries when transmitting 256 KB across 1480-byte IP packets.
func TestIPListener_LargePayload_ChunkingAcrossIPMTU(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 30 * time.Millisecond

	_, srv, cli, cleanup := createIPSessionPair(t, 1480, cfg, "127.0.0.2")
	defer cleanup()

	chSrv, _ := srv.OpenChannel("rawbig")
	chCli, _ := cli.OpenChannel("rawbig")

	const payloadSize = 256 * 1024
	payload := make([]byte, payloadSize)
	_, _ = rand.Read(payload)
	expectedHash := sha256.Sum256(payload)

	readErr := make(chan error, 1)
	go func() {
		recv := make([]byte, payloadSize)
		if _, err := io.ReadFull(chSrv, recv); err != nil {
			readErr <- err
			return
		}
		if actualHash := sha256.Sum256(recv); actualHash != expectedHash {
			readErr <- fmt.Errorf("hash mismatch: expected %x, got %x", expectedHash, actualHash)
			return
		}
		readErr <- nil
	}()

	if _, err := chCli.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	select {
	case err := <-readErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout reading large payload over raw IP")
	}
}

// ============================================================================
// 2. LOSS & IMPAIRMENT SIMULATION OVER RAW IP
// ============================================================================

type lossyIPConn struct {
	net.PacketConn
	counter atomic.Uint64
	dropMod uint64
}

func (l *lossyIPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if l.dropMod > 0 && l.counter.Add(1)%l.dropMod == 0 {
		return len(p), nil // simulate packet loss at IP layer
	}
	return l.PacketConn.WriteTo(p, addr)
}

func TestIPListener_Reliable_PacketLoss_Recovery(t *testing.T) {
	skipUnlessRawIP(t)

	rawPconn, err := net.ListenPacket(testIPProtocol, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer rawPconn.Close()

	// Drop every 6th raw IP packet (~16.6% packet loss)
	lossy := &lossyIPConn{PacketConn: rawPconn, dropMod: 6}

	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 30 * time.Millisecond
	cfg.MaxRetransmit = 15

	ln, err := ListenPacket(lossy, 1480, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		ch, _ := s.OpenChannel("lossip")
		buf := make([]byte, 32*1024)
		for {
			n, err := ch.Read(buf)
			if err != nil {
				return
			}
			if _, err := ch.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	cliConn, err := net.DialIP(testIPProtocol, &net.IPAddr{IP: net.ParseIP("127.0.0.2")}, &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()

	sessCli, err := DialConfig(cliConn, cfg)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer sessCli.Close()

	chCli, err := sessCli.OpenChannel("lossip")
	if err != nil {
		t.Fatal(err)
	}

	sendData := make([]byte, 64*1024)
	_, _ = rand.Read(sendData)

	go func() {
		_, _ = chCli.Write(sendData)
	}()

	recvData := make([]byte, len(sendData))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(chCli, recvData)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Read through loss failed: %v", err)
		}
		if !bytes.Equal(sendData, recvData) {
			t.Fatal("Data corruption over lossy raw IP channel")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout: ARQ failed to recover raw IP packet drops")
	}
}

// ============================================================================
// 3. UNPRIVILEGED SIMULATED IP TEST (FOR STANDARD CI RUNS)
// ============================================================================

// pipePacketConn emulates a raw IP PacketConn using pipe channels without requiring root.
type pipePacketConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	in         chan []byte
	out        chan []byte
	closed     atomic.Bool
	die        chan struct{}
}

func newSimulatedIPPair() (*pipePacketConn, *pipePacketConn) {
	c1 := make(chan []byte, 128)
	c2 := make(chan []byte, 128)
	die1 := make(chan struct{})
	die2 := make(chan struct{})

	p1 := &pipePacketConn{
		localAddr:  &net.IPAddr{IP: net.ParseIP("10.0.0.1")},
		remoteAddr: &net.IPAddr{IP: net.ParseIP("10.0.0.2")},
		in:         c1,
		out:        c2,
		die:        die1,
	}
	p2 := &pipePacketConn{
		localAddr:  &net.IPAddr{IP: net.ParseIP("10.0.0.2")},
		remoteAddr: &net.IPAddr{IP: net.ParseIP("10.0.0.1")},
		in:         c2,
		out:        c1,
		die:        die2,
	}
	return p1, p2
}

func (p *pipePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-p.die:
		return 0, nil, io.ErrClosedPipe
	case pkt := <-p.in:
		n := copy(b, pkt)
		return n, p.remoteAddr, nil
	}
}

func (p *pipePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	cpy := make([]byte, len(b))
	copy(cpy, b)
	select {
	case <-p.die:
		return 0, io.ErrClosedPipe
	case p.out <- cpy:
		return len(b), nil
	}
}

func (p *pipePacketConn) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.die)
	}
	return nil
}

func (p *pipePacketConn) LocalAddr() net.Addr                { return p.localAddr }
func (p *pipePacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipePacketConn) SetWriteDeadline(t time.Time) error { return nil }

/*
// TestIPListener_Simulated_Unprivileged tests raw IP network routing and
// datagram Conn logic on unprivileged machines (works in any CI without sudo).
func TestIPListener_Simulated_Unprivileged(t *testing.T) {
	srvPconn, cliPconn := newSimulatedIPPair()
	defer srvPconn.Close()
	defer cliPconn.Close()

	cfg := DefaultConfig()
	cfg.Reliability = true

	ln, err := ListenPacket(srvPconn, 1480, cfg)
	if err != nil {
		t.Fatalf("ListenPacket on simulated IP: %v", err)
	}
	defer ln.Close()

	// Simulate client side using packetSubConn
	cliSubConn := newPacketSubConn(&Listener{mtu: 1480}, srvPconn.LocalAddr())
	defer cliSubConn.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := cliPconn.ReadFrom(buf)
			if err != nil {
				return
			}
			pBuf := defaultAllocator.Get(n)
			copy(*pBuf, buf[:n])
			_ = cliSubConn.feed(pBuf)
		}
	}()

	sessCli := NewSession(cliSubConn, cfg)
	defer sessCli.Close()

	chCli, err := sessCli.OpenChannel("simip")
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("simulated raw ip verification")
	go func() {
		_, _ = chCli.Write(payload)
	}()

	// Feed outgoing from cliSubConn into cliPconn
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := cliSubConn.Read(buf)
			if err != nil {
				return
			}
			_, _ = cliPconn.WriteTo(buf[:n], srvPconn.LocalAddr())
		}
	}()

	sessSrv, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sessSrv.Close()

	chSrv, err := sessSrv.OpenChannel("simip")
	if err != nil {
		t.Fatal(err)
	}

	recv := make([]byte, len(payload))
	if _, err := io.ReadFull(chSrv, recv); err != nil {
		t.Fatalf("ReadFull on simulated IP failed: %v", err)
	}
	if !bytes.Equal(recv, payload) {
		t.Fatalf("got %q, want %q", recv, payload)
	}
}
*/
// ============================================================================
// 4. BENCHMARKS OVER RAW IP
// ============================================================================

// BenchmarkThroughput_RawIP measures raw IP bandwidth across different chunk sizes.
func BenchmarkThroughput_RawIP(b *testing.B) {
	skipUnlessRawIP(b)

	chunkSizes := []int{
		1 * 1024,
		4 * 1024,
		16 * 1024,
		32 * 1024,
		64 * 1024,
	}

	for idx, sz := range chunkSizes {
		sz := sz
		clientIP := fmt.Sprintf("127.0.0.%d", idx+2) // 127.0.0.2, 127.0.0.3, ...

		b.Run(fmt.Sprintf("%dKB", sz/1024), func(b *testing.B) {
			cfg := DefaultConfig()
			cfg.Reliability = true
			cfg.MaxWriteBufferSize = 512
			cfg.RetransmitTimeout = 50 * time.Millisecond
			cfg.MaxRetransmit = 16
			cfg.StreamingAckRatio = 2
			// Limit in-flight window so it doesn't overrun raw socket queues
			cfg.InitialStreamWindow = 1 * 1024 * 1024
			cfg.InitialSessionWindow = 8 * 1024 * 1024

			// Server setup
			pconn, err := net.ListenPacket(testIPProtocol, "127.0.0.1")
			if err != nil {
				b.Fatalf("ListenPacket failed: %v", err)
			}

			// Expand OS socket buffers to prevent kernel-level drop bursts
			if ipConn, ok := pconn.(*net.IPConn); ok {
				_ = ipConn.SetReadBuffer(4 * 1024 * 1024)
				_ = ipConn.SetWriteBuffer(4 * 1024 * 1024)
			}
			//2082 < ,gives 1 alloc on 1k packet
			ln, err := ListenPacket(pconn, 1400, cfg)
			if err != nil {
				_ = pconn.Close()
				b.Fatalf("ListenPacket constructor failed: %v", err)
			}

			// Client setup
			laddr := &net.IPAddr{IP: net.ParseIP(clientIP)}
			raddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
			cliConn, err := net.DialIP(testIPProtocol, laddr, raddr)
			if err != nil {
				_ = ln.Close()
				b.Fatalf("DialIP failed: %v", err)
			}
			_ = cliConn.SetReadBuffer(4 * 1024 * 1024)
			_ = cliConn.SetWriteBuffer(4 * 1024 * 1024)

			cli, err := DialConfig(cliConn, cfg)
			if err != nil {
				_ = cliConn.Close()
				_ = ln.Close()
				b.Fatalf("DialConfig failed: %v", err)
			}

			srv, err := ln.Accept()
			if err != nil {
				_ = cli.Close()
				_ = cliConn.Close()
				_ = ln.Close()
				b.Fatalf("Accept failed: %v", err)
			}

			defer func() {
				_ = cli.Close()
				_ = srv.Close()
				_ = cliConn.Close()
				_ = ln.Close()
			}()

			ch1, err := cli.OpenChannel("ipbnch")
			if err != nil {
				b.Fatal(err)
			}
			ch2, err := srv.OpenChannel("ipbnch")
			if err != nil {
				b.Fatal(err)
			}

			buf := make([]byte, sz)
			_, _ = rand.Read(buf)

			b.SetBytes(int64(sz))
			b.ReportAllocs()
			b.ResetTimer()

			done := make(chan error, 1)
			go func() {
				recv := make([]byte, sz)
				for i := 0; i < b.N; i++ {
					if _, err := io.ReadFull(ch2, recv); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()

			for i := 0; i < b.N; i++ {
				if _, err := ch1.Write(buf); err != nil {
					b.Fatalf("Write error at iteration %d/%d: %v", i, b.N, err)
				}
			}

			select {
			case err := <-done:
				if err != nil {
					b.Fatalf("Read error: %v", err)
				}
			case <-time.After(15 * time.Second):
				b.Fatal("Benchmark deadlock: receiver timed out waiting for data")
			}

			_ = ch1.Close()
			_ = ch2.Close()
		})
	}
}

// BenchmarkThroughput_RawIP_MultiChannel measures 8 multiplexed streams over one raw IP socket.
func BenchmarkThroughput_RawIP_MultiChannel(b *testing.B) {
	skipUnlessRawIP(b)

	cfg := DefaultConfig()
	cfg.Reliability = true

	_, srv, cli, cleanup := createIPSessionPair(b, 1500, cfg, "127.0.0.2")
	defer cleanup()

	const numChannels = 8
	const chunkSize = 16 * 1024
	buf := make([]byte, chunkSize)
	_, _ = rand.Read(buf)

	var cliChans [numChannels]*Channel
	var srvChans [numChannels]*Channel

	for i := 0; i < numChannels; i++ {
		lbl := fmt.Sprintf("ip%02d", i)
		cliChans[i], _ = cli.OpenChannel(lbl)
		srvChans[i], _ = srv.OpenChannel(lbl)
	}

	b.SetBytes(int64(chunkSize * numChannels))
	b.ReportAllocs()
	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(numChannels)

	// Receivers
	for i := 0; i < numChannels; i++ {
		go func(c *Channel) {
			defer wg.Done()
			recv := make([]byte, chunkSize)
			for j := 0; j < b.N; j++ {
				if _, err := io.ReadFull(c, recv); err != nil {
					return
				}
			}
		}(srvChans[i])
	}

	// Senders
	for j := 0; j < b.N; j++ {
		for i := 0; i < numChannels; i++ {
			if _, err := cliChans[i].Write(buf); err != nil {
				b.Fatalf("Write error: %v", err)
			}
		}
	}

	wg.Wait()
}

// BenchmarkLatency_RawIP_PingPong measures round-trip time framing latency over raw IP.
func BenchmarkLatency_RawIP_PingPong(b *testing.B) {
	skipUnlessRawIP(b)

	cfg := DefaultConfig()
	cfg.Reliability = true

	_, srv, cli, cleanup := createIPSessionPair(b, 1480, cfg, "127.0.0.2")
	defer cleanup()

	ch1, _ := cli.OpenChannel("ippong")
	ch2, _ := srv.OpenChannel("ippong")

	msg := []byte("ping")
	recv := make([]byte, len(msg))

	go func() {
		echoBuf := make([]byte, len(msg))
		for {
			if _, err := io.ReadFull(ch2, echoBuf); err != nil {
				return
			}
			if _, err := ch2.Write(echoBuf); err != nil {
				return
			}
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := ch1.Write(msg); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(ch1, recv); err != nil {
			b.Fatal(err)
		}
	}
}
