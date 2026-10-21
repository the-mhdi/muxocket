package muxocket

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func waitDone(t *testing.T, ch *Channel, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch.Done():
	case <-time.After(d):
		t.Fatalf("%s: channel never finalized", what)
	}
}

// Close while the peer is still writing (and never closes): the peer gets an
// RST, its writes fail with ErrChannelReset, and both sides finalize instead
// of lingering until the session ends.
func closeWhilePeerWrites(t *testing.T, s1, s2 *Session) {
	a, _ := s1.OpenChannel("rst")
	b, _ := s2.OpenChannel("rst")

	if _, err := a.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	writeErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := b.Write(buf); err != nil {
				writeErr <- err
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	a.Close()

	select {
	case err := <-writeErr:
		if !errors.Is(err, ErrChannelReset) {
			t.Fatalf("peer write error = %v, want ErrChannelReset", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer kept writing after Close")
	}
	// Data written before Close is still delivered to the peer.
	got, err := io.ReadAll(b)
	if err != nil || string(got) != "hello" {
		t.Fatalf("peer read %q %v", got, err)
	}
	waitDone(t, a, 3*time.Second, "closer")
	waitDone(t, b, 3*time.Second, "peer")

	// The label is reusable afterwards.
	time.Sleep(20 * time.Millisecond)
	if _, err := s1.OpenChannel("rst"); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

func TestChannel_Close_ResetsWritingPeer(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()
	closeWhilePeerWrites(t, s1, s2)
}

func TestChannel_Close_ResetsWritingPeer_Reliable(t *testing.T) {
	s1, s2 := createReliableSessionPair(t)
	defer s1.Close()
	defer s2.Close()
	closeWhilePeerWrites(t, s1, s2)
}

// An idle peer that never closes also gets reset: no lingering channel.
func TestChannel_Close_IdlePeerFinalizes(t *testing.T) {
	for _, rel := range []bool{false, true} {
		var s1, s2 *Session
		if rel {
			s1, s2 = createReliableSessionPair(t)
		} else {
			s1, s2 = createSessionPair(t)
		}
		a, _ := s1.OpenChannel("idle")
		b, _ := s2.OpenChannel("idle")
		a.Close()
		waitDone(t, a, 3*time.Second, "closer")
		waitDone(t, b, 3*time.Second, "idle peer")
		if _, err := b.Write([]byte("x")); !errors.Is(err, ErrChannelReset) {
			t.Fatalf("reliable=%v: write after reset = %v", rel, err)
		}
		s1.Close()
		s2.Close()
	}
}

// RST arriving before the peer has opened the channel is stashed and applied
// on OpenChannel.
func TestChannel_Reset_BeforeOpen(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()
	a, _ := s1.OpenChannel("early")
	a.Write([]byte("data"))
	time.Sleep(10 * time.Millisecond)
	a.Close()
	time.Sleep(50 * time.Millisecond)
	b, _ := s2.OpenChannel("early")
	got, err := io.ReadAll(b)
	if err != nil || string(got) != "data" {
		t.Fatalf("got %q %v", got, err)
	}
	waitDone(t, b, 3*time.Second, "late opener")
	waitDone(t, a, 3*time.Second, "closer")
}

// A peer that ignores the RST (black hole) is cut off by ChannelCloseTimeout.
func TestChannel_CloseTimeout(t *testing.T) {
	for _, rel := range []bool{false, true} {
		c1, c2 := net.Pipe()
		go io.Copy(io.Discard, c2)
		cfg := DefaultConfig()
		cfg.Reliability = rel
		cfg.MaxRetransmit = 1000 // make sure the timeout, not ARQ, ends it
		cfg.ChannelCloseTimeout = 200 * time.Millisecond
		s := NewSession(c1, cfg)
		ch, _ := s.OpenChannel("tmo")
		start := time.Now()
		ch.Close()
		waitDone(t, ch, 2*time.Second, "timeout")
		if el := time.Since(start); el < 150*time.Millisecond {
			t.Fatalf("reliable=%v: finalized too early (%v)", rel, el)
		}
		if s.getChannel(ch.id) != nil {
			t.Fatal("channel still registered")
		}
		s.Close()
		c2.Close()
	}
}

// Negative ChannelCloseTimeout disables the timeout.
func TestChannel_CloseTimeout_Disabled(t *testing.T) {
	c1, c2 := net.Pipe()
	go io.Copy(io.Discard, c2)
	cfg := DefaultConfig()
	cfg.ChannelCloseTimeout = -1
	s := NewSession(c1, cfg)
	defer s.Close()
	defer c2.Close()
	ch, _ := s.OpenChannel("keep")
	ch.Close()
	select {
	case <-ch.Done():
		t.Fatal("finalized without peer FIN although timeout is disabled")
	case <-time.After(300 * time.Millisecond):
	}
}
