package muxocket

import (
	"io"
	"net"
	"testing"
	"time"
)

func readN(t *testing.T, ch *Channel, n int) string {
	t.Helper()
	buf := make([]byte, n)
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(ch, buf); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read timed out")
	}
	return string(buf)
}

// Stashed early frames older than pendingTTL are discarded, not delivered.
func TestSession_Stash_ExpiresAfterTTL(t *testing.T) {
	s1, s2, cleanup := createTCPSessionPair(t)
	defer cleanup()

	a, _ := s1.OpenChannel("ttl")
	a.Write([]byte("stale"))
	time.Sleep(50 * time.Millisecond)

	s2.channelsMu.Lock()
	q := s2.pending[func() uint32 { id, _ := stringToUint32("ttl"); return id }()]
	if q == nil {
		s2.channelsMu.Unlock()
		t.Fatal("frame was not stashed")
	}
	q.expires = time.Now().Add(-time.Second) // simulate pendingTTL passing
	s2.channelsMu.Unlock()

	b, _ := s2.OpenChannel("ttl")
	a.Write([]byte("fresh"))
	if got := readN(t, b, 5); got != "fresh" {
		t.Fatalf("got %q, want only post-open data", got)
	}
	s2.channelsMu.Lock()
	defer s2.channelsMu.Unlock()
	if len(s2.pending) != 0 || s2.pendingBytes != 0 {
		t.Fatalf("stash not released: %d queues, %d bytes", len(s2.pending), s2.pendingBytes)
	}
}

// A retransmit arriving after a reliable channel is fully closed must not be
// stashed and handed to a later channel that reuses the same label.
func TestReliable_LateFrames_NotDeliveredToReopenedChannel(t *testing.T) {
	s1, s2, cleanup := createReliableTCPSessionPair(t)
	defer cleanup()

	a, _ := s1.OpenChannel("late")
	b, _ := s2.OpenChannel("late")
	a.Write([]byte("hello"))
	if got := readN(t, b, 5); got != "hello" {
		t.Fatalf("got %q", got)
	}
	a.Close()
	b.Close()
	for _, ch := range []*Channel{a, b} {
		select {
		case <-ch.done:
		case <-time.After(2 * time.Second):
			t.Fatal("channel not finalized")
		}
	}

	// Simulate a delayed ARQ retransmit of the old channel's first bytes.
	id, _ := stringToUint32("late")
	stale := defaultAllocator.Get(5)
	copy(*stale, "stale")
	if !s1.writeControlFrameNonBlocking(writeFrame{flag: FLG_DATA, chID: id, offset: 0, pBuf: stale, length: 5}) {
		t.Fatal("could not inject frame")
	}
	time.Sleep(100 * time.Millisecond)

	s2.channelsMu.Lock()
	n := len(s2.pending)
	s2.channelsMu.Unlock()
	if n != 0 {
		t.Fatal("late frame was stashed")
	}
	if e := s2.unknownChannelErrors.Load(); e != 0 {
		t.Fatalf("late frame counted as unknown-channel error (%d)", e)
	}

	a2, _ := s1.OpenChannel("late")
	b2, _ := s2.OpenChannel("late")
	a2.Write([]byte("fresh"))
	if got := readN(t, b2, 5); got != "fresh" {
		t.Fatalf("reopened channel got %q, want %q", got, "fresh")
	}
}

// A Config literal that leaves the stash fields at zero must still buffer
// early frames (zero means "use the default", not "disabled").
func TestSession_Stash_ZeroValueConfigUsesDefaults(t *testing.T) {
	c1, c2 := net.Pipe()
	s1 := NewSession(c1, &Config{})
	s2 := NewSession(c2, &Config{})
	defer s1.Close()
	defer s2.Close()

	a, _ := s1.OpenChannel("zero")
	a.Write([]byte("early"))
	time.Sleep(50 * time.Millisecond) // arrives before s2 opens the channel

	b, _ := s2.OpenChannel("zero")
	if got := readN(t, b, 5); got != "early" {
		t.Fatalf("got %q, want early data delivered", got)
	}
}
