package muxocket

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func halfCloseRoundTrip(t *testing.T, s1, s2 *Session) {
	t.Helper()
	a, _ := s1.OpenChannel("hc")
	b, _ := s2.OpenChannel("hc")

	// Client sends a request and half-closes; server reads to EOF, then
	// replies on the still-open reverse direction.
	if _, err := a.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("write after CloseWrite succeeded")
	}

	req, err := io.ReadAll(b)
	if err != nil || string(req) != "request" {
		t.Fatalf("server got %q %v", req, err)
	}
	if _, err := b.Write([]byte("response")); err != nil {
		t.Fatalf("reply after peer half-close: %v", err)
	}
	b.Close()

	resp, err := io.ReadAll(a)
	if err != nil || string(resp) != "response" {
		t.Fatalf("client got %q %v", resp, err)
	}
	a.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s1.getChannel(a.id) == nil && s2.getChannel(b.id) == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("half-closed channels never finalized")
}

func TestChannel_CloseWrite_HalfClose(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()
	halfCloseRoundTrip(t, s1, s2)
}

func TestChannel_CloseWrite_HalfClose_Reliable(t *testing.T) {
	s1, s2 := createReliableSessionPair(t)
	defer s1.Close()
	defer s2.Close()
	halfCloseRoundTrip(t, s1, s2)
}

// Data (and FIN) sent before the receiver calls OpenChannel must be delivered,
// in order, once it does. Non-reliable mode used to drop it silently.
func TestSession_EarlyFrames_DeliveredOnOpen(t *testing.T) {
	s1, s2, cleanup := createTCPSessionPair(t)
	defer cleanup()

	a, _ := s1.OpenChannel("early")
	want := bytes.Repeat([]byte("0123456789"), 5000) // spans several frames
	if _, err := a.Write(want); err != nil {
		t.Fatal(err)
	}
	a.CloseWrite()
	time.Sleep(50 * time.Millisecond) // let it all arrive before we open

	b, _ := s2.OpenChannel("early")
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("early data mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

// Drops the first FIN frame on the wire; ARQ must retransmit it.
type finDropConn struct {
	net.Conn
	mu      sync.Mutex
	dropped bool
}

func (c *finDropConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dropped && len(b) == 17 && b[4] == FLG_FIN && binary.BigEndian.Uint32(b[0:4]) == 0 {
		c.dropped = true
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func TestReliable_LostFIN_IsRetransmitted(t *testing.T) {
	c1, c2 := net.Pipe()
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 30 * time.Millisecond
	s1 := NewSession(&finDropConn{Conn: c1}, cfg)
	s2 := NewSession(c2, cfg)
	defer s1.Close()
	defer s2.Close()

	a, _ := s1.OpenChannel("fin")
	b, _ := s2.OpenChannel("fin")
	a.Write([]byte("bye"))
	a.CloseWrite()

	done := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(b)
		if err == nil && string(got) != "bye" {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer never saw EOF: lost FIN was not retransmitted")
	}
}

// Close must flush queued data and tell the peer (GOAWAY), so the peer closes
// at once instead of waiting out ConnectionResumeTimeout.
func TestSession_GracefulClose_FlushesAndGoAway(t *testing.T) {
	s1, s2, cleanup := createTCPSessionPair(t)
	defer cleanup()
	a, _ := s1.OpenChannel("bye")
	b, _ := s2.OpenChannel("bye")

	want := bytes.Repeat([]byte("z"), 512*1024)
	go func() { a.Write(want); a.CloseWrite() }()
	got, err := io.ReadAll(b)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("read %d bytes, err %v", len(got), err)
	}
	b.Close()
	select {
	case <-a.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("channel never finished")
	}
	start := time.Now()
	s1.Close()
	select {
	case <-s2.Done():
	case <-time.After(time.Second):
		t.Fatal("peer did not close on GOAWAY")
	}
	if time.Since(start) > 900*time.Millisecond {
		t.Fatal("graceful close too slow")
	}
}

// Data the peer sent before closing must stay readable after the session is
// gone: a proxy writes the response, closes, and closes the session right
// away. Previously the receiver's Read returned io.ErrClosedPipe and the
// buffered tail of the stream was discarded.
func TestBufferedDataReadableAfterPeerClosesSession(t *testing.T) {
	for _, withFIN := range []bool{true, false} {
		s1, s2 := createSessionPair(t)
		a, _ := s1.OpenChannel("tail")
		b, _ := s2.OpenChannel("tail")
		payload := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
		if _, err := b.Write(payload); err != nil {
			t.Fatal(err)
		}
		if withFIN {
			b.Close()
			<-time.After(50 * time.Millisecond) // FIN delivered; a not read yet
		}
		s2.Close() // GOAWAY after the flush
		select {
		case <-s1.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("GOAWAY not processed")
		}
		got, err := io.ReadAll(a)
		if !bytes.Equal(got, payload) {
			t.Fatalf("withFIN=%v: read %d/%d bytes, err=%v", withFIN, len(got), len(payload), err)
		}
		s1.Close()
	}
}
