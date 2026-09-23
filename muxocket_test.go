package muxocket

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func createSessionPair(t *testing.T) (*Session, *Session) {
	c1, c2 := net.Pipe()
	s1 := NewSession(c1, DefaultConfig())
	s2 := NewSession(c2, DefaultConfig())
	return s1, s2
}

func createTCPSessionPair(t testing.TB) (*Session, *Session, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var s2 *Session
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		c2, err := ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := c2.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			//_ = tc.SetWriteBuffer(128 * 1024)
			//_ = tc.SetReadBuffer(128 * 1024)
		}
		s2 = NewSession(c2, DefaultConfig())
	}()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := c1.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		//_ = tc.SetWriteBuffer(128 * 1024)
		//_ = tc.SetReadBuffer(128 * 1024)
	}
	s1 := NewSession(c1, DefaultConfig())
	wg.Wait()

	cleanup := func() {
		s1.Close()
		s2.Close()
		ln.Close()
	}

	return s1, s2, cleanup
}

func createRawTCPPair(t testing.TB) (net.Conn, net.Conn, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var c2 net.Conn
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		var err error
		c2, err = ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := c2.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			//_ = tc.SetWriteBuffer(128 * 1024)
			//_ = tc.SetReadBuffer(128 * 1024)
		}
	}()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := c1.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		//_ = tc.SetWriteBuffer(128 * 1024)
		//_ = tc.SetReadBuffer(128 * 1024)
	}
	wg.Wait()

	cleanup := func() {
		_ = c1.Close()
		_ = c2.Close()
		_ = ln.Close()
	}

	return c1, c2, cleanup
}

func TestStringToUint32(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"", false},
		{"toolonglabel", false},
		{"a", true},
		{"test", true},
		{"ABC", true},
		{"123", true}, // Numbers are valid in base-36
		{"c0001", true},
		{"chan_1", false},
		{"zzzzzz", true},
	}

	seen := make(map[uint32]string)
	for _, tc := range tests {
		val, ok := stringToUint32(tc.input)
		if ok != tc.valid {
			t.Fatalf("stringToUint32(%q) valid = %v, expected %v", tc.input, ok, tc.valid)
		}
		if ok {
			if prev, exists := seen[val]; exists {
				t.Fatalf("Collision detected: %q and %q generated identical ID %d", tc.input, prev, val)
			}
			seen[val] = tc.input

			// Verify inverse decoding
			decoded, decOk := uint32ToString(val)
			if !decOk {
				t.Fatalf("uint32ToString(%d) failed for input %q", val, tc.input)
			}
			if len(decoded) != len(tc.input) {
				t.Fatalf("Decoded length mismatch: got %q, want %q", decoded, tc.input)
			}
		}
	}
}

func TestAllocator_GetPut(t *testing.T) {
	alloc := NewAllocator()

	sizes := []int{1, 15, 16, 512, 1024, 16384, 65535, 65536}
	for _, sz := range sizes {
		p := alloc.Get(sz)
		if p == nil || len(*p) != sz {
			t.Fatalf("Allocator.Get(%d) returned invalid slice", sz)
		}
		if err := alloc.Put(p); err != nil {
			t.Fatalf("Allocator.Put failed for size %d: %v", sz, err)
		}
	}

	badSlice := make([]byte, 13)
	if err := alloc.Put(&badSlice); err == nil {
		t.Fatalf("Expected error putting non-power-of-2 capacity slice")
	}
}

func TestSession_SingleChannel_Echo(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch1, err := s1.OpenChannel("echo")
	if err != nil {
		t.Fatalf("Failed to open channel on s1: %v", err)
	}

	ch2, err := s2.OpenChannel("echo")
	if err != nil {
		t.Fatalf("Failed to open channel on s2: %v", err)
	}

	message := []byte("Hello, High-Throughput Muxocket!")

	go func() {
		_, err := ch1.Write(message)
		if err != nil {
			t.Errorf("ch1.Write error: %v", err)
		}
	}()

	recvBuf := make([]byte, len(message))
	_, err = io.ReadFull(ch2, recvBuf)
	if err != nil {
		t.Fatalf("ch2.Read error: %v", err)
	}

	if !bytes.Equal(message, recvBuf) {
		t.Fatalf("Data mismatch! Sent %s, Received %s", message, recvBuf)
	}
}

func TestSession_LargePayload_Chunking(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch1, _ := s1.OpenChannel("large")
	ch2, _ := s2.OpenChannel("large")

	payloadSize := 1024 * 1024 // 1 MB
	data := make([]byte, payloadSize)
	rand.Read(data)

	go func() {
		n, err := ch1.Write(data)
		if err != nil || n != payloadSize {
			t.Errorf("Write error: n=%d, err=%v", n, err)
		}
	}()

	received := make([]byte, payloadSize)
	_, err := io.ReadFull(ch2, received)
	if err != nil {
		t.Fatalf("ReadFull error: %v", err)
	}

	if !bytes.Equal(data, received) {
		t.Fatal("Data corruption during multi-chunk transmission")
	}
}

func TestSession_MultiChannel_Concurrent(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	const numChannels = 16
	const payloadPerChan = 32 * 1024

	labels := []string{"ch01", "ch02", "ch03", "ch04", "ch05", "ch06", "ch07", "ch08",
		"ch09", "ch10", "ch11", "ch12", "ch13", "ch14", "ch15", "ch16"}

	var wg sync.WaitGroup
	wg.Add(numChannels)

	for i := 0; i < numChannels; i++ {
		label := labels[i]
		ch1, err := s1.OpenChannel(label)
		if err != nil {
			t.Fatalf("s1.OpenChannel(%s) error: %v", label, err)
		}
		ch2, err := s2.OpenChannel(label)
		if err != nil {
			t.Fatalf("s2.OpenChannel(%s) error: %v", label, err)
		}

		payload := make([]byte, payloadPerChan)
		rand.Read(payload)

		go func(c *Channel, p []byte) {
			_, err := c.Write(p)
			if err != nil {
				t.Errorf("Channel write error: %v", err)
			}
		}(ch1, payload)

		go func(c *Channel, expected []byte) {
			defer wg.Done()
			buf := make([]byte, len(expected))
			_, err := io.ReadFull(c, buf)
			if err != nil {
				t.Errorf("Channel read error: %v", err)
				return
			}
			if !bytes.Equal(expected, buf) {
				t.Errorf("Channel %s data corrupted", label)
			}
		}(ch2, payload)
	}

	wg.Wait()
}

func TestSession_Channel_Close_EOF(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch1, _ := s1.OpenChannel("fin")
	ch2, _ := s2.OpenChannel("fin")

	msg := []byte("before fin")
	_, _ = ch1.Write(msg)
	_ = ch1.Close()

	readBuf := make([]byte, len(msg))
	_, err := io.ReadFull(ch2, readBuf)
	if err != nil {
		t.Fatalf("Failed to read buffered data before EOF: %v", err)
	}

	extraBuf := make([]byte, 10)
	n, err := ch2.Read(extraBuf)
	if err != io.EOF || n != 0 {
		t.Fatalf("Expected io.EOF on closed channel, got n=%d, err=%v", n, err)
	}
}

func TestChannel_Close_Unblocks_Reader(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch1, _ := s1.OpenChannel("unblk")
	ch2, _ := s2.OpenChannel("unblk")
	_ = ch2

	readErr := make(chan error, 1)

	go func() {
		buf := make([]byte, 10)
		_, err := ch1.Read(buf)
		readErr <- err
	}()

	time.Sleep(20 * time.Millisecond)

	if err := ch1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case err := <-readErr:
		if err != io.ErrClosedPipe {
			t.Fatalf("Expected io.ErrClosedPipe, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Deadlock: ch.Close() failed to unblock blocked ch.Read()")
	}
}

func TestSession_Close_Termination(t *testing.T) {
	s1, s2 := createSessionPair(t)

	ch1, _ := s1.OpenChannel("term")
	_ = s1.Close()

	_, err := ch1.Write([]byte("data"))
	if err == nil {
		t.Fatal("Expected error writing on closed session channel")
	}

	_ = s2.Close()
}

func TestSession_Channel_NoMemoryLeak(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	const iterations = 500

	for i := 0; i < iterations; i++ {
		label := fmt.Sprintf("c%04d", i)

		ch1, err := s1.OpenChannel(label)
		if err != nil {
			t.Fatalf("OpenChannel failed on s1: %v", err)
		}
		ch2, err := s2.OpenChannel(label)
		if err != nil {
			t.Fatalf("OpenChannel failed on s2: %v", err)
		}

		msg := []byte("ping")
		if _, err := ch1.Write(msg); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if err := ch1.Close(); err != nil {
			t.Fatalf("ch1.Close failed: %v", err)
		}

		recvBuf := make([]byte, len(msg))
		if _, err := io.ReadFull(ch2, recvBuf); err != nil {
			t.Fatalf("ReadFull failed: %v", err)
		}

		extra := make([]byte, 1)
		if _, err := ch2.Read(extra); err != io.EOF {
			t.Fatalf("Expected io.EOF, got %v", err)
		}

		if err := ch2.Close(); err != nil {
			t.Fatalf("ch2.Close failed: %v", err)
		}

		var s1HasChannel, s2HasChannel bool
		for attempt := 0; attempt < 50; attempt++ {
			s1.channelsMu.RLock()
			_, s1HasChannel = s1.channels[ch1.id]
			s1.channelsMu.RUnlock()

			s2.channelsMu.RLock()
			_, s2HasChannel = s2.channels[ch2.id]
			s2.channelsMu.RUnlock()

			if !s1HasChannel && !s2HasChannel {
				break
			}
			time.Sleep(1 * time.Millisecond)
		}

		if s1HasChannel || s2HasChannel {
			t.Fatalf("Channel %s leaked! s1 present=%v, s2 present=%v", label, s1HasChannel, s2HasChannel)
		}
	}

	s1.channelsMu.RLock()
	count1 := len(s1.channels)
	s1.channelsMu.RUnlock()

	s2.channelsMu.RLock()
	count2 := len(s2.channels)
	s2.channelsMu.RUnlock()

	if count1 != 0 || count2 != 0 {
		t.Fatalf("Memory leak: s1 has %d lingering channels, s2 has %d", count1, count2)
	}
}

// ---------------------- BENCHMARKS ----------------------

// 1. Single Channel TCP Throughput (Large Buffers)
func BenchmarkThroughput_TCP(b *testing.B) {
	s1, s2, cleanup := createTCPSessionPair(b)
	defer cleanup()

	ch1, _ := s1.OpenChannel("bench")
	ch2, _ := s2.OpenChannel("bench")

	chunkSize := 32 * 1024
	buf := make([]byte, chunkSize)
	rand.Read(buf)

	b.SetBytes(int64(chunkSize))
	b.ResetTimer()

	done := make(chan struct{})
	go func() {
		recv := make([]byte, chunkSize)
		for i := 0; i < b.N; i++ {
			if _, err := io.ReadFull(ch2, recv); err != nil {
				return
			}
		}
		close(done)
	}()

	for i := 0; i < b.N; i++ {
		if _, err := ch1.Write(buf); err != nil {
			b.Fatalf("Write error: %v", err)
		}
	}

	<-done
}

// 2. Multi-Channel Concurrent TCP Throughput (True Multiplexing Test)
func BenchmarkThroughput_TCP_MultiChannel(b *testing.B) {
	s1, s2, cleanup := createTCPSessionPair(b)
	defer cleanup()

	const numChannels = 8
	chunkSize := 32 * 1024
	buf := make([]byte, chunkSize)
	rand.Read(buf)

	var ch1s [numChannels]*Channel
	var ch2s [numChannels]*Channel

	for i := 0; i < numChannels; i++ {
		label := fmt.Sprintf("mc%02d", i)
		ch1s[i], _ = s1.OpenChannel(label)
		ch2s[i], _ = s2.OpenChannel(label)
	}

	b.SetBytes(int64(chunkSize * numChannels))
	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(numChannels)

	for i := 0; i < numChannels; i++ {
		go func(c *Channel) {
			defer wg.Done()
			recv := make([]byte, chunkSize)
			for j := 0; j < b.N; j++ {
				if _, err := io.ReadFull(c, recv); err != nil {
					return
				}
			}
		}(ch2s[i])
	}

	for j := 0; j < b.N; j++ {
		for i := 0; i < numChannels; i++ {
			if _, err := ch1s[i].Write(buf); err != nil {
				b.Fatalf("Write error: %v", err)
			}
		}
	}

	wg.Wait()
}

// 3. Ping-Pong Round-Trip Latency Benchmark (Measures Framing & Scheduling Latency)
func BenchmarkLatency_PingPong(b *testing.B) {
	s1, s2, cleanup := createTCPSessionPair(b)
	defer cleanup()

	ch1, _ := s1.OpenChannel("ping")
	ch2, _ := s2.OpenChannel("ping")

	msg := []byte("ping")
	recv := make([]byte, len(msg))

	// Echo server
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
func BenchmarkCompare_Throughput(b *testing.B) {
	chunkSizes := []int{
		4 * 1024,  // 4 KB (small packets)
		16 * 1024, // 16 KB
		32 * 1024, // 32 KB (default chunk size / L1 sweet spot)
		64 * 1024, // 64 KB (large packets)
		128 * 1024,
		256 * 1024,
	}

	for _, size := range chunkSizes {
		sizeName := fmt.Sprintf("%dKB", size/1024)

		// 1. Baseline: Raw TCP Loopback
		b.Run(fmt.Sprintf("RawTCP/%s", sizeName), func(b *testing.B) {
			c1, c2, cleanup := createRawTCPPair(b)
			defer cleanup()

			buf := make([]byte, size)
			_, _ = rand.Read(buf)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			done := make(chan struct{})
			go func() {
				recv := make([]byte, size)
				for i := 0; i < b.N; i++ {
					if _, err := io.ReadFull(c2, recv); err != nil {
						return
					}
				}
				close(done)
			}()

			for i := 0; i < b.N; i++ {
				if _, err := c1.Write(buf); err != nil {
					b.Fatalf("Raw TCP write error: %v", err)
				}
			}

			<-done
		})

		// 2. Protocol: Muxocket over TCP Loopback
		b.Run(fmt.Sprintf("Muxocket/%s", sizeName), func(b *testing.B) {
			s1, s2, cleanup := createTCPSessionPair(b)
			defer cleanup()

			ch1, err := s1.OpenChannel("bench")
			if err != nil {
				b.Fatal(err)
			}
			ch2, err := s2.OpenChannel("bench")
			if err != nil {
				b.Fatal(err)
			}

			buf := make([]byte, size)
			_, _ = rand.Read(buf)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			done := make(chan struct{})
			go func() {
				recv := make([]byte, size)
				for i := 0; i < b.N; i++ {
					if _, err := io.ReadFull(ch2, recv); err != nil {
						return
					}
				}
				close(done)
			}()

			for i := 0; i < b.N; i++ {
				if _, err := ch1.Write(buf); err != nil {
					b.Fatalf("Muxocket write error: %v", err)
				}
			}

			<-done
		})
	}
}

// -------------------------------------------------------------------------
// 2. Round-Trip Latency Benchmark: Raw TCP vs Muxocket (Ping-Pong)
// -------------------------------------------------------------------------

func BenchmarkCompare_PingPongLatency(b *testing.B) {
	payloadSizes := []int{64, 1024} // 64B (RPC header) and 1KB (small query)

	for _, size := range payloadSizes {
		name := fmt.Sprintf("%dB", size)

		// 1. Baseline: Raw TCP Round-Trip
		b.Run(fmt.Sprintf("RawTCP/%s", name), func(b *testing.B) {
			c1, c2, cleanup := createRawTCPPair(b)
			defer cleanup()

			msg := make([]byte, size)
			_, _ = rand.Read(msg)
			recv := make([]byte, size)

			// Echo server
			go func() {
				echoBuf := make([]byte, size)
				for {
					if _, err := io.ReadFull(c2, echoBuf); err != nil {
						return
					}
					if _, err := c2.Write(echoBuf); err != nil {
						return
					}
				}
			}()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if _, err := c1.Write(msg); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(c1, recv); err != nil {
					b.Fatal(err)
				}
			}
		})

		// 2. Protocol: Muxocket Round-Trip
		b.Run(fmt.Sprintf("Muxocket/%s", name), func(b *testing.B) {
			s1, s2, cleanup := createTCPSessionPair(b)
			defer cleanup()

			ch1, _ := s1.OpenChannel("ping")
			ch2, _ := s2.OpenChannel("ping")

			msg := make([]byte, size)
			_, _ = rand.Read(msg)
			recv := make([]byte, size)

			// Echo server
			go func() {
				echoBuf := make([]byte, size)
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
		})
	}
}

//------------------------------------------------------------------------
// TEST HELPERS
// -------------------------------------------------------------------------

func createReliableSessionPair(t *testing.T) (*Session, *Session) {
	c1, c2 := net.Pipe()
	cfg1 := DefaultConfig()
	cfg1.Reliable = true
	cfg1.RetransmitTimeout = 40 * time.Millisecond

	cfg2 := DefaultConfig()
	cfg2.Reliable = true
	cfg2.RetransmitTimeout = 40 * time.Millisecond

	s1 := NewSession(c1, cfg1)
	s2 := NewSession(c2, cfg2)
	return s1, s2
}

func createReliableTCPSessionPair(t testing.TB) (*Session, *Session, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var s2 *Session
	var wg sync.WaitGroup
	wg.Add(1)

	cfg := DefaultConfig()
	cfg.Reliable = true
	cfg.RetransmitTimeout = 50 * time.Millisecond

	go func() {
		defer wg.Done()
		c2, err := ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := c2.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		s2 = NewSession(c2, cfg)
	}()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := c1.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	s1 := NewSession(c1, cfg)
	wg.Wait()

	cleanup := func() {
		s1.Close()
		s2.Close()
		ln.Close()
	}

	return s1, s2, cleanup
}

// Simulated connection that selectively drops entire multiplexer frames to test ARQ
type lossyFrameConn struct {
	net.Conn
	mu          sync.Mutex
	dropped     atomic.Bool
	droppingLen int
}

func (l *lossyFrameConn) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// If currently swallowing the payload of a dropped header
	if l.droppingLen > 0 {
		toDrop := len(b)
		if toDrop > l.droppingLen {
			toDrop = l.droppingLen
		}
		l.droppingLen -= toDrop
		if len(b) == toDrop {
			return len(b), nil
		}
		b = b[toDrop:]
	}

	// Intercept the first 17-byte ARQ FLG_DATA frame header
	if !l.dropped.Load() && len(b) == 17 && b[4] == FLG_DATA {
		dataLen := int(binary.BigEndian.Uint32(b[0:4]))
		l.dropped.Store(true)
		l.droppingLen = dataLen
		return len(b), nil // Swallow header
	}

	return l.Conn.Write(b)
}

// -------------------------------------------------------------------------
// 1. ARQ & RELIABILITY UNIT TESTS
// -------------------------------------------------------------------------

func TestReliable_SingleChannel_Echo(t *testing.T) {
	s1, s2 := createReliableSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch1, err := s1.OpenChannel("echo")
	if err != nil {
		t.Fatalf("OpenChannel s1: %v", err)
	}
	ch2, err := s2.OpenChannel("echo")
	if err != nil {
		t.Fatalf("OpenChannel s2: %v", err)
	}

	msg := []byte("Reliable ARQ In-Order Delivery")
	go func() {
		_, _ = ch1.Write(msg)
	}()

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(ch2, recv); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}
	if !bytes.Equal(msg, recv) {
		t.Fatalf("Mismatch! Got %q, want %q", recv, msg)
	}
}

// Tests out-of-order gap detection and sequential reassembly in feedReliable
func TestReliable_Out_Of_Order_Reassembly(t *testing.T) {
	s1, s2 := createReliableSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch2, _ := s2.OpenChannel("reord")

	// Chunk 2: offset 6..11 ("WORLD!")
	p2 := defaultAllocator.Get(6)
	copy(*p2, []byte("WORLD!"))

	// Chunk 1: offset 0..5 ("HELLO_")
	p1 := defaultAllocator.Get(6)
	copy(*p1, []byte("HELLO_"))

	// 1. Feed Chunk 2 FIRST (out of order: gap at offset 0)
	ch2.feedReliable(6, p2, 6)

	// Ring buffer must NOT contain chunk 2 yet (it must wait in reorderMap)
	if ch2.ring.Length() != 0 {
		t.Fatalf("Expected 0 chunks in ring buffer, found %d (gap was bypassed!)", ch2.ring.Length())
	}

	// 2. Feed Chunk 1 (contiguous gap-filler)
	ch2.feedReliable(0, p1, 6)

	// Both chunks should now be assembled into contiguous stream
	buf := make([]byte, 12)
	n, err := io.ReadFull(ch2, buf)
	if err != nil || n != 12 {
		t.Fatalf("ReadFull failed: n=%d err=%v", n, err)
	}
	if string(buf) != "HELLO_WORLD!" {
		t.Fatalf("Reassembly error! Got %q, want 'HELLO_WORLD!'", string(buf))
	}
}

// Tests duplicate frame rejection and allocator safety
func TestReliable_Duplicate_Packet_Discard(t *testing.T) {
	s1, s2 := createReliableSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch2, _ := s2.OpenChannel("dup")

	p1 := defaultAllocator.Get(4)
	copy(*p1, []byte("DATA"))
	ch2.feedReliable(0, p1, 4)

	// Feed duplicate at offset 0 again
	pDup := defaultAllocator.Get(4)
	copy(*pDup, []byte("DATA"))
	ch2.feedReliable(0, pDup, 4) // should hit offset+len <= readOffset and discard

	buf := make([]byte, 8)
	n, err := ch2.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 4 || string(buf[:n]) != "DATA" {
		t.Fatalf("Duplicate packet leaked into stream! Got n=%d, data=%q", n, buf[:n])
	}
}

// Tests ARQ timer expiration and retransmission on wire loss
func TestReliable_EndToEnd_PacketLoss_Retransmit(t *testing.T) {
	c1, c2 := net.Pipe()
	lossy := &lossyFrameConn{Conn: c1}

	cfg := DefaultConfig()
	cfg.Reliable = true
	cfg.RetransmitTimeout = 100 * time.Millisecond

	s1 := NewSession(lossy, cfg)
	s2 := NewSession(c2, cfg)
	defer s1.Close()
	defer s2.Close()

	ch1, err := s1.OpenChannel("retran")
	if err != nil {
		t.Fatal(err)
	}
	ch2, err := s2.OpenChannel("retran")
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Message surviving packet loss")

	go func() {
		_, _ = ch1.Write(msg)
	}()

	recv := make([]byte, len(msg))
	done := make(chan error, 1)

	go func() {
		_, err := io.ReadFull(ch2, recv)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
		if !bytes.Equal(msg, recv) {
			t.Fatalf("Data mismatch: got %q, want %q", recv, msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Deadlock: Dropped packet was not retransmitted by ARQ loop")
	}

	if !lossy.dropped.Load() {
		t.Fatal("Loss simulation failed to drop frame")
	}
}

// Tests unacked buffer reclamation upon ACK arrival
func TestReliable_Unacked_Buffer_Reclamation(t *testing.T) {
	s1, s2 := createReliableSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch1, _ := s1.OpenChannel("unack")
	ch2, _ := s2.OpenChannel("unack")

	payload := make([]byte, 64*1024)
	rand.Read(payload)

	go func() {
		_, _ = ch1.Write(payload)
	}()

	recv := make([]byte, len(payload))
	if _, err := io.ReadFull(ch2, recv); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	// Poll until ACK is processed by s1
	var unackedLen int
	for i := 0; i < 50; i++ {
		ch1.unackedMu.Lock()
		unackedLen = len(ch1.unacked)
		ch1.unackedMu.Unlock()

		if unackedLen == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if unackedLen != 0 {
		t.Fatalf("Memory leak: %d unacknowledged frames left in sender queue after ACK", unackedLen)
	}
}

// Tests channel closure when remote host never ACKs and MaxRetransmit is exceeded
func TestReliable_MaxRetransmit_Timeout(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := DefaultConfig()
	cfg.Reliable = true
	cfg.RetransmitTimeout = 20 * time.Millisecond
	cfg.MaxRetransmit = 3

	s1 := NewSession(c1, cfg)
	defer s1.Close()

	ch1, err := s1.OpenChannel("timeou")
	if err != nil {
		t.Fatal(err)
	}

	// Discard all reads from c2 (simulate complete black hole)
	go func() {
		buf := make([]byte, 512)
		for {
			if _, err := c2.Read(buf); err != nil {
				return
			}
		}
	}()

	_, err = ch1.Write([]byte("unreachable"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Wait for 3 retransmits to expire (3 * 20ms = ~60ms)
	time.Sleep(200 * time.Millisecond)

	if !ch1.closed.Load() {
		t.Fatal("Channel did not close after exceeding MaxRetransmit")
	}
}

// -------------------------------------------------------------------------
// 2. SESSION RESUMPTION & SUSPENSION TESTS
// -------------------------------------------------------------------------

// Tests session suspension on network disconnect and resume with connection migration
func TestSession_Resumption_And_DataContinuity(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := DefaultConfig()
	cfg.Reliable = true
	cfg.AllowConnectionResumption = true
	cfg.ConnectionResumeTimeout = 2 * time.Second
	cfg.RetransmitTimeout = 50 * time.Millisecond

	s1 := NewSession(c1, cfg)
	s2 := NewSession(c2, cfg)
	defer s1.Close()
	defer s2.Close()

	ch1, _ := s1.OpenChannel("resume")
	ch2, _ := s2.OpenChannel("resume")

	// 1. Send Part 1
	part1 := []byte("Part 1: Before Disconnect | ")
	go func() { _, _ = ch1.Write(part1) }()

	recv1 := make([]byte, len(part1))
	if _, err := io.ReadFull(ch2, recv1); err != nil {
		t.Fatalf("Part 1 read failed: %v", err)
	}

	// 2. Sever underlying connection
	_ = c1.Close()
	_ = c2.Close()

	// Allow disconnect handlers to transition sessions to suspended
	time.Sleep(30 * time.Millisecond)

	if !s1.suspended.Load() || !s2.suspended.Load() {
		t.Fatalf("Sessions should be suspended: s1=%v, s2=%v", s1.suspended.Load(), s2.suspended.Load())
	}
	if s1.isClosed() || s2.isClosed() {
		t.Fatal("Sessions prematurely closed instead of entering suspension")
	}

	// 3. Queue data while connection is severed (in-flight)
	part2 := []byte("Part 2: During Disconnect | ")
	go func() { _, _ = ch1.Write(part2) }()

	// 4. Create new underlying transport (reconnection)
	newC1, newC2 := net.Pipe()

	s1.resumeWithConnection(newC1)
	s2.resumeWithConnection(newC2)

	if s1.suspended.Load() || s2.suspended.Load() {
		t.Fatal("Sessions should no longer be suspended after resumption")
	}

	// 5. Verify Part 2 is delivered over the new connection via retransmitAllUnacked
	recv2 := make([]byte, len(part2))
	if _, err := io.ReadFull(ch2, recv2); err != nil {
		t.Fatalf("Part 2 read failed after resume: %v", err)
	}
	if !bytes.Equal(part2, recv2) {
		t.Fatalf("Data corruption after resume: got %q, want %q", recv2, part2)
	}

	// 6. Verify channel continues functioning normally after reconnection
	part3 := []byte("Part 3: Post Resumption")
	go func() { _, _ = ch1.Write(part3) }()

	recv3 := make([]byte, len(part3))
	if _, err := io.ReadFull(ch2, recv3); err != nil {
		t.Fatalf("Part 3 read failed: %v", err)
	}
	if !bytes.Equal(part3, recv3) {
		t.Fatalf("Data mismatch on resumed session: got %q, want %q", recv3, part3)
	}
}

// Tests that a suspended session terminates if reconnection grace period expires
func TestSession_Resumption_Timeout_Expiry(t *testing.T) {
	c1, c2 := net.Pipe()

	cfg := DefaultConfig()
	cfg.AllowConnectionResumption = true
	cfg.ConnectionResumeTimeout = 50 * time.Millisecond // Short grace period

	s1 := NewSession(c1, cfg)
	defer s1.Close()

	_ = c1.Close()
	_ = c2.Close()

	// Wait for grace period to expire
	time.Sleep(120 * time.Millisecond)

	if !s1.isClosed() {
		t.Fatal("Session did not close after ConnectionResumeTimeout expired")
	}
}

// -------------------------------------------------------------------------
// 3. CONCURRENCY & FLOW CONTROL TESTS
// -------------------------------------------------------------------------

// Tests that Channel.Read thread-safety lock (readMu) prevents races across concurrent readers
func TestChannel_Concurrent_Readers(t *testing.T) {
	s1, s2 := createSessionPair(t)
	defer s1.Close()
	defer s2.Close()

	ch1, _ := s1.OpenChannel("concr")
	ch2, _ := s2.OpenChannel("concr")

	const totalBytes = 128 * 1024
	payload := make([]byte, totalBytes)
	rand.Read(payload)

	go func() {
		_, _ = ch1.Write(payload)
		_ = ch1.Close()
	}()

	const numReaders = 4
	var readBytes atomic.Int64
	var wg sync.WaitGroup
	wg.Add(numReaders)

	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 1024)
			for {
				n, err := ch2.Read(buf)
				if n > 0 {
					readBytes.Add(int64(n))
				}
				if err != nil {
					return
				}
			}
		}()
	}

	wg.Wait()

	if readBytes.Load() != totalBytes {
		t.Fatalf("Concurrent read loss: expected %d bytes, read %d bytes", totalBytes, readBytes.Load())
	}
}

// Tests flow control credit replenishment when ARQ is active
func TestFlowControl_Backpressure_With_Reliable(t *testing.T) {
	c1, c2 := net.Pipe()
	cfg := DefaultConfig()
	cfg.Reliable = true
	cfg.InitialStreamWindow = 16 * 1024  // 16 KB window
	cfg.InitialSessionWindow = 32 * 1024 // 32 KB window

	s1 := NewSession(c1, cfg)
	s2 := NewSession(c2, cfg)
	defer s1.Close()
	defer s2.Close()

	ch1, _ := s1.OpenChannel("flow")
	ch2, _ := s2.OpenChannel("flow")

	largeData := make([]byte, 64*1024)
	writeDone := make(chan int, 1)

	go func() {
		n, _ := ch1.Write(largeData)
		writeDone <- n
	}()

	// Verify backpressure holds
	select {
	case <-writeDone:
		t.Fatal("Writer did not pause on saturated flow control window")
	case <-time.After(40 * time.Millisecond):
		// Expected: paused
	}

	// Drain receiver to trigger WINDOW_UPDATE
	drain := make([]byte, len(largeData))
	if _, err := io.ReadFull(ch2, drain); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	select {
	case n := <-writeDone:
		if n != len(largeData) {
			t.Fatalf("Incomplete write: got %d, want %d", n, len(largeData))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Writer deadlock: window update failed to wake writer")
	}
}

// High-concurrency stress test with 16 simultaneous channels under ARQ
func TestReliable_MultiChannel_Stress(t *testing.T) {
	s1, s2, cleanup := createReliableTCPSessionPair(t)
	defer cleanup()

	const numChannels = 16
	const payloadSize = 64 * 1024

	var wg sync.WaitGroup
	wg.Add(numChannels)

	for i := 0; i < numChannels; i++ {
		label := fmt.Sprintf("ar%02d", i)
		ch1, err := s1.OpenChannel(label)
		if err != nil {
			t.Fatalf("OpenChannel s1: %v", err)
		}
		ch2, err := s2.OpenChannel(label)
		if err != nil {
			t.Fatalf("OpenChannel s2: %v", err)
		}

		payload := make([]byte, payloadSize)
		rand.Read(payload)

		go func(c *Channel, p []byte) {
			if _, err := c.Write(p); err != nil {
				t.Errorf("Write error: %v", err)
			}
			_ = c.Close()
		}(ch1, payload)

		go func(c *Channel, expected []byte, lbl string) {
			defer wg.Done()
			buf := make([]byte, len(expected))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Errorf("Read error on %s: %v", lbl, err)
				return
			}
			if !bytes.Equal(expected, buf) {
				t.Errorf("Payload mismatch on %s", lbl)
			}
		}(ch2, payload, label)
	}

	wg.Wait()
}

// -------------------------------------------------------------------------
// 4. BENCHMARKS
// -------------------------------------------------------------------------

// Benchmark reliable mode throughput over TCP
func BenchmarkThroughput_Reliable_TCP(b *testing.B) {
	s1, s2, cleanup := createReliableTCPSessionPair(b)
	defer cleanup()

	ch1, _ := s1.OpenChannel("bench")
	ch2, _ := s2.OpenChannel("bench")

	chunkSize := 54 * 1024
	buf := make([]byte, chunkSize)
	rand.Read(buf)

	b.SetBytes(int64(chunkSize))
	b.ReportAllocs()
	b.ResetTimer()

	done := make(chan struct{})
	go func() {
		recv := make([]byte, chunkSize)
		for i := 0; i < b.N; i++ {
			if _, err := io.ReadFull(ch2, recv); err != nil {
				return
			}
		}
		close(done)
	}()

	for i := 0; i < b.N; i++ {
		if _, err := ch1.Write(buf); err != nil {
			b.Fatalf("Write error: %v", err)
		}
	}

	<-done
}

// Benchmark side-by-side comparison: Standard (Reliable: false) vs Reliable (ARQ: true)
func BenchmarkCompare_Reliable_vs_Standard(b *testing.B) {
	chunkSize := 32 * 1024
	buf := make([]byte, chunkSize)
	rand.Read(buf)

	// 1. Standard mode (9-byte header, no ARQ tracking)
	b.Run("Standard_Mode", func(b *testing.B) {
		s1, s2, cleanup := createTCPSessionPair(b)
		defer cleanup()

		ch1, _ := s1.OpenChannel("std")
		ch2, _ := s2.OpenChannel("std")

		b.SetBytes(int64(chunkSize))
		b.ReportAllocs()
		b.ResetTimer()

		done := make(chan struct{})
		go func() {
			recv := make([]byte, chunkSize)
			for i := 0; i < b.N; i++ {
				if _, err := io.ReadFull(ch2, recv); err != nil {
					return
				}
			}
			close(done)
		}()

		for i := 0; i < b.N; i++ {
			if _, err := ch1.Write(buf); err != nil {
				b.Fatal(err)
			}
		}
		<-done
	})

	// 2. Reliable mode (17-byte header, 64-bit offsets, ACKs, reorder map)
	b.Run("Reliable_Mode", func(b *testing.B) {
		s1, s2, cleanup := createReliableTCPSessionPair(b)
		defer cleanup()

		ch1, _ := s1.OpenChannel("rel")
		ch2, _ := s2.OpenChannel("rel")

		b.SetBytes(int64(chunkSize))
		b.ReportAllocs()
		b.ResetTimer()

		done := make(chan struct{})
		go func() {
			recv := make([]byte, chunkSize)
			for i := 0; i < b.N; i++ {
				if _, err := io.ReadFull(ch2, recv); err != nil {
					return
				}
			}
			close(done)
		}()

		for i := 0; i < b.N; i++ {
			if _, err := ch1.Write(buf); err != nil {
				b.Fatal(err)
			}
		}
		<-done
	})
}

// Micro-benchmark measuring raw in-order feed and reorder-map draining performance
func BenchmarkReorder_FeedReliable(b *testing.B) {
	s1, s2 := createReliableSessionPair(&testing.T{})
	defer s1.Close()
	defer s2.Close()

	ch, _ := s2.OpenChannel("micro")

	chunkSize := 1024
	raw := make([]byte, chunkSize)

	// Consume data in background so ring buffer never fills up
	go func() {
		drain := make([]byte, 4096)
		for {
			if _, err := ch.Read(drain); err != nil {
				return
			}
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pBuf := defaultAllocator.Get(chunkSize)
		copy(*pBuf, raw)
		offset := uint64(i * chunkSize)
		ch.feedReliable(offset, pBuf, uint32(chunkSize))
	}
}

// Benchmark round-trip latency in reliable mode (with ACKs and 17-byte headers)
func BenchmarkLatency_Reliable_PingPong(b *testing.B) {
	s1, s2, cleanup := createReliableTCPSessionPair(b)
	defer cleanup()

	ch1, _ := s1.OpenChannel("ping")
	ch2, _ := s2.OpenChannel("ping")

	msg := []byte("ping")
	recv := make([]byte, len(msg))

	go func() {
		echo := make([]byte, len(msg))
		for {
			if _, err := io.ReadFull(ch2, echo); err != nil {
				return
			}
			if _, err := ch2.Write(echo); err != nil {
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
