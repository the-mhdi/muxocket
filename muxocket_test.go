package muxocket

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
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
			_ = tc.SetWriteBuffer(128 * 1024)
			_ = tc.SetReadBuffer(128 * 1024)
		}
		s2 = NewSession(c2, DefaultConfig())
	}()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := c1.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetWriteBuffer(128 * 1024)
		_ = tc.SetReadBuffer(128 * 1024)
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
			_ = tc.SetWriteBuffer(128 * 1024)
			_ = tc.SetReadBuffer(128 * 1024)
		}
	}()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := c1.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetWriteBuffer(128 * 1024)
		_ = tc.SetReadBuffer(128 * 1024)
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

	chunkSize := 64 * 1024
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
		16 * 1024, // 16 KB (default chunk size / L1 sweet spot)
		32 * 1024, // 32 KB
		64 * 1024, // 64 KB (large packets)
		128 * 1024,
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
