package muxocket

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"
)

func dumpProfile(filename string) {
	runtime.GC()
	runtime.GC() // Twice to clear finalizers
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_ = pprof.WriteHeapProfile(f)
}

func BenchmarkDiff_ReliableChurn(b *testing.B) {
	s1, s2, cleanup := createReliableTCPSessionPair(b)
	defer cleanup()

	// 1. Warm-up phase (fill sync.Pools and pre-allocate hash maps)
	for i := 0; i < 50; i++ {
		c1, _ := s1.OpenChannel("warm")
		c2, _ := s2.OpenChannel("warm")
		_, _ = c1.Write([]byte("warmup"))
		buf := make([]byte, 6)
		_, _ = io.ReadFull(c2, buf)
		_ = c1.Close()
		_ = c2.Close()
		<-c1.Done()
		<-c2.Done()
	}

	// Capture baseline heap
	dumpProfile("baseline.pprof")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		label := fmt.Sprintf("k%04d", i%1000)
		c1, err := s1.OpenChannel(label)
		if err != nil {
			b.Fatal(err)
		}
		c2, err := s2.OpenChannel(label)
		if err != nil {
			b.Fatal(err)
		}

		data := make([]byte, 4096)
		if _, err := c1.Write(data); err != nil {
			b.Fatal(err)
		}

		recv := make([]byte, 4096)
		if _, err := io.ReadFull(c2, recv); err != nil {
			b.Fatal(err)
		}

		_ = c1.Close()
		_ = c2.Close()

		select {
		case <-c1.Done():
		case <-time.After(2 * time.Second):
			b.Fatalf("iteration %d: c1 failed to finalize", i)
		}
		select {
		case <-c2.Done():
		case <-time.After(2 * time.Second):
			b.Fatalf("iteration %d: c2 failed to finalize", i)
		}
	}
	b.StopTimer()

	// Capture post-run heap
	dumpProfile("after.pprof")
}

func getHeapStats() (alloc uint64, objects uint64) {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc, m.HeapObjects
}

func TestLeaks_ReliableChannelChurn(t *testing.T) {
	s1, s2, cleanup := createReliableTCPSessionPair(t)
	defer cleanup()

	// Warmup to populate allocator pools
	for i := 0; i < 20; i++ {
		c1, _ := s1.OpenChannel("w")
		c2, _ := s2.OpenChannel("w")
		c1.Write([]byte("init"))
		io.ReadFull(c2, make([]byte, 4))
		c1.Close()
		c2.Close()
		<-c1.Done()
		<-c2.Done()
	}

	startAlloc, startObjects := getHeapStats()
	startGoroutines := runtime.NumGoroutine()

	const iterations = 500
	for i := 0; i < iterations; i++ {
		lbl := fmt.Sprintf("l%04d", i%500)
		c1, err := s1.OpenChannel(lbl)
		if err != nil {
			t.Fatalf("OpenChannel c1 failed: %v", err)
		}
		c2, err := s2.OpenChannel(lbl)
		if err != nil {
			t.Fatalf("OpenChannel c2 failed: %v", err)
		}

		payload := make([]byte, 4*8192)
		rand.Read(payload)
		if _, err := c1.Write(payload); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		recv := make([]byte, len(payload))
		if _, err := io.ReadFull(c2, recv); err != nil {
			t.Fatalf("ReadFull failed: %v", err)
		}

		c1.Close()
		c2.Close()

		select {
		case <-c1.Done():
		case <-time.After(2 * time.Second):
			t.Fatalf("c1 failed to finalize at %d", i)
		}
		select {
		case <-c2.Done():
		case <-time.After(2 * time.Second):
			t.Fatalf("c2 failed to finalize at %d", i)
		}
	}

	// 1. Check Internal Structure Leaks
	s1.channelsMu.RLock()
	ch1Count := len(s1.channels)
	pending1Count := len(s1.pending)
	pending1Bytes := s1.pendingBytes
	s1.channelsMu.RUnlock()

	s2.channelsMu.RLock()
	ch2Count := len(s2.channels)
	pending2Count := len(s2.pending)
	pending2Bytes := s2.pendingBytes
	s2.channelsMu.RUnlock()

	if ch1Count != 0 || ch2Count != 0 {
		t.Errorf("LEAK: Channels map lingering: s1=%d, s2=%d", ch1Count, ch2Count)
	}
	if pending1Count != 0 || pending2Count != 0 || pending1Bytes != 0 || pending2Bytes != 0 {
		t.Errorf("LEAK: Pending stash lingering: s1=(%d queues, %d B), s2=(%d queues, %d B)",
			pending1Count, pending1Bytes, pending2Count, pending2Bytes)
	}

	// 2. Check ARQ Set Leaks
	s1.arqMu.Lock()
	arq1 := len(s1.arqSet)
	s1.arqMu.Unlock()

	s2.arqMu.Lock()
	arq2 := len(s2.arqSet)
	s2.arqMu.Unlock()

	if arq1 != 0 || arq2 != 0 {
		t.Errorf("LEAK: arqSet lingering: s1=%d, s2=%d", arq1, arq2)
	}

	// 3. Check Goroutines Leaks
	endGoroutines := runtime.NumGoroutine()
	if endGoroutines > startGoroutines+2 {
		t.Errorf("LEAK: Goroutines grew from %d to %d", startGoroutines, endGoroutines)
	}

	// 4. Check Heap Object Accumulation
	endAlloc, endObjects := getHeapStats()
	if int64(endObjects)-int64(startObjects) > 300 {
		t.Errorf("LEAK: HeapObjects grew significantly: %d -> %d (+%d objects)",
			startObjects, endObjects, int64(endObjects)-int64(startObjects))
	}
	t.Logf("Memory Delta: Alloc: %d B -> %d B, Objects: %d -> %d",
		startAlloc, endAlloc, startObjects, endObjects)
}

func TestAllocator_AccountingAudit(t *testing.T) {
	// 1. Verify buffer sizes up to MaxAllocSize can be Put back properly
	for sz := 1; sz <= MaxAllocSize; sz *= 2 {
		buf := defaultAllocator.Get(sz)
		if buf == nil {
			t.Fatalf("failed to allocate %d", sz)
		}
		if cap(*buf) != sz {
			t.Fatalf("expected cap %d, got %d", sz, cap(*buf))
		}
		if err := defaultAllocator.Put(buf); err != nil {
			t.Fatalf("allocator rejected legitimate buffer of cap %d: %v", sz, err)
		}
	}

	// 2. Test non-power-of-two behavior
	for _, sz := range []int{100, 1500, 3000, 65000} {
		buf := defaultAllocator.Get(sz)
		if err := defaultAllocator.Put(buf); err != nil {
			t.Fatalf("failed to return buffer requested with size %d: %v", sz, err)
		}
	}
}
