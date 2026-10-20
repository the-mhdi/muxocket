package muxocket

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// TEST FIXTURES & HELPERS
// ============================================================================

func createUDPSessionPair(t testing.TB, mtu int, cfg *Config) (*Listener, *Session, *Session, func()) {
	t.Helper()
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}

	ln, err := ListenPacket(pconn, mtu, cfg)
	if err != nil {
		pconn.Close()
		t.Fatalf("ListenPacket failed: %v", err)
	}

	cliConn, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("Dial UDP failed: %v", err)
	}

	sessCli, err := DialConfig(cliConn, cfg)
	if err != nil {
		cliConn.Close()
		ln.Close()
		t.Fatalf("Client DialConfig failed: %v", err)
	}

	sessSrv, err := ln.Accept()
	if err != nil {
		sessCli.Close()
		cliConn.Close()
		ln.Close()
		t.Fatalf("Listener Accept failed: %v", err)
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
// 1. FUNCTIONAL TESTS OVER UDP
// ============================================================================

// Tests that single channel bidirectional stream functions correctly over UDP
func TestPacketListener_SingleChannel_Echo(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 30 * time.Millisecond

	_, srv, cli, cleanup := createUDPSessionPair(t, 1400, cfg)
	defer cleanup()

	chSrv, err := srv.OpenChannel("echoud")
	if err != nil {
		t.Fatalf("srv OpenChannel: %v", err)
	}
	chCli, err := cli.OpenChannel("echoud")
	if err != nil {
		t.Fatalf("cli OpenChannel: %v", err)
	}

	msg := []byte("hello high-performance udp packet listener!")
	go func() {
		_, _ = chCli.Write(msg)
	}()

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(chSrv, recv); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
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
		t.Fatalf("echo ReadFull failed: %v", err)
	}
	if !bytes.Equal(echo, msg) {
		t.Fatalf("got echo %q, want %q", echo, msg)
	}
}

// Tests multiple concurrent UDP clients hitting the exact same PacketConn listener.
// Verifies datagram routing by remote address (packetSubConn dispatching).
func TestPacketListener_MultipleConcurrentClients(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pconn.Close()

	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 40 * time.Millisecond

	ln, err := ListenPacket(pconn, 1400, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const numClients = 10
	var wg sync.WaitGroup
	wg.Add(numClients)

	// Server accepts loop
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
				// Echo everything back
				buf := make([]byte, 256)
				n, _ := ch.Read(buf)
				_, _ = ch.Write(buf[:n])
			}(s)
		}
	}()

	// Launch concurrent clients
	for i := 0; i < numClients; i++ {
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("udp", ln.Addr().String())
			if err != nil {
				t.Errorf("client %d dial failed: %v", id, err)
				return
			}
			defer conn.Close()

			sess, err := DialConfig(conn, cfg)
			if err != nil {
				t.Errorf("client %d handshake failed: %v", id, err)
				return
			}
			defer sess.Close()

			ch, err := sess.OpenChannel("multi")
			if err != nil {
				t.Errorf("client %d open channel: %v", id, err)
				return
			}

			payload := []byte(fmt.Sprintf("datagram-payload-from-client-%d", id))
			if _, err := ch.Write(payload); err != nil {
				t.Errorf("client %d write: %v", id, err)
				return
			}

			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(ch, echo); err != nil {
				t.Errorf("client %d read echo: %v", id, err)
				return
			}
			if !bytes.Equal(echo, payload) {
				t.Errorf("client %d payload mismatch: got %q, want %q", id, echo, payload)
			}
		}(i)
	}

	wg.Wait()
}

// Tests sending data that spans several whole datagrams across the MTU boundary.
func TestPacketListener_LargePayload_ChunkingAcrossMTU(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 30 * time.Millisecond

	const mtu = 1200
	_, srv, cli, cleanup := createUDPSessionPair(t, mtu, cfg)
	defer cleanup()

	chSrv, _ := srv.OpenChannel("chunk")
	chCli, _ := cli.OpenChannel("chunk")

	// 256 KB payload (must be split into ~220 datagrams of 1200 - 17 bytes)
	const totalSize = 256 * 1024
	payload := make([]byte, totalSize)
	rand.Read(payload)
	expectedHash := sha256.Sum256(payload)

	readErr := make(chan error, 1)
	go func() {
		recv := make([]byte, totalSize)
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
	case <-time.After(8 * time.Second):
		t.Fatal("timeout reading multi-datagram payload")
	}
}

// ============================================================================
// 2. NETWORK IMPAIRMENT SIMULATION (LOSS & OUT-OF-ORDER OVER UDP)
// ============================================================================

// lossyUDPConn intercepts PacketConn WriteTo calls and deterministically drops packets.
type lossyUDPConn struct {
	net.PacketConn
	dropCounter atomic.Uint64
	dropMod     uint64 // drop every Nth datagram
}

func (l *lossyUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if l.dropMod > 0 && l.dropCounter.Add(1)%l.dropMod == 0 {
		return len(p), nil // simulate packet loss in flight
	}
	return l.PacketConn.WriteTo(p, addr)
}

// Tests that ARQ recovery functions reliably over lossy UDP transports
func TestPacketListener_Reliable_PacketLoss_Recovery(t *testing.T) {
	rawPconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rawPconn.Close()

	// Drop every 5th datagram sent by the listener (20% loss rate)
	lossy := &lossyUDPConn{PacketConn: rawPconn, dropMod: 5}

	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.AllowConnectionResumption = true
	cfg.RetransmitTimeout = 150 * time.Millisecond
	cfg.MaxRetransmit = 12

	ln, err := ListenPacket(lossy, 1500, cfg)
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
		ch, _ := s.OpenChannel("loss")
		// Echo server
		buf := make([]byte, 32*1024)
		for {
			n, err := ch.Read(buf)
			if err != nil {
				//log.Fatal(err)
				return
			}
			if _, err := ch.Write(buf[:n]); err != nil {
				//log.Fatal(err)
				return
			}
		}
	}()

	cliConn, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()

	sessCli, err := DialConfig(cliConn, cfg)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer sessCli.Close()

	chCli, err := sessCli.OpenChannel("loss")
	if err != nil {
		t.Fatal(err)
	}

	// Send 64 KB across lossy UDP
	sendData := make([]byte, 64*1024)
	rand.Read(sendData)

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
			t.Fatalf("failed reading through loss: %v", err)
		}
		if !bytes.Equal(sendData, recvData) {
			t.Fatal("payload mismatch across lossy UDP channel")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout: ARQ failed to recover dropped datagrams")
	}

	if lossy.dropCounter.Load() == 0 {
		t.Fatal("lossy filter did not trigger")
	}
}

// Tests out-of-order packet reordering in packetSubConn
func TestPacketListener_OutOfOrder_Assembly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Reliability = true

	subConn := newPacketSubConn(&Listener{mtu: 1500}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999})
	defer subConn.Close()

	sess := NewSession(subConn, cfg)
	defer sess.Close()

	ch, _ := sess.OpenChannel("order")

	// Synthesize two DATA frames manually:
	// Frame 1: Offset 0..4 ("AAAA")
	f1 := make([]byte, 17+4)
	binary.BigEndian.PutUint32(f1[0:4], 4) // length: 4
	f1[4] = FLG_DATA
	binary.BigEndian.PutUint32(f1[5:9], ch.id) // <--- Correct 4-byte uint32 channel ID
	binary.BigEndian.PutUint64(f1[9:17], 0)    // offset: 0
	copy(f1[17:], "AAAA")

	// Frame 2: Offset 4..8 ("BBBB")
	f2 := make([]byte, 17+4)
	binary.BigEndian.PutUint32(f2[0:4], 4) // length: 4
	f2[4] = FLG_DATA
	binary.BigEndian.PutUint32(f2[5:9], ch.id) // <--- Correct 4-byte uint32 channel ID
	binary.BigEndian.PutUint64(f2[9:17], 4)    // offset: 4
	copy(f2[17:], "BBBB")

	// Feed Frame 2 FIRST (out of order), then Frame 1
	p2 := defaultAllocator.Get(len(f2))
	copy(*p2, f2)
	p1 := defaultAllocator.Get(len(f1))
	copy(*p1, f1)

	subConn.feed(p2)
	time.Sleep(10 * time.Millisecond)
	subConn.feed(p1)

	got := make([]byte, 8)
	if _, err := io.ReadFull(ch, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "AAAABBBB" {
		t.Fatalf("reordering failed: got %q, want 'AAAABBBB'", string(got))
	}
}

// ============================================================================
// 3. UDP SESSION RESUMPTION & CONNECTION MIGRATION
// ============================================================================

// Tests client changing UDP port (e.g. NAT rebind or network switch) and resuming session
func TestPacketListener_SessionResumption_NATRebind(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.AllowConnectionResumption = true
	cfg.ConnectionResumeTimeout = 3 * time.Second
	cfg.RetransmitTimeout = 40 * time.Millisecond

	ln, srv, cli, cleanup := createUDPSessionPair(t, 1400, cfg)
	defer cleanup()

	chSrv, _ := srv.OpenChannel("rebind")
	chCli, _ := cli.OpenChannel("rebind")

	// 1. Data on old UDP socket
	if _, err := chCli.Write([]byte("before-rebind")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 13)
	if _, err := io.ReadFull(chSrv, buf); err != nil || string(buf) != "before-rebind" {
		t.Fatalf("initial read failed: %q, %v", buf, err)
	}

	// 2. Client switches to a new local UDP socket (simulating IP/Port change)
	newCliConn, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer newCliConn.Close()

	if err := cli.Resume(newCliConn); err != nil {
		t.Fatalf("Resume on new UDP port failed: %v", err)
	}

	// 3. Channel communication continues uninterrupted on new transport
	if _, err := chCli.Write([]byte("after-rebind")); err != nil {
		t.Fatal(err)
	}
	buf2 := make([]byte, 12)
	if _, err := io.ReadFull(chSrv, buf2); err != nil || string(buf2) != "after-rebind" {
		t.Fatalf("post-rebind read failed: %q, %v", buf2, err)
	}
}

// ============================================================================
// 4. TEARDOWN & RESOURCE CLEANUP TESTS
// ============================================================================

func TestPacketListener_Close_CleansUpPeerConns(t *testing.T) {
	cfg := DefaultConfig()
	ln, srv, cli, cleanup := createUDPSessionPair(t, 1400, cfg)
	_ = srv
	_ = cli

	ln.peerMu.RLock()
	peersCount := len(ln.peerConns)
	ln.peerMu.RUnlock()

	if peersCount == 0 {
		t.Fatal("expected peerConns to track active UDP subConn")
	}

	cleanup()

	// Allow Close handlers to unbind
	time.Sleep(20 * time.Millisecond)

	ln.peerMu.RLock()
	remainingPeers := len(ln.peerConns)
	ln.peerMu.RUnlock()

	if remainingPeers != 0 {
		t.Fatalf("peerConns leaked: %d still registered after close", remainingPeers)
	}
}

// ============================================================================
// 5. HIGH-THROUGHPUT & LATENCY BENCHMARKS OVER UDP
// ============================================================================

// BenchmarkThroughput_UDP measures sustained streaming bandwidth across payload sizes.
func BenchmarkThroughput_UDP(b *testing.B) {
	chunkSizes := []int{
		1 * 1024,
		8 * 1024,
		32 * 1024,
		64 * 1024,
	}

	for _, sz := range chunkSizes {
		sz := sz
		b.Run(fmt.Sprintf("%dKB", sz/1024), func(b *testing.B) {
			cfg := DefaultConfig()
			cfg.Reliability = true
			cfg.RetransmitTimeout = 40 * time.Millisecond
			cfg.MaxWriteBufferSize = 64
			// Fit in-flight window to kernel buffer capacity
			cfg.InitialStreamWindow = 512 * 1024
			cfg.InitialSessionWindow = 1024 * 1024

			// Server setup
			pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				b.Fatalf("ListenPacket failed: %v", err)
			}
			// Expand kernel UDP socket buffers
			if uc, ok := pconn.(*net.UDPConn); ok {
				_ = uc.SetReadBuffer(4 * 1024 * 1024)
				_ = uc.SetWriteBuffer(4 * 1024 * 1024)
			}

			// 65507 is the absolute max IPv4 UDP payload (65535 - 28)
			const safeUDP_MTU = 1400
			ln, err := ListenPacket(pconn, safeUDP_MTU, cfg)
			if err != nil {
				_ = pconn.Close()
				b.Fatalf("ListenPacket constructor failed: %v", err)
			}

			// Client setup
			cliConn, err := net.Dial("udp", ln.Addr().String())
			if err != nil {
				_ = ln.Close()
				b.Fatalf("Dial UDP failed: %v", err)
			}
			if uc, ok := cliConn.(*net.UDPConn); ok {
				_ = uc.SetReadBuffer(4 * 1024 * 1024)
				_ = uc.SetWriteBuffer(4 * 1024 * 1024)
			}

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

			ch1, err := cli.OpenChannel("bench")
			if err != nil {
				b.Fatal(err)
			}
			ch2, err := srv.OpenChannel("bench")
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
				b.Fatal("Benchmark deadlock: receiver timed out")
			}

			b.StopTimer()
			_ = ch1.Close()
			_ = ch2.Close()
		})
	}
}

// BenchmarkThroughput_UDP_MultiChannel tests true multiplexing concurrency over a single UDP socket.
func BenchmarkThroughput_UDP_MultiChannel(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	cfg.RetransmitTimeout = 50 * time.Millisecond
	cfg.MaxWriteBufferSize = 256
	// Expand session window so 8 concurrent channels don't starve each other
	cfg.InitialStreamWindow = 1 * 1024 * 1024  // 1 MB per channel
	cfg.InitialSessionWindow = 8 * 1024 * 1024 // 8 MB session total

	const numChannels = 8
	const chunkSize = 4 * 1024
	//const safeUDP_MTU = 32000 // Max valid IPv4 UDP payload (65535 - 28)

	// 1. Setup Server with expanded socket buffers
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ListenPacket failed: %v", err)
	}
	if uc, ok := pconn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(4 * 1024 * 1024)
		_ = uc.SetWriteBuffer(4 * 1024 * 1024)
	}

	ln, err := ListenPacket(pconn, 1400, cfg)
	if err != nil {
		_ = pconn.Close()
		b.Fatalf("ListenPacket constructor failed: %v", err)
	}

	// 2. Setup Client with expanded socket buffers
	cliConn, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		b.Fatalf("Dial UDP failed: %v", err)
	}
	if uc, ok := cliConn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(4 * 1024 * 1024)
		_ = uc.SetWriteBuffer(4 * 1024 * 1024)
	}

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

	var cliChans [numChannels]*Channel
	var srvChans [numChannels]*Channel

	for i := 0; i < numChannels; i++ {
		lbl := fmt.Sprintf("u%02d", i)
		cliChans[i], err = cli.OpenChannel(lbl)
		if err != nil {
			b.Fatalf("client OpenChannel %s failed: %v", lbl, err)
		}
		srvChans[i], err = srv.OpenChannel(lbl)
		if err != nil {
			b.Fatalf("server OpenChannel %s failed: %v", lbl, err)
		}
	}

	buf := make([]byte, chunkSize)
	_, _ = rand.Read(buf)

	b.SetBytes(int64(chunkSize * numChannels))
	b.ReportAllocs()
	b.ResetTimer()

	errChan := make(chan error, numChannels*2)
	var consumerWg sync.WaitGroup
	consumerWg.Add(numChannels)

	// 8 Concurrent Consumers
	for i := 0; i < numChannels; i++ {
		go func(c *Channel, id int) {
			defer consumerWg.Done()
			recv := make([]byte, chunkSize)
			for j := 0; j < b.N; j++ {
				if _, err := io.ReadFull(c, recv); err != nil {
					errChan <- fmt.Errorf("consumer %d read error at %d/%d: %w", id, j, b.N, err)
					return
				}
			}
		}(srvChans[i], i)
	}

	// 8 Concurrent Producers (Eliminates single-thread lockstep deadlock)
	var producerWg sync.WaitGroup
	producerWg.Add(numChannels)
	for i := 0; i < numChannels; i++ {
		go func(c *Channel, id int) {
			defer producerWg.Done()
			for j := 0; j < b.N; j++ {
				if _, err := c.Write(buf); err != nil {
					errChan <- fmt.Errorf("producer %d write error at %d/%d: %w", id, j, b.N, err)
					return
				}
			}
		}(cliChans[i], i)
	}

	// Wait for all producers to finish writing
	producerWg.Wait()

	// Wait for all consumers with a timeout guard
	consumersDone := make(chan struct{})
	go func() {
		consumerWg.Wait()
		close(consumersDone)
	}()

	select {
	case err := <-errChan:
		b.Fatal(err)
	case <-consumersDone:
		// Success
	case <-time.After(20 * time.Second):
		b.Fatal("Benchmark deadlock: timed out waiting for multi-channel consumers")
	}

	b.StopTimer()
	for i := 0; i < numChannels; i++ {
		_ = cliChans[i].Close()
		_ = srvChans[i].Close()
	}
}

// BenchmarkLatency_UDP_PingPong measures RTT framing and dispatch latency over UDP.
func BenchmarkLatency_UDP_PingPong(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Reliability = true
	// 1. Critical for ping-pong: Fast RTO and NO delayed ACK stall
	cfg.RetransmitTimeout = 20 * time.Millisecond
	cfg.AckInterval = 0 // Immediate ACK: never delay ACKs when waiting for single-packet responses

	// 2. Setup Server UDP Socket with expanded buffers
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("ListenPacket failed: %v", err)
	}
	if uc, ok := pconn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(4 * 1024 * 1024)
		_ = uc.SetWriteBuffer(4 * 1024 * 1024)
	}

	ln, err := ListenPacket(pconn, 1400, cfg)
	if err != nil {
		_ = pconn.Close()
		b.Fatalf("ListenPacket constructor failed: %v", err)
	}

	// 3. Setup Client UDP Socket with expanded buffers
	cliConn, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		b.Fatalf("Dial UDP failed: %v", err)
	}
	if uc, ok := cliConn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(4 * 1024 * 1024)
		_ = uc.SetWriteBuffer(4 * 1024 * 1024)
	}

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

	ch1, err := cli.OpenChannel("ping")
	if err != nil {
		b.Fatal(err)
	}
	ch2, err := srv.OpenChannel("ping")
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("ping")
	recv := make([]byte, len(msg))

	echoDone := make(chan struct{})
	// Echo server goroutine
	go func() {
		defer close(echoDone)
		echoBuf := make([]byte, len(msg))
		for {
			if _, err := io.ReadFull(ch2, echoBuf); err != nil {
				return // clean exit when ch2 or session closes
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
			b.Fatalf("Write error at iteration %d/%d: %v", i, b.N, err)
		}
		if _, err := io.ReadFull(ch1, recv); err != nil {
			b.Fatalf("ReadFull error at iteration %d/%d: %v", i, b.N, err)
		}
	}

	b.StopTimer()

	// Clean channel closure to terminate echo goroutine cleanly
	_ = ch1.Close()
	_ = ch2.Close()
	<-echoDone
}

// BenchmarkPacketSubConn_ReadWrite tests virtual datagram queue throughput directly.
func BenchmarkPacketSubConn_ReadWrite(b *testing.B) {
	subConn := newPacketSubConn(&Listener{mtu: 1500}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080})
	defer subConn.Close()

	payload := make([]byte, 1200)
	dst := make([]byte, 1200)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(2)

	// Feeder
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			p := defaultAllocator.Get(len(payload))
			copy(*p, payload)
			if err := subConn.feed(p); err != nil {
				defaultAllocator.Put(p)
				return
			}
		}
	}()

	// Reader
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			if _, err := io.ReadFull(subConn, dst); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}
