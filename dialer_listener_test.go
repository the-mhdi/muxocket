package muxocket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// ============================================================================
// 1. END-TO-END STREAM (TCP) HANDSHAKE & DATA TESTS
// ============================================================================

func TestDialer_Listener_TCP_EndToEnd(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	cfg := DefaultConfig()
	ln, err := Listen(tcpLn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		sessServer, err := ln.Accept()
		if err != nil {
			t.Errorf("Server Accept failed: %v", err)
			return
		}
		//defer sessServer.Close()

		chServer, err := sessServer.OpenChannel("e2e01")
		if err != nil {
			t.Errorf("Server OpenChannel failed: %v", err)
			return
		}

		buf := make([]byte, 12)
		if _, err := io.ReadFull(chServer, buf); err != nil {

			t.Errorf("Server Read error: %v", err)
			return
		}
		if string(buf) != "hello server" {
			t.Errorf("Server got %q, want 'hello server'", string(buf))
			return
		}

		if _, err := chServer.Write([]byte("hello client")); err != nil {
			t.Errorf("Server Write error: %v", err)
			return
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sessClient, err := Dial(conn)
	if err != nil {
		t.Fatalf("Client Dial failed: %v", err)
	}
	defer sessClient.Close()

	chClient, err := sessClient.OpenChannel("e2e01")
	if err != nil {
		t.Fatalf("Client OpenChannel failed: %v", err)
	}
	print(chClient.closed.Load())
	if _, err := chClient.Write([]byte("hello server")); err != nil {
		t.Fatalf("Client Write failed: %v", err)
	}
	print(chClient.closed.Load())
	reply := make([]byte, 12)
	if _, err := io.ReadFull(chClient, reply); err != nil {
		print(chClient.closed.Load())
		t.Fatalf("Client Read failed: %v", err)
	}
	if string(reply) != "hello client" {
		t.Fatalf("Client got %q, want 'hello client'", string(reply))
	}

	<-serverDone
}

func TestDialer_CapabilitiesNegotiation(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	cfg := DefaultConfig()
	cfg.InitialStreamWindow = 128 * 1024
	cfg.InitialSessionWindow = 512 * 1024
	cfg.MaxFrameDataSize = 16 * 1024
	cfg.Reliability = true

	ln, err := Listen(tcpLn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		sess, err := ln.Accept()
		if err == nil {
			defer sess.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientCfg := DefaultConfig()
	sess, resp, err := clientHandshake(conn, clientCfg, clientPriv)
	if err != nil {
		t.Fatalf("clientHandshake failed: %v", err)
	}
	defer sess.Close()

	if resp.InitialStreamWindow != cfg.InitialStreamWindow {
		t.Errorf("InitialStreamWindow mismatch: got %d, want %d", resp.InitialStreamWindow, cfg.InitialStreamWindow)
	}
	if resp.InitialSessionWindow != cfg.InitialSessionWindow {
		t.Errorf("InitialSessionWindow mismatch: got %d, want %d", resp.InitialSessionWindow, cfg.InitialSessionWindow)
	}
	if resp.MaxFrameDataLen != cfg.MaxFrameDataSize {
		t.Errorf("MaxFrameDataLen mismatch: got %d, want %d", resp.MaxFrameDataLen, cfg.MaxFrameDataSize)
	}
	if !resp.Reliability {
		t.Errorf("Expected Reliability=true from server")
	}
	if sess.config.InitialStreamWindow != cfg.InitialStreamWindow {
		t.Errorf("Client session config not updated: got %d", sess.config.InitialStreamWindow)
	}
}

// ============================================================================
// 2. CRYPTOGRAPHIC & PROTOCOL BOUNDARY SECURITY TESTS
// ============================================================================

func TestListener_Handshake_InvalidProtocolVersion(t *testing.T) {
	cClient, cServer := net.Pipe()
	defer cClient.Close()
	defer cServer.Close()

	ln := &Listener{
		sessionConfig:    DefaultConfig(),
		handshakeTimeout: 1 * time.Second,
		sessions:         make(map[string]*activeSession),
	}

	errChan := make(chan error, 1)
	go func() {
		_, _, err := ln.handshake(cServer)
		errChan <- err
	}()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	packet, err := BuildInitiatorHandshake([32]byte{}, 0, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt ProtocolVersion (index 2 because of 2-byte length prefix)
	packet[2] = 99

	if _, err := cClient.Write(packet); err != nil {
		t.Fatal(err)
	}

	err = <-errChan
	if !errors.Is(err, ErrProtocolVersionMismatch) {
		t.Fatalf("Expected ErrProtocolVersionMismatch, got: %v", err)
	}
}

func TestListener_Handshake_MalformedLengths(t *testing.T) {
	ln := &Listener{
		sessionConfig:    DefaultConfig(),
		handshakeTimeout: 1 * time.Second,
		sessions:         make(map[string]*activeSession),
	}

	t.Run("TooShort", func(t *testing.T) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		go func() {
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], 100) // Less than MinInitiatorHandshakeLen (165)
			_, _ = cClient.Write(lenBuf[:])
		}()

		_, _, err := ln.handshake(cServer)
		if err == nil || err.Error() != "handshake message too short" {
			t.Fatalf("Expected 'handshake message too short', got: %v", err)
		}
	})

	t.Run("TooLong", func(t *testing.T) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		go func() {
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], 600) // Greater than MaxHandshakeLen (512)
			_, _ = cClient.Write(lenBuf[:])
		}()

		_, _, err := ln.handshake(cServer)
		if err == nil || err.Error() != "handshake message too long" {
			t.Fatalf("Expected 'handshake message too long', got: %v", err)
		}
	})

	t.Run("OutOfBoundsPublicKeyField", func(t *testing.T) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		packet, _ := BuildInitiatorHandshake([32]byte{}, 0, priv)

		// Byte index 69 is publicKeyLen (2-byte prefix + 67)
		packet[69] = 200 // Overflows the buffer

		go func() {
			_, _ = cClient.Write(packet)
		}()

		_, _, err := ln.handshake(cServer)
		if err == nil {
			t.Fatal("Expected error on out-of-bounds public key length")
		}
	})
}

func TestListener_Handshake_TamperedSignature(t *testing.T) {
	cClient, cServer := net.Pipe()
	defer cClient.Close()
	defer cServer.Close()

	ln := &Listener{
		sessionConfig:    DefaultConfig(),
		handshakeTimeout: 1 * time.Second,
		sessions:         make(map[string]*activeSession),
	}

	errChan := make(chan error, 1)
	go func() {
		_, _, err := ln.handshake(cServer)
		errChan <- err
	}()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	packet, _ := BuildInitiatorHandshake([32]byte{}, 0, priv)

	// Tamper with the last byte of the signature
	packet[len(packet)-1] ^= 0xFF

	if _, err := cClient.Write(packet); err != nil {
		t.Fatal(err)
	}

	err := <-errChan
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Expected ErrInvalidSignature, got: %v", err)
	}
}

func TestListener_Handshake_NewSession_NonZeroNonceRejected(t *testing.T) {
	cClient, cServer := net.Pipe()
	defer cClient.Close()
	defer cServer.Close()

	ln := &Listener{
		sessionConfig:    DefaultConfig(),
		handshakeTimeout: 1 * time.Second,
		sessions:         make(map[string]*activeSession),
	}

	errChan := make(chan error, 1)
	go func() {
		_, _, err := ln.handshake(cServer)
		errChan <- err
	}()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Nonce is 1 instead of 0 on a zero session ID
	packet, _ := BuildInitiatorHandshake([32]byte{}, 1, priv)

	if _, err := cClient.Write(packet); err != nil {
		t.Fatal(err)
	}

	err := <-errChan
	if err == nil || err.Error() != "invalid nonce for new session: must be 0" {
		t.Fatalf("Expected error for non-zero nonce on fresh session, got: %v", err)
	}
}

func TestDialer_ServerTamperedSignature(t *testing.T) {
	cClient, cServer := net.Pipe()
	defer cClient.Close()
	defer cServer.Close()

	go func() {
		var lenBuf [2]byte
		_, _ = io.ReadFull(cServer, lenBuf[:])
		l := binary.BigEndian.Uint16(lenBuf[:])
		buf := make([]byte, l)
		_, _ = io.ReadFull(cServer, buf)

		// Forge server responder handshake
		ln := &Listener{sessionConfig: DefaultConfig()}
		_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
		res, _ := ln.buildResponderHandshake("12345678901234567890123456789012", 0, serverPriv)

		// Corrupt signature byte
		res[len(res)-1] ^= 0xEE
		_, _ = cServer.Write(res)
	}()

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, _, err := clientHandshake(cClient, DefaultConfig(), clientPriv)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Expected client to reject tampered server signature, got: %v", err)
	}
}

// ============================================================================
// 3. SESSION RESUMPTION & REPLAY ATTACK DEFENSE TESTS
// ============================================================================

func TestListener_SessionResumption_Success(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	cfg := DefaultConfig()
	cfg.Reliability = true
	ln, err := Listen(tcpLn, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		_, _ = ln.Accept()
	}()

	// 1. Initial Connection
	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	sessClient, resp, err := clientHandshake(conn1, cfg, clientPriv)
	if err != nil {
		t.Fatalf("Initial clientHandshake failed: %v", err)
	}

	chClient, err := sessClient.OpenChannel("res01")
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	_, _ = chClient.Write([]byte("data before disconnect"))

	// 2. Sever connection (Simulate network drop)
	_ = conn1.Close()

	// 3. Reconnect & Resume session with incremented Nonce (1)
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	var sid [32]byte
	copy(sid[:], resp.SessionID[:])
	resumePacket, err := BuildInitiatorHandshake(sid, 1, clientPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Read server confirmation

	done := make(chan error, 1)
	go func() {
		done <- func() error {
			var lenBuf [2]byte
			if _, err := io.ReadFull(conn2, lenBuf[:]); err != nil {
				return fmt.Errorf("read server resumption response len: %w", err)
			}
			respLen := binary.BigEndian.Uint16(lenBuf[:])
			respBuf := make([]byte, respLen)
			if _, err := io.ReadFull(conn2, respBuf); err != nil {
				return fmt.Errorf("read server resumption response: %w", err)
			}

			resumeResp, err := parseResponderHandshakeMessage(respBuf)
			if err != nil {
				return fmt.Errorf("parseResponderHandshakeMessage: %w", err)
			}

			if resumeResp.Nonce != 1 {
				return fmt.Errorf("expected responder nonce 1, got %d", resumeResp.Nonce)
			}

			// Apply new connection to the existing client session
			sessClient.alterConnection(conn2)

			// Verify channel can still write post-resumption
			if _, err := chClient.Write([]byte("data after resumption")); err != nil {
				return fmt.Errorf("write post-resumption: %w", err)
			}
			return nil
		}()
	}()

	if _, err := conn2.Write(resumePacket); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for resumption")
	}
	sessClient.Close()

}

func TestListener_SessionResumption_ReplayAttackRejected(t *testing.T) {
	cClient, cServer := net.Pipe()
	defer cClient.Close()
	defer cServer.Close()

	ln := &Listener{
		sessionConfig:             DefaultConfig(),
		handshakeTimeout:          1 * time.Second,
		AllowConnectionResumption: true,
		sessions:                  make(map[string]*activeSession),
	}

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub := clientPriv.Public().(ed25519.PublicKey)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	sid := "12345678901234567890123456789012"
	var sidBytes [32]byte
	copy(sidBytes[:], sid)

	// Pre-register active session with Nonce = 1
	active := &activeSession{
		id:                  sid,
		session:             NewSessionWithID(newIdleConn(t), DefaultConfig(), sid),
		initiatorPublicKey:  clientPub,
		responderPrivateKey: serverPriv,
	}
	active.nonce.Store(1)
	ln.saveSession(sid, active)

	errChan := make(chan error, 1)
	go func() {
		_, _, err := ln.handshake(cServer)
		errChan <- err
	}()

	// Attacker replays old Nonce = 1
	replayedPacket, _ := BuildInitiatorHandshake(sidBytes, 1, clientPriv)
	_, _ = cClient.Write(replayedPacket)

	err := <-errChan
	if !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("Expected ErrInvalidNonce on replayed packet, got: %v", err)
	}
}

func TestListener_SessionResumption_WrongKey_HijackingAttempt(t *testing.T) {
	cClient, cServer := net.Pipe()
	defer cClient.Close()
	defer cServer.Close()

	ln := &Listener{
		sessionConfig:             DefaultConfig(),
		handshakeTimeout:          1 * time.Second,
		AllowConnectionResumption: true,
		sessions:                  make(map[string]*activeSession),
	}

	_, legitPriv, _ := ed25519.GenerateKey(rand.Reader)
	legitPub := legitPriv.Public().(ed25519.PublicKey)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	sid := "legitimate_session_id_32_bytes!!" // must be exactly 32 bytes
	var sidBytes [32]byte
	copy(sidBytes[:], sid)

	active := &activeSession{
		id:                  sid,
		session:             NewSessionWithID(newIdleConn(t), DefaultConfig(), sid),
		initiatorPublicKey:  legitPub,
		responderPrivateKey: serverPriv,
	}
	active.nonce.Store(0)
	ln.saveSession(sid, active)

	errChan := make(chan error, 1)
	go func() {
		_, _, err := ln.handshake(cServer)
		errChan <- err
	}()

	// Attacker tries to resume legit session using their OWN keypair
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	hijackPacket, _ := BuildInitiatorHandshake(sidBytes, 1, attackerPriv)
	_, _ = cClient.Write(hijackPacket)

	err := <-errChan
	if err == nil || err.Error() != "invalid public key for session resumption" {
		t.Fatalf("Expected public key mismatch error on hijacking attempt, got: %v", err)
	}
}

func TestListener_SessionResumption_Disabled(t *testing.T) {
	cClient, cServer := net.Pipe()
	defer cClient.Close()
	defer cServer.Close()

	ln := &Listener{
		sessionConfig:             DefaultConfig(),
		handshakeTimeout:          1 * time.Second,
		AllowConnectionResumption: false, // Disabled
		sessions:                  make(map[string]*activeSession),
	}

	errChan := make(chan error, 1)
	go func() {
		_, _, err := ln.handshake(cServer)
		errChan <- err
	}()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var sid [32]byte
	copy(sid[:], "existing_session_id_32_bytes___")
	packet, _ := BuildInitiatorHandshake(sid, 1, priv)

	_, _ = cClient.Write(packet)

	err := <-errChan
	if !errors.Is(err, ErrResumptionDisabled) {
		t.Fatalf("Expected ErrResumptionDisabled, got: %v", err)
	}
}

// ============================================================================
// 4. LISTENER LIFECYCLE TESTS
// ============================================================================

func TestListener_Close_UnblocksAccept(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(tcpLn, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	acceptErr := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		acceptErr <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case err := <-acceptErr:
		if err == nil {
			t.Fatal("Expected error from Accept after Close")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Deadlock: ln.Close() failed to unblock ln.Accept()")
	}
}

// ============================================================================
// 5. PACKET LISTENER (UDP) TESTS
// ============================================================================

func TestListenPacket_UDP_HandshakeAndData(t *testing.T) {
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pconn.Close()

	cfg := DefaultConfig()
	cfg.Reliability = true

	ln, err := ListenPacket(pconn, 1500, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		sessServer, err := ln.Accept()
		if err != nil {
			t.Errorf("Packet server Accept failed: %v", err)
			return
		}
		defer sessServer.Close()

		chServer, err := sessServer.OpenChannel("udp01")
		if err != nil {
			t.Errorf("Server OpenChannel failed: %v", err)
			return
		}

		buf := make([]byte, 14)
		if _, err := io.ReadFull(chServer, buf); err != nil {
			t.Errorf("Server Read error: %v", err)
			return
		}
		if string(buf) != "hello over udp" {
			t.Errorf("Server got %q, want 'hello over udp'", string(buf))
			return
		}
	}()

	clientConn, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	sessClient, _, err := clientHandshake(clientConn, cfg, clientPriv)
	if err != nil {
		t.Fatalf("clientHandshake over UDP failed: %v", err)
	}
	defer sessClient.Close()

	chClient, err := sessClient.OpenChannel("udp01")
	if err != nil {
		t.Fatalf("Client OpenChannel failed: %v", err)
	}

	if _, err := chClient.Write([]byte("hello over udp")); err != nil {
		t.Fatalf("Client Write over UDP failed: %v", err)
	}

	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for UDP server to receive message")
	}
}

// newIdleConn returns one end of a pipe whose peer is never written to, so a
// session built on it just sits in readLoop without touching the handshake
// transport under test.
func newIdleConn(t *testing.T) net.Conn {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a
}
