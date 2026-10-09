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
	"sync/atomic"
	"time"
)

var handshakeBuffer = sync.Pool{
	New: func() any {
		return make([]byte, 512)
	},
}

var (
	ErrProtocolVersionMismatch = errors.New("protocol version mismatch")
	ErrInvalidSignature        = errors.New("invalid signature")
	ErrHandshakeTimeout        = errors.New("handshake timeout")
	ErrSessionNotFound         = errors.New("session not found for resumption")
	ErrResumptionDisabled      = errors.New("connection resumption disabled")
	ErrInvalidNonce            = errors.New("invalid nonce")
	ErrMalformedHandshake      = errors.New("malformed handshake packet")
	ErrListenerClosed          = errors.New("listener closed")
)

const (
	PROTOCOL_VERSION uint8 = 1

	// Minimum sizes
	MinInitiatorHandshakeLen = 165
	MaxHandshakeLen          = 512
	ResponderPayloadLen      = 151
)

// Listener implements net.Listener interface for both stream (TCP) and packet (UDP/IP) transports
type Listener struct {
	ln    net.Listener
	pconn net.PacketConn // Set if created via ListenPacket

	sessionConfig *Config

	handshakeTimeout          time.Duration
	AllowConnectionResumption bool
	ConnectionResumeTimeout   time.Duration
	TransparentResumption     bool // If true, resumed sessions continue in-place without returning to Accept()

	sessions map[string]*activeSession // map of sessionID to activeSession
	mu       sync.RWMutex

	// Datagram / PacketConn Management
	peerMu     sync.RWMutex
	peerConns  map[string]*packetSubConn // remoteAddr.String() -> *packetSubConn
	acceptChan chan *Session
	die        chan struct{}
	closeOnce  sync.Once
	closed     atomic.Bool
}

type activeSession struct {
	id                  string
	session             *Session
	nonce               atomic.Uint32
	initiatorPublicKey  ed25519.PublicKey
	responderPrivateKey ed25519.PrivateKey
	mu                  sync.RWMutex
}

// Listen creates a stream-oriented listener (TCP, Unix domain sockets)
func Listen(listener net.Listener, config *Config) (*Listener, error) {
	if config == nil {
		config = DefaultConfig()
	}

	return &Listener{
		ln:                        listener,
		sessionConfig:             config,
		handshakeTimeout:          5 * time.Second,
		AllowConnectionResumption: true,
		ConnectionResumeTimeout:   config.ConnectionResumeTimeout,
		sessions:                  make(map[string]*activeSession),
		die:                       make(chan struct{}),
	}, nil
}

func (ln *Listener) Close() error {
	if ln.closed.CompareAndSwap(false, true) {
		ln.closeOnce.Do(func() {
			close(ln.die)
		})

		ln.mu.Lock()
		for id, sess := range ln.sessions {
			_ = sess.session.Close()
			delete(ln.sessions, id)
		}
		ln.mu.Unlock()

		ln.peerMu.Lock()
		for addr, sub := range ln.peerConns {
			_ = sub.Close()
			delete(ln.peerConns, addr)
		}
		ln.peerMu.Unlock()

		if ln.pconn != nil {
			return ln.pconn.Close()
		}
		return ln.ln.Close()
	}
	return nil
}

func (ln *Listener) Addr() net.Addr {
	if ln.pconn != nil {
		return ln.pconn.LocalAddr()
	}
	return ln.ln.Addr()
}

func (ln *Listener) Accept() (*Session, error) {
	// If backed by a packet connection (UDP/IP), pull accepted sessions from acceptChan
	if ln.pconn != nil {
		select {
		case <-ln.die:
			return nil, ErrListenerClosed
		case sess, ok := <-ln.acceptChan:
			if !ok {
				return nil, ErrListenerClosed
			}
			return sess, nil
		}
	}

	// Stream (TCP) accept loop
	for {
		conn, err := ln.ln.Accept()
		if err != nil {
			return nil, err
		}

		activeSess, isResumed, err := ln.handshake(conn)
		if err != nil {
			_ = conn.Close()
			if ln.closed.Load() {
				return nil, err
			}
			continue
		}

		if isResumed && ln.TransparentResumption {
			continue
		}

		return activeSess.session, nil
	}
}

func (ln *Listener) handleIncomingPacketConn(subConn *packetSubConn) {
	activeSess, isResumed, err := ln.handshake(subConn)
	if err != nil {
		_ = subConn.Close()
		return
	}

	if isResumed && ln.TransparentResumption {
		return
	}

	select {
	case <-ln.die:
		_ = subConn.Close()
	case ln.acceptChan <- activeSess.session:
	}
}

func (ln *Listener) handshake(conn net.Conn) (*activeSession, bool, error) {
	_ = conn.SetDeadline(time.Now().Add(ln.handshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	buf := handshakeBuffer.Get().([]byte)
	defer handshakeBuffer.Put(buf)

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, false, err
	}

	length := binary.BigEndian.Uint16(lenBuf[:])
	if length < MinInitiatorHandshakeLen {
		return nil, false, errors.New("handshake message too short")
	}
	if length > MaxHandshakeLen {
		return nil, false, errors.New("handshake message too long")
	}

	if _, err := io.ReadFull(conn, buf[:length]); err != nil {
		return nil, false, err
	}

	parsedMsg, err := parseInitiatorHandshakeMessage(buf[:length])
	if err != nil {
		return nil, false, err
	}

	if parsedMsg.ProtocolVersion != PROTOCOL_VERSION {
		return nil, false, ErrProtocolVersionMismatch
	}

	signedData := buf[:68+int(parsedMsg.publicKeyLen)]
	isResumption := !isZeroID(parsedMsg.SessionID[:])

	// =========================================================================
	// 1. Session Resumption Flow (Supports IP/Port Connection Migration)
	// =========================================================================
	if isResumption {
		if !ln.AllowConnectionResumption {
			return nil, false, ErrResumptionDisabled
		}

		session, exists := ln.getSession(parsedMsg.SessionID[:])
		if !exists {
			return nil, false, ErrSessionNotFound
		}

		expectedNonce := session.nonce.Load() + 1
		if uint32(parsedMsg.Nonce) != expectedNonce || parsedMsg.Nonce == 0 {
			return nil, false, ErrInvalidNonce
		}

		if len(parsedMsg.PublicKey) != ed25519.PublicKeySize || !bytes.Equal(parsedMsg.PublicKey, session.initiatorPublicKey) {
			return nil, false, errors.New("invalid public key for session resumption")
		}

		if !ed25519.Verify(session.initiatorPublicKey, signedData, parsedMsg.Signature) {
			return nil, false, ErrInvalidSignature
		}

		session.nonce.Store(uint32(parsedMsg.Nonce))

		res, err := ln.buildResponderHandshake(session.id, parsedMsg.Nonce, session.responderPrivateKey)
		if err != nil {
			return nil, false, err
		}

		if _, err := conn.Write(res); err != nil {
			return nil, false, err
		}

		ln.resumeSession(session, conn)
		return session, true, nil
	}

	// =========================================================================
	// 2. Fresh Session Flow
	// =========================================================================
	if parsedMsg.Nonce != 0 {
		return nil, false, errors.New("invalid nonce for new session: must be 0")
	}

	if len(parsedMsg.PublicKey) != ed25519.PublicKeySize {
		return nil, false, errors.New("invalid public key size: expected 32-byte Ed25519 key")
	}

	if !ed25519.Verify(parsedMsg.PublicKey, signedData, parsedMsg.Signature) {
		return nil, false, ErrInvalidSignature
	}

	sid := genSessID(32)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}

	res, err := ln.buildResponderHandshake(sid, 0, priv)
	if err != nil {
		return nil, false, err
	}

	if _, err := conn.Write(res); err != nil {
		return nil, false, err
	}

	s := NewSessionWithID(conn, ln.sessionConfig, sid)

	activeSess := &activeSession{
		id:                  sid,
		session:             s,
		initiatorPublicKey:  parsedMsg.PublicKey,
		responderPrivateKey: priv,
	}
	activeSess.nonce.Store(0)

	ln.saveSession(sid, activeSess)
	return activeSess, false, nil
}

func (ln *Listener) buildResponderHandshake(
	sid string,
	nonce uint16,
	priv ed25519.PrivateKey,
) ([]byte, error) {
	cfg := ln.sessionConfig
	if cfg == nil {
		cfg = DefaultConfig()
	}

	pub := priv.Public().(ed25519.PublicKey)
	signedLen := 1 + 32 + 2 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + len(pub)
	totalPayloadLen := signedLen + 1 + ed25519.SignatureSize

	payload := make([]byte, totalPayloadLen)

	payload[0] = PROTOCOL_VERSION
	copy(payload[1:33], sid)
	binary.BigEndian.PutUint16(payload[33:35], nonce)
	binary.BigEndian.PutUint32(payload[35:39], cfg.InitialStreamWindow)
	binary.BigEndian.PutUint32(payload[39:43], cfg.InitialSessionWindow)
	binary.BigEndian.PutUint32(payload[43:47], DefaultWindowUpdateRatio)
	binary.BigEndian.PutUint32(payload[47:51], cfg.MaxFrameDataSize)

	if cfg.Reliability {
		payload[51] = 1
	}

	if ln.AllowConnectionResumption {
		payload[52] = 1
	}

	payload[53] = byte(len(pub))
	copy(payload[54:86], pub)

	sig := ed25519.Sign(priv, payload[:signedLen])
	payload[signedLen] = byte(len(sig))
	copy(payload[signedLen+1:], sig)

	packet := make([]byte, 2+totalPayloadLen)
	binary.BigEndian.PutUint16(packet[0:2], uint16(totalPayloadLen))
	copy(packet[2:], payload)

	return packet, nil
}

func (ln *Listener) resumeSession(session *activeSession, conn io.ReadWriteCloser) {
	session.session.alterConnection(conn)
}

func isZeroID(id []byte) bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

func (ln *Listener) getSession(ID []byte) (*activeSession, bool) {
	ln.mu.RLock()
	defer ln.mu.RUnlock()

	s, exists := ln.sessions[string(ID)]
	if exists && s.session.isClosed() {
		return nil, false
	}
	return s, exists
}

func (ln *Listener) saveSession(ID string, s *activeSession) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.sessions == nil {
		ln.sessions = make(map[string]*activeSession)
	}
	ln.sessions[ID] = s
}

func (ln *Listener) deleteSession(ID string) {
	ln.mu.Lock()
	defer ln.mu.Unlock()

	s, exists := ln.sessions[ID]
	if !exists {
		return
	}

	_ = s.session.Close()
	delete(ln.sessions, ID)
}

// ============================================================================
// PACKET PARSING & CLIENT HELPERS
// ============================================================================

type initiatorHandshakeMessage struct {
	length          uint16
	ProtocolVersion uint8
	SessionID       [32]byte
	Nonce           uint16
	Random          [32]byte
	publicKeyLen    uint8
	PublicKey       []byte
	signatureLen    uint8
	Signature       []byte
}

func parseInitiatorHandshakeMessage(data []byte) (*initiatorHandshakeMessage, error) {
	if len(data) < MinInitiatorHandshakeLen {
		return nil, ErrMalformedHandshake
	}

	msg := &initiatorHandshakeMessage{}
	msg.ProtocolVersion = data[0]
	copy(msg.SessionID[:], data[1:33])
	msg.Nonce = binary.BigEndian.Uint16(data[33:35])
	copy(msg.Random[:], data[35:67])
	msg.publicKeyLen = data[67]

	pubKeyEnd := 68 + int(msg.publicKeyLen)
	if len(data) < pubKeyEnd+1 {
		return nil, errors.New("malformed handshake: public key out of bounds")
	}
	msg.PublicKey = data[68:pubKeyEnd]

	msg.signatureLen = data[pubKeyEnd]
	sigEnd := pubKeyEnd + 1 + int(msg.signatureLen)
	if len(data) < sigEnd {
		return nil, errors.New("malformed handshake: signature out of bounds")
	}
	msg.Signature = data[pubKeyEnd+1 : sigEnd]

	return msg, nil
}

type responderHandshakeMessage struct {
	length                    uint16
	ProtocolVersion           uint8
	SessionID                 [32]byte
	Nonce                     uint16
	InitialStreamWindow       uint32
	InitialSessionWindow      uint32
	WindowUpdateRatio         uint32
	MaxFrameDataLen           uint32
	Reliability               bool
	AllowConnectionResumption bool
	publicKeyLen              uint8
	PublicKey                 []byte
	signatureLen              uint8
	Signature                 []byte
}

func parseResponderHandshakeMessage(data []byte) (*responderHandshakeMessage, error) {
	if len(data) < ResponderPayloadLen {
		return nil, errors.New("responder handshake message too short")
	}

	msg := &responderHandshakeMessage{}
	msg.ProtocolVersion = data[0]
	copy(msg.SessionID[:], data[1:33])
	msg.Nonce = binary.BigEndian.Uint16(data[33:35])
	msg.InitialStreamWindow = binary.BigEndian.Uint32(data[35:39])
	msg.InitialSessionWindow = binary.BigEndian.Uint32(data[39:43])
	msg.WindowUpdateRatio = binary.BigEndian.Uint32(data[43:47])
	msg.MaxFrameDataLen = binary.BigEndian.Uint32(data[47:51])
	msg.Reliability = data[51] == 1
	msg.AllowConnectionResumption = data[52] == 1

	msg.publicKeyLen = data[53]
	pubEnd := 54 + int(msg.publicKeyLen)
	if len(data) < pubEnd+1 {
		return nil, errors.New("malformed responder handshake: public key out of bounds")
	}
	msg.PublicKey = data[54:pubEnd]

	msg.signatureLen = data[pubEnd]
	sigEnd := pubEnd + 1 + int(msg.signatureLen)
	if len(data) < sigEnd {
		return nil, errors.New("malformed responder handshake: signature out of bounds")
	}
	msg.Signature = data[pubEnd+1 : sigEnd]

	return msg, nil
}

func BuildInitiatorHandshake(
	sessionID [32]byte,
	nonce uint16,
	priv ed25519.PrivateKey,
) ([]byte, error) {
	pub := priv.Public().(ed25519.PublicKey)
	var randomBytes [32]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return nil, err
	}

	signedLen := 1 + 32 + 2 + 32 + 1 + len(pub)
	totalLen := signedLen + 1 + ed25519.SignatureSize

	payload := make([]byte, totalLen)
	payload[0] = PROTOCOL_VERSION
	copy(payload[1:33], sessionID[:])
	binary.BigEndian.PutUint16(payload[33:35], nonce)
	copy(payload[35:67], randomBytes[:])
	payload[67] = byte(len(pub))
	copy(payload[68:68+len(pub)], pub)

	sig := ed25519.Sign(priv, payload[:signedLen])
	payload[signedLen] = byte(len(sig))
	copy(payload[signedLen+1:], sig)

	packet := make([]byte, 2+totalLen)
	binary.BigEndian.PutUint16(packet[0:2], uint16(totalLen))
	copy(packet[2:], payload)

	return packet, nil
}
