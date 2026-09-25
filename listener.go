package muxocket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
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

var ErrProtocolVersionMismatch = errors.New("protocol version mismatch")
var ErrInvalidSignature = errors.New("invalid signature")

const (
	PROTOCOL_VERSION uint8 = 1
)

// implements net.Listener interface
type Listener struct {
	ln            net.Listener
	sessionConfig *Config
	//listener conf
	handshakeTimeout time.Duration

	AllowConnectionResumption bool          //default true
	ConnectionResumeTimeout   time.Duration //default 5 seconds
	/////////////////

	sessions map[string]*activeSession //map of  sessionID to Session
	mu       sync.RWMutex
}

type activeSession struct {
	id                  string
	session             *Session
	nonce               atomic.Uint32
	initiatorPublicKey  ed25519.PublicKey  //client
	responderPrivateKey ed25519.PrivateKey //server //ephimeral keypair for signing the handshake messages
	mu                  sync.RWMutex
}

func Listen(listener net.Listener, config *Config) (*Listener, error) {
	return &Listener{
		ln:               listener,
		sessionConfig:    config,
		handshakeTimeout: 5 * time.Second,
		sessions:         make(map[string]*activeSession),
	}, nil

}

func ListenPacket(packetConn net.PacketConn) {

}

func (ln *Listener) Accept() (*Session, error) {

	conn, err := ln.ln.Accept()

	if err != nil {
		return nil, err
	}

	session, err := ln.handshake(conn)

	if err != nil {
		return nil, err
	}

	return session.session, nil
}

// initator sends: porotocol versoin[1byte]:sessionID[max32bytes,all 0 if it's a fresh start]:nonce[2 bytes]((it's 0 for a new session)(increments evey time session gets resumed)):random[32byte of random bytes]:pubkeyLen[1byte]:sessoinPublickey[max 128 bytes(1024 bits)]:sigLen[1byte]:signature[max 256 bytes]
// responder sends: protocol version[1byte]:sessionID[max32bytes]:nonce[2 bytes]:windowsize and capabilities: responderpubkey and signature
// initator starts the session based on the responder's handshake message and the capabilities it advertises. If the responder's handshake message is invalid, the initator closes the connection and returns an error.
func (ln *Listener) handshake(conn net.Conn) (*activeSession, error) {
	conn.SetDeadline(time.Now().Add(ln.handshakeTimeout))

	buf := handshakeBuffer.Get().([]byte)
	defer handshakeBuffer.Put(buf)
	lenBuf := make([]byte, 2)
	_, err := io.ReadFull(conn, lenBuf[:]) // read the whole handshake message
	if err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lenBuf[:])

	if length < 166 {
		return nil, errors.New("handshake message too short")
	}

	if length > 512 {
		return nil, errors.New("handshake message too long")
	}

	_, err = io.ReadFull(conn, buf[:length])
	if err != nil {
		return nil, err
	}

	parsedMsg, err := parseInitiatorHandshakeMessage(buf[:length])
	if err != nil {
		return nil, err
	}

	if parsedMsg.ProtocolVersion != PROTOCOL_VERSION {
		return nil, ErrProtocolVersionMismatch
	}

	// sessionID
	sessionID := parsedMsg.SessionID
	if !isZeroID(sessionID[:]) && ln.AllowConnectionResumption {
		if session, exists := ln.getSession(sessionID[:]); exists {
			// Session already exists

			if session.nonce.Load()+1 != uint32(parsedMsg.Nonce) || parsedMsg.Nonce == 0 {
				return nil, errors.New("invalid nonce for session resumption")
			}

			if parsedMsg.PublicKey == nil || len(parsedMsg.PublicKey) != ed25519.PublicKeySize || !bytes.Equal(parsedMsg.PublicKey, session.initiatorPublicKey) {
				return nil, errors.New("invalid public key for session resumption")
			}

			if !ed25519.Verify(session.initiatorPublicKey, buf[:int(length)-int(parsedMsg.signatureLen)-1], parsedMsg.Signature) {
				return nil, ErrInvalidSignature
			}

			ln.resumeSession(session, conn)
			return session, err
		}
	}

	if parsedMsg.Nonce != 0 {
		return nil, errors.New("invalid nonce for new session")
	}

	if parsedMsg.PublicKey == nil || len(parsedMsg.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key size")
	}
	if !ed25519.Verify(parsedMsg.PublicKey, buf[:int(length)-int(parsedMsg.signatureLen)-1], parsedMsg.Signature) {
		return nil, ErrInvalidSignature
	}

	//craft the response handshake message and send it back to the client
	sid := genSessID(32)
	res := append([]byte{PROTOCOL_VERSION}, sid...)
	var noncebuf [2]byte
	binary.BigEndian.PutUint16(noncebuf[:], 0)
	res = append(res, noncebuf[:]...) // append nonce
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	res = append(res, byte(len(pub)))
	res = append(res, pub...) // append responder public key

	sig := ed25519.Sign(priv, res)
	res = append(res, byte(len(sig)))
	res = append(res, sig...) // append signature

	activeSess := &activeSession{
		id:                  sid,
		initiatorPublicKey:  parsedMsg.PublicKey,
		responderPrivateKey: priv, // will be generated below
		nonce:               atomic.Uint32{},
	}

	ln.saveSession(sid, activeSess)

	_, err = conn.Write(res)
	if err != nil {
		return nil, err
	}

	s := NewSession(conn, ln.sessionConfig)
	activeSess.session = s

	conn.SetDeadline(time.Time{})

	return activeSess, nil

}

func (ln *Listener) resumeSession(session *activeSession, conn io.ReadWriteCloser) {
	session.session.alterConnection(conn)
}

/*
func (l *Listener) Addr() net.Addr {}

func (l *Listener) Close() error {}
*/
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

	// Convert []byte to string for map lookup
	s, exists := ln.sessions[string(ID)]
	return s, exists
}

func (ln *Listener) saveSession(ID string, s *activeSession) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	// Initialize map if nil
	if ln.sessions == nil {
		ln.sessions = make(map[string]*activeSession)
	}
	ln.sessions[string(ID)] = s

}

func (ln *Listener) deleteSession(ID string) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	s, exists := ln.sessions[ID]

	if !exists {
		log.Printf("[ERROR] Attempted to delete non-existent session: %x", ID)
		return
	}

	s.session.Close()

	delete(ln.sessions, string(ID))
}

type initiatorHandshakeMessage struct {
	length uint16

	ProtocolVersion uint8
	SessionID       [32]byte
	Nonce           uint16
	Random          [32]byte
	publicKeyLen    uint8
	PublicKey       []byte //max 128 bytes, min 32 bytes
	signatureLen    uint8
	Signature       []byte //max 128 bytes, min 64 bytes
}

func parseInitiatorHandshakeMessage(data []byte) (*initiatorHandshakeMessage, error) {

	msg := &initiatorHandshakeMessage{}
	msg.ProtocolVersion = data[0]
	copy(msg.SessionID[:], data[1:33])
	msg.Nonce = binary.BigEndian.Uint16(data[33:35])
	copy(msg.Random[:], data[35:67])
	msg.publicKeyLen = data[67]
	msg.PublicKey = data[68 : 68+msg.publicKeyLen]
	msg.signatureLen = data[68+msg.publicKeyLen]
	msg.Signature = data[69+msg.publicKeyLen : 69+msg.publicKeyLen+msg.signatureLen]

	return msg, nil
}

type responderHandshakeMessage struct {
	length          uint16
	ProtocolVersion uint8

	InitialStreamWindow       uint32
	InitialSessionWindow      uint32
	WindowUpdateRatio         uint32
	MaxFrameDataLen           uint32
	Reliability               bool
	AllowConnectionResumption bool
	SessionID                 [32]byte
	Nonce                     uint16
	PublicKey                 []byte
	Signature                 []byte
}
