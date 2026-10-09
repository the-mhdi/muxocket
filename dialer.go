package muxocket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

type dialer struct {
	session            *Session
	nonce              atomic.Uint32
	PrivateKey         ed25519.PrivateKey
	responderPublicKey ed25519.PublicKey
	mu                 sync.RWMutex
}

func Dial(conn net.Conn) (*Session, error) {

	// Generate client identity
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	sess, _, err := clientHandshake(conn, cfg, clientPriv)
	if err != nil {
		return nil, err
	}

	return sess, nil

	//conn.Write()
	//return NewSession(), nil
}

func clientHandshake(conn net.Conn, cfg *Config, priv ed25519.PrivateKey) (*Session, *responderHandshakeMessage, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	req, err := BuildInitiatorHandshake([32]byte{}, 0, priv)
	if err != nil {
		return nil, nil, err
	}

	if _, err := conn.Write(req); err != nil {
		return nil, nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, nil, err
	}

	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen < ResponderPayloadLen || respLen > MaxHandshakeLen {
		return nil, nil, fmt.Errorf("invalid responder handshake length: %d", respLen)
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, nil, err
	}

	resp, err := parseResponderHandshakeMessage(respBuf)
	if err != nil {
		return nil, nil, err
	}

	if resp.ProtocolVersion != PROTOCOL_VERSION {
		return nil, nil, ErrProtocolVersionMismatch
	}

	signedPortion := respBuf[:54+int(resp.publicKeyLen)]
	if !ed25519.Verify(resp.PublicKey, signedPortion, resp.Signature) {
		return nil, nil, ErrInvalidSignature
	}

	sessCfg := *cfg
	sessCfg.InitialStreamWindow = resp.InitialStreamWindow
	sessCfg.InitialSessionWindow = resp.InitialSessionWindow
	sessCfg.MaxFrameDataSize = resp.MaxFrameDataLen
	sessCfg.Reliability = resp.Reliability

	sess := NewSessionWithID(conn, &sessCfg, string(resp.SessionID[:]))
	return sess, resp, nil
}
