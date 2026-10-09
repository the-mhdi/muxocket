package muxocket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultHandshakeTimeout bounds the whole client handshake (write request,
	// read response). Without it a lost UDP datagram or a silent server hung
	// Dial forever.
	DefaultHandshakeTimeout = 5 * time.Second

	// maxUDPPayload is the largest datagram we may receive on a packet conn.
	maxUDPPayload = 65535
)

var (
	ErrNotResumable      = errors.New("session was not created by a dialer and cannot be resumed")
	ErrResumeInProgress  = errors.New("session resumption already in progress")
	ErrNonceExhausted    = errors.New("resumption nonce space exhausted")
	ErrServerKeyMismatch = errors.New("responder public key changed during resumption")
	ErrSessionIDMismatch = errors.New("responder returned a different session id")
	ErrInvalidHandshake  = errors.New("invalid responder handshake parameters")
)

// Dialer establishes client-side (initiator) sessions on top of an already
// connected transport: TCP/Unix stream conns, or connected UDP / raw IP conns.
//
// The zero value is usable.
type Dialer struct {
	// Config is the local session config. Window sizes, max frame size and
	// reliability are overridden by what the listener advertises.
	Config *Config

	// PrivateKey is the client identity used to sign handshakes. If nil, an
	// ephemeral Ed25519 key is generated per session. The same key is
	// required for resumption, which the session remembers internally.
	PrivateKey ed25519.PrivateKey

	// HandshakeTimeout bounds each handshake. Defaults to DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration

	// Redial, if set, is used to obtain a fresh transport whenever the current
	// one breaks; the session is then resumed transparently (connection
	// migration). Without it, call Session.Resume yourself.
	Redial func() (net.Conn, error)
}

// dialer is the per-session client state needed for resumption.
type dialer struct {
	session            *Session
	nonce              atomic.Uint32
	PrivateKey         ed25519.PrivateKey
	responderPublicKey ed25519.PublicKey
	sessionID          [32]byte
	timeout            time.Duration
	redial             func() (net.Conn, error)
	mu                 sync.Mutex // serialises resume attempts
	resuming           atomic.Bool
}

// Dial performs the initiator handshake over conn with default settings and
// returns the established session.
func Dial(conn net.Conn) (*Session, error) {
	var d Dialer
	return d.Dial(conn)
}

// DialConfig is Dial with a custom local config.
func DialConfig(conn net.Conn, cfg *Config) (*Session, error) {
	d := Dialer{Config: cfg}
	return d.Dial(conn)
}

// Dial performs the initiator handshake over conn and returns the session.
// On failure conn is left open; the caller owns it.
func (d *Dialer) Dial(conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, errors.New("muxocket: nil conn")
	}
	priv := d.PrivateKey
	if priv == nil {
		var err error
		if _, priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	} else if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("muxocket: invalid ed25519 private key")
	}

	sess, _, err := d.dial(conn, priv)
	return sess, err
}

func (d *Dialer) timeout() time.Duration {
	if d != nil && d.HandshakeTimeout > 0 {
		return d.HandshakeTimeout
	}
	return DefaultHandshakeTimeout
}

func (d *Dialer) dial(conn net.Conn, priv ed25519.PrivateKey) (*Session, *responderHandshakeMessage, error) {
	cfg := d.Config
	if cfg == nil {
		cfg = DefaultConfig()
	}

	tconn := wrapTransport(conn)
	timeout := d.timeout()

	resp, err := initiatorExchange(tconn, timeout, [32]byte{}, 0, priv)
	if err != nil {
		return nil, nil, err
	}
	if resp.Nonce != 0 {
		return nil, nil, ErrInvalidNonce
	}

	sessCfg, err := negotiatedConfig(cfg, resp)
	if err != nil {
		return nil, nil, err
	}
	if dc, ok := tconn.(*datagramConn); ok {
		// Pack outgoing frames into datagrams no larger than what the
		// listener can receive (it advertised MTU-17 as max frame data).
		dc.setMaxOut(int(sessCfg.MaxFrameDataSize) + 17)
	}

	st := &dialer{
		PrivateKey:         priv,
		responderPublicKey: append(ed25519.PublicKey(nil), resp.PublicKey...),
		sessionID:          resp.SessionID,
		timeout:            timeout,
		redial:             d.Redial,
	}

	sess := NewSessionWithID(tconn, sessCfg, string(resp.SessionID[:]))
	st.session = sess
	sess.dialer.Store(st)
	return sess, resp, nil
}

// clientHandshake is the low-level initiator handshake (kept for tests and
// internal callers).
func clientHandshake(conn net.Conn, cfg *Config, priv ed25519.PrivateKey) (*Session, *responderHandshakeMessage, error) {
	d := Dialer{Config: cfg}
	return d.dial(conn, priv)
}

// negotiatedConfig applies the listener-advertised parameters to a copy of
// the local config, validating them first.
func negotiatedConfig(local *Config, resp *responderHandshakeMessage) (*Config, error) {
	if resp.MaxFrameDataLen == 0 || resp.MaxFrameDataLen > MaxAllocSize {
		return nil, fmt.Errorf("%w: max frame data size %d", ErrInvalidHandshake, resp.MaxFrameDataLen)
	}
	// Windows are tracked as int32; reject values that would wrap negative.
	if resp.InitialStreamWindow == 0 || resp.InitialStreamWindow > math.MaxInt32 ||
		resp.InitialSessionWindow > math.MaxInt32 {
		return nil, fmt.Errorf("%w: window sizes", ErrInvalidHandshake)
	}

	sessCfg := *local
	sessCfg.InitialStreamWindow = resp.InitialStreamWindow
	sessCfg.InitialSessionWindow = resp.InitialSessionWindow
	sessCfg.MaxFrameDataSize = resp.MaxFrameDataLen
	sessCfg.Reliability = resp.Reliability
	// Only keep the session around after a drop if both sides agreed to it.
	sessCfg.AllowConnectionResumption = local.AllowConnectionResumption && resp.AllowConnectionResumption
	return &sessCfg, nil
}

// initiatorExchange sends one initiator handshake and reads/validates the
// responder's reply. It does not create a session.
func initiatorExchange(conn net.Conn, timeout time.Duration, sid [32]byte, nonce uint16, priv ed25519.PrivateKey) (*responderHandshakeMessage, error) {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}

	req, err := BuildInitiatorHandshake(sid, nonce, priv)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}

	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen < ResponderPayloadLen || respLen > MaxHandshakeLen {
		return nil, fmt.Errorf("invalid responder handshake length: %d", respLen)
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, err
	}

	resp, err := parseResponderHandshakeMessage(respBuf)
	if err != nil {
		return nil, err
	}

	if resp.ProtocolVersion != PROTOCOL_VERSION {
		return nil, ErrProtocolVersionMismatch
	}
	if len(resp.PublicKey) != ed25519.PublicKeySize || len(resp.Signature) != ed25519.SignatureSize {
		// ed25519.Verify panics on a wrong-sized public key.
		return nil, ErrMalformedHandshake
	}

	// The signature must cover our exact request (incl. its fresh random), so
	// a response captured from an earlier handshake fails here.
	signedPortion := respBuf[:54+int(resp.publicKeyLen)]
	if !ed25519.Verify(resp.PublicKey, responderSignedMessage(signedPortion, req[2:]), resp.Signature) {
		return nil, ErrInvalidSignature
	}
	if nonce != 0 && resp.Nonce != nonce {
		return nil, ErrInvalidNonce
	}
	if !isZeroID(sid[:]) && resp.SessionID != sid {
		return nil, ErrSessionIDMismatch
	}
	return resp, nil
}

// Resume re-attaches a client session to a new transport (for example after
// the client's IP changed or the TCP connection dropped). The session must
// have been created by Dial/Dialer and still be within its
// ConnectionResumeTimeout grace period. Channels, offsets and (with
// Reliability) unacknowledged data survive the switch.
//
// On failure conn is left open; the caller owns it.
func (s *Session) Resume(conn net.Conn) error {
	d := s.dialer.Load()
	if d == nil {
		return ErrNotResumable
	}
	return d.resume(conn)
}

func (d *dialer) resume(conn net.Conn) error {
	s := d.session
	if s.isClosed() {
		return ErrSessionClosed
	}
	if !s.config.AllowConnectionResumption {
		return ErrResumptionDisabled
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Consume the nonce *before* trying. The listener only requires nonces
	// to increase, so a failed attempt (e.g. the response got lost after the
	// server accepted it) can't wedge us on an already-used nonce.
	next := d.nonce.Add(1)
	if next > math.MaxUint16 {
		return ErrNonceExhausted
	}

	tconn := wrapTransport(conn)
	resp, err := initiatorExchange(tconn, d.timeout, d.sessionID, uint16(next), d.PrivateKey)
	if err != nil {
		return err
	}
	// Pin the responder identity learned on the first handshake: otherwise
	// anyone could answer a resumption with their own key.
	if !bytes.Equal(resp.PublicKey, d.responderPublicKey) {
		return ErrServerKeyMismatch
	}
	if dc, ok := tconn.(*datagramConn); ok {
		dc.setMaxOut(int(s.config.MaxFrameDataSize) + 17)
	}
	if s.isClosed() {
		return ErrSessionClosed
	}

	s.resumeWithConnection(tconn)
	return nil
}

// autoResume is started by Session.handleDisconnect when Dialer.Redial is
// set. It retries with exponential backoff until the session is resumed,
// closed, or the grace period runs out.
func (d *dialer) autoResume() {
	if !d.resuming.CompareAndSwap(false, true) {
		return
	}
	defer d.resuming.Store(false)

	s := d.session
	deadline := time.Now().Add(s.config.ConnectionResumeTimeout)
	backoff := 50 * time.Millisecond

	for time.Now().Before(deadline) && !s.isClosed() && s.suspended.Load() {
		conn, err := d.redial()
		if err == nil {
			if err = d.resume(conn); err == nil {
				return
			}
			_ = conn.Close()
		}

		select {
		case <-s.die:
			return
		case <-time.After(backoff):
		}
		if backoff < time.Second {
			backoff *= 2
		}
	}
}

// ============================================================================
// DATAGRAM TRANSPORT ADAPTER (client side)
// ============================================================================

// datagramConn turns a connected packet conn (UDP, raw IP, unixgram) into the
// byte stream Session expects. Reading a UDP socket with a short buffer
// discards the rest of the datagram, so the old Dial lost data as soon as
// io.ReadFull asked for the 2-byte handshake length (and every 17-byte frame
// header afterwards). Here every datagram is read whole and served piecewise.
type datagramConn struct {
	net.Conn
	pc net.PacketConn // non-nil when ReadFrom is available (strips IPv4 header on raw IP)

	readMu sync.Mutex
	buf    []byte
	r, w   int

	maxOut atomic.Int32
}

func isDatagramNetwork(network string) bool {
	switch {
	case strings.HasPrefix(network, "udp"),
		strings.HasPrefix(network, "ip"),
		network == "unixgram", network == "unixpacket":
		return true
	}
	return false
}

func wrapTransport(conn net.Conn) net.Conn {
	if _, ok := conn.(*datagramConn); ok {
		return conn
	}
	la := conn.LocalAddr()
	if la == nil || !isDatagramNetwork(la.Network()) {
		return conn
	}
	dc := &datagramConn{Conn: conn, buf: make([]byte, maxUDPPayload)}
	if pc, ok := conn.(net.PacketConn); ok {
		dc.pc = pc
	}
	dc.maxOut.Store(1500 - 28) // conservative until the handshake tells us more
	return dc
}

func (c *datagramConn) setMaxOut(n int) {
	if n > maxUDPPayload {
		n = maxUDPPayload
	}
	c.maxOut.Store(int32(n))
}

func (c *datagramConn) maxDatagramSize() int { return int(c.maxOut.Load()) }

func (c *datagramConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.r == c.w {
		var n int
		var err error
		if c.pc != nil {
			n, _, err = c.pc.ReadFrom(c.buf)
		} else {
			n, err = c.Conn.Read(c.buf)
		}
		if err != nil {
			return 0, err
		}
		c.r, c.w = 0, n
	}
	n := copy(b, c.buf[c.r:c.w])
	c.r += n
	return n, nil
}
