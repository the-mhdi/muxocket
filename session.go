package muxocket

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrSessionClosed    = errors.New("session has been closed")
	ErrSessionSuspended = errors.New("session is suspended awaiting reconnect")
)

const maxBatchFrames int = 16

const (
	DEFAULT_MAX_FRAME_DATA_LEN   uint32 = 32 << 10
	DEFAULT_MAX_FRAME_LEN        uint32 = DEFAULT_MAX_FRAME_DATA_LEN + 17
	DEFAULT_MAX_CHANNEL_DATA_LEN uint32 = DEFAULT_MAX_FRAME_DATA_LEN
	DEFAULT_MIN_FRAME_LEN        uint32 = 5
)

const (
	FLG_DATA uint8 = 1
	FLG_NOOP uint8 = 2
	FLG_FIN  uint8 = 3
	FLG_PING uint8 = 4
	FLG_PONG uint8 = 5
	FLG_UPD  uint8 = 6 // WINDOW_UPDATE
	FLG_ACK  uint8 = 7 // ARQ ACKNOWLEDGEMENT
)

type Session struct {
	id     string
	config *Config
	connMu sync.RWMutex
	conn   io.ReadWriteCloser
	// connEpoch is bumped every time the transport is swapped or dropped.
	// Grace-period timers capture it so a stale timer can't kill a session
	// that has been resumed (and possibly dropped again) in the meantime.
	connEpoch atomic.Uint64
	// readerMu guarantees a single readLoop at a time. Channel rings are SPSC,
	// so two overlapping readLoops (old + resumed conn) would corrupt them.
	readerMu sync.Mutex

	channelsMu sync.RWMutex
	channels   map[uint32]*Channel

	writer *writeScheduler
	flow   *SessionFlow

	die       chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool
	suspended atomic.Bool

	// rxActivity is set by readLoop on every frame; the keepalive loop
	// clears it to detect dead/half-open transports.
	rxActivity atomic.Bool

	unknownChannelErrors atomic.Uint32

	// dialer holds client-side resumption state (nil on the listener side).
	dialer atomic.Pointer[dialer]

	hooksMu    sync.Mutex
	closeHooks []func()
}

type PacketFrame struct {
	DataLength uint32
	Flag       uint8
	ChID       uint32
	Offset     uint64
	Data       []byte
}

type Config struct {
	MaxFrameDataSize uint32
	//MaxChannelDataSize     uint32
	MaxWriteBufferSize      uint32
	InitialStreamWindow     uint32
	InitialSessionWindow    uint32
	DrainChannelAfterClose  bool
	KeepAlive               bool
	KeepAliveInterval       time.Duration
	KeepAliveTimeout        time.Duration
	MaxUnknownChannelErrors uint32 //default 128, if a session receives more than this number of unknown channel errors, it will close the session
	// Reliability Engine (ARQ)
	Reliability       bool          // Enable ARQ, stream offsets, in-order reassembly, and ACKs
	RetransmitTimeout time.Duration // Base RTO
	MaxRetransmit     int           // Max attempts before closing channel
	AckInterval       time.Duration // Delay ACK window

	// Resumption Configuration
	AllowConnectionResumption bool
	ConnectionResumeTimeout   time.Duration
}

func DefaultConfig() *Config {
	return &Config{

		MaxFrameDataSize:          DEFAULT_MAX_FRAME_DATA_LEN,
		MaxWriteBufferSize:        32,
		InitialStreamWindow:       DefaultInitialStreamWindow,
		InitialSessionWindow:      DefaultInitialSessionWindow,
		MaxUnknownChannelErrors:   128,
		KeepAlive:                 true,
		KeepAliveInterval:         10 * time.Second,
		KeepAliveTimeout:          30 * time.Second,
		Reliability:               false,
		RetransmitTimeout:         150 * time.Millisecond,
		MaxRetransmit:             8,
		AckInterval:               10 * time.Millisecond,
		AllowConnectionResumption: true,
		ConnectionResumeTimeout:   5 * time.Second,
	}
}

func NewSession(conn io.ReadWriteCloser, cfg *Config) *Session {
	return NewSessionWithID(conn, cfg, genSessID(32))
}

func NewSessionWithID(conn io.ReadWriteCloser, cfg *Config, id string) *Session {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	// Each session owns a private copy. The listener used to hand the same
	// *Config to every session, and the defaulting below mutated it
	// concurrently from many goroutines (data race).
	c := *cfg
	cfg = &c

	if cfg.MaxFrameDataSize == 0 {
		cfg.MaxFrameDataSize = DEFAULT_MAX_FRAME_DATA_LEN
	}
	if cfg.MaxFrameDataSize > MaxAllocSize {
		// The allocator returns nil above MaxAllocSize; readLoop would panic.
		cfg.MaxFrameDataSize = MaxAllocSize
	}
	if cfg.InitialStreamWindow == 0 {
		cfg.InitialStreamWindow = DefaultInitialStreamWindow
	}
	if cfg.InitialSessionWindow == 0 {
		cfg.InitialSessionWindow = DefaultInitialSessionWindow
	}

	if cfg.RetransmitTimeout == 0 {
		cfg.RetransmitTimeout = 150 * time.Millisecond
	}

	if cfg.MaxRetransmit == 0 {
		cfg.MaxRetransmit = 8
	}
	if cfg.MaxUnknownChannelErrors == 0 {
		cfg.MaxUnknownChannelErrors = 128
	}

	s := &Session{
		id:       id,
		config:   cfg,
		conn:     conn,
		channels: make(map[uint32]*Channel),
		die:      make(chan struct{}),
	}

	s.flow = NewSessionFlow(int32(cfg.InitialSessionWindow), s)
	s.writer = newWriteScheduler(s, conn, int(cfg.MaxWriteBufferSize))

	go s.readLoop(conn)
	if cfg.KeepAlive && cfg.KeepAliveInterval > 0 {
		go s.keepAliveLoop()
	}
	return s
}

func (s *Session) OpenChannel(label string) (*Channel, error) {
	if s.isClosed() {
		return nil, ErrSessionClosed
	}

	id, ok := stringToUint32(label)
	if !ok {
		return nil, errors.New("channel name has to be 1 to 6 chars long [a-z, A-Z, 0-9]")
	}

	s.channelsMu.Lock()
	defer s.channelsMu.Unlock()

	if _, exists := s.channels[id]; exists {
		return nil, errors.New("channel with this label and ID already exists")
	}

	ch := newChannel(id, s)
	s.channels[id] = ch
	return ch, nil
}

func (s *Session) getChannel(id uint32) *Channel {
	s.channelsMu.RLock()
	ch := s.channels[id]
	s.channelsMu.RUnlock()
	return ch
}

func (s *Session) removeChannel(id uint32) {
	s.channelsMu.Lock()
	delete(s.channels, id)
	s.channelsMu.Unlock()
}

func (s *Session) isClosed() bool {
	return s.closed.Load()
}

func (s *Session) writeDataFrame(f writeFrame) error {
	if s.isClosed() {
		return ErrSessionClosed
	}
	select {
	case <-s.die:
		return ErrSessionClosed
	case s.writer.writes <- f:
		return nil
	}
}

func (s *Session) writeControlFrame(f writeFrame) error {
	if s.isClosed() {
		return ErrSessionClosed
	}
	select {
	case <-s.die:
		return ErrSessionClosed
	case s.writer.ctrlQueue <- f:
		return nil
	}
}

func (s *Session) writeControlFrameNonBlocking(f writeFrame) bool {
	if s.isClosed() {
		return false
	}
	select {
	case <-s.die:
		return false
	case s.writer.ctrlQueue <- f:
		return true
	default:
		// Fallback to async delivery to prevent flow control deadlocks.
		// ACKs are coalesced per channel (see Channel.sendAck), so the number
		// of these goroutines is bounded by the number of channels instead of
		// the number of received frames.
		go func() {
			select {
			case <-s.die:
			case s.writer.ctrlQueue <- f:
			}
		}()
		return true
	}
}

func (s *Session) writeDataFrameNonBlocking(f writeFrame) bool {
	if s.isClosed() {
		return false
	}
	select {
	case <-s.die:
		return false
	case s.writer.writes <- f:
		return true
	default:
		return false
	}
}

// creditDiscarded gives session-level credit back for payload bytes that were
// received but will never be read by the application (unknown/closed channel).
// Without this the sender's session window shrinks permanently and the whole
// session eventually stalls. Only used in non-reliable mode: in ARQ mode the
// sender retransmits without consuming new credit, and the retransmission is
// credited when read.
func (s *Session) creditDiscarded(n uint32) {
	if s.config.Reliability || s.flow == nil || !s.flow.enabled || n == 0 {
		return
	}
	s.flow.OnRead(int32(n))
}

func (s *Session) readLoop(c io.ReadWriteCloser) {
	if c == nil {
		return
	}
	s.readerMu.Lock()
	defer s.readerMu.Unlock()

	// Local header: the old shared s.header field was written by two
	// goroutines when a resumed readLoop overlapped the dying one.
	var header [17]byte

	for {
		if s.isClosed() {
			return
		}

		if _, err := io.ReadFull(c, header[:]); err != nil {
			s.handleDisconnect(c)
			return
		}
		s.rxActivity.Store(true)

		dataLength := binary.BigEndian.Uint32(header[0:4])
		flag := header[4]
		channelID := binary.BigEndian.Uint32(header[5:9])
		offset := binary.BigEndian.Uint64(header[9:17])

		switch flag {
		case FLG_DATA:
			if dataLength == 0 {
				continue
			}
			if dataLength > s.config.MaxFrameDataSize || dataLength > MaxAllocSize {
				// Framing violation: the stream can't be trusted any more.
				s.handleDisconnect(c)
				return
			}

			// Always consume the payload, even for unknown channels. The old
			// code `continue`d before reading it, desynchronising the stream
			// (payload bytes were then parsed as the next header).
			pNewbuf := defaultAllocator.Get(int(dataLength))
			if _, err := io.ReadFull(c, *pNewbuf); err != nil {
				_ = defaultAllocator.Put(pNewbuf)
				s.handleDisconnect(c)
				return
			}

			ch := s.getChannel(channelID)
			if ch == nil {
				_ = defaultAllocator.Put(pNewbuf)
				s.creditDiscarded(dataLength)
				if s.unknownChannelErrors.Add(1) > s.config.MaxUnknownChannelErrors {
					// Previously this just returned, leaving the session
					// half-alive with no reader. Close it properly.
					s.Close()
					return
				}
				continue
			}

			if s.config.Reliability {
				ch.feedReliable(offset, pNewbuf, dataLength)
			} else if err := ch.feed(pNewbuf); err != nil {
				_ = defaultAllocator.Put(pNewbuf)
				s.creditDiscarded(dataLength)
			}

		case FLG_ACK:
			if s.config.Reliability {
				if ch := s.getChannel(channelID); ch != nil {
					ch.onAck(offset)
				}
			}

		case FLG_UPD:
			delta := int32(dataLength)
			if channelID == 0 {
				if s.flow != nil {
					s.flow.AddCredits(delta)
				}
			} else if ch := s.getChannel(channelID); ch != nil {
				ch.flow.AddCredits(delta)
			}

		case FLG_FIN:
			if ch := s.getChannel(channelID); ch != nil {
				if s.config.Reliability {
					ch.handleFinReliable(offset)
				} else {
					ch.remoteClose()
				}
			}

		case FLG_PING:
			// Never block the reader on a full control queue: a peer that
			// isn't reading would otherwise stall our whole receive path.
			select {
			case s.writer.ctrlQueue <- writeFrame{flag: FLG_PONG}:
			default:
			}

		case FLG_PONG, FLG_NOOP:
			// liveness only (rxActivity already recorded)

		default:
			// Unknown flag: we can't know whether a payload follows, so the
			// framing is lost.
			s.handleDisconnect(c)
			return
		}
	}
}

// keepAliveLoop sends PINGs and drops the transport when nothing has been
// received for KeepAliveTimeout. This is the only way to detect dead UDP peers
// and half-open TCP connections; previously the KeepAlive* settings were unused.
func (s *Session) keepAliveLoop() {
	interval := s.config.KeepAliveInterval
	timeout := s.config.KeepAliveTimeout
	if timeout < interval {
		timeout = 3 * interval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastSeen := time.Now()

	for {
		select {
		case <-s.die:
			return
		case now := <-ticker.C:
			if s.rxActivity.Swap(false) || s.suspended.Load() {
				lastSeen = now
			} else if now.Sub(lastSeen) > timeout {
				if c := s.getConn(); c != nil {
					s.handleDisconnect(c)
				}
				lastSeen = now
				continue
			}
			select {
			case s.writer.ctrlQueue <- writeFrame{flag: FLG_PING}:
			default: // queue busy => traffic is flowing anyway
			}
		}
	}
}

// handleDisconnect is called with the transport that failed. If that transport
// has already been replaced (resumption raced with the old reader/writer
// noticing the error), the call is ignored. The old version unconditionally
// nil'ed s.conn, which could tear down a freshly resumed connection.
func (s *Session) handleDisconnect(failed io.ReadWriteCloser) {
	if s.isClosed() {
		return
	}
	if !s.config.AllowConnectionResumption {
		s.Close()
		return
	}

	s.connMu.Lock()
	if s.conn == nil || (failed != nil && s.conn != failed) {
		s.connMu.Unlock()
		return // stale notification or already suspended
	}
	old := s.conn
	s.conn = nil
	epoch := s.connEpoch.Add(1)
	s.writer.alterConn(nil)
	s.suspended.Store(true)
	s.connMu.Unlock()

	_ = old.Close()

	// Grace period timer for reconnection
	go func() {
		t := time.NewTimer(s.config.ConnectionResumeTimeout)
		defer t.Stop()
		select {
		case <-s.die:
		case <-t.C:
			if s.suspended.Load() && s.connEpoch.Load() == epoch {
				s.Close()
			}
		}
	}()

	if d := s.dialer.Load(); d != nil && d.redial != nil {
		go d.autoResume()
	}
}

func (s *Session) resumeWithConnection(conn io.ReadWriteCloser) {
	s.connMu.Lock()
	old := s.conn
	s.conn = conn
	s.connEpoch.Add(1)
	s.writer.alterConn(conn)
	s.suspended.Store(false)
	s.connMu.Unlock()

	// A migrated client may leave the old transport half-open; close it so
	// the old readLoop exits and releases readerMu.
	if old != nil && old != conn {
		_ = old.Close()
	}

	// Retransmit any unacknowledged frames across all channels. Done
	// asynchronously: with a synchronous transport (net.Pipe) or a full write
	// queue this would otherwise block the caller until the peer reads.
	if s.config.Reliability {
		s.channelsMu.RLock()
		chans := make([]*Channel, 0, len(s.channels))
		for _, ch := range s.channels {
			chans = append(chans, ch)
		}
		s.channelsMu.RUnlock()
		go func() {
			for _, ch := range chans {
				ch.retransmitAllUnacked()
			}
		}()
	}

	go s.readLoop(conn)
}

func (s *Session) wakeWaitingChannels() {
	s.channelsMu.RLock()
	for _, ch := range s.channels {
		ch.flow.WakeWriter()
	}
	s.channelsMu.RUnlock()
}

func (s *Session) ID() string {
	return s.id
}

func (s *Session) alterID(newID string) string {
	s.id = newID
	return s.id
}

// addCloseHook registers fn to run once the session is closed. If the session
// is already closed fn runs immediately.
func (s *Session) addCloseHook(fn func()) {
	s.hooksMu.Lock()
	if s.isClosed() {
		s.hooksMu.Unlock()
		fn()
		return
	}
	s.closeHooks = append(s.closeHooks, fn)
	s.hooksMu.Unlock()
}

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.hooksMu.Lock()
		s.closed.Store(true)
		hooks := s.closeHooks
		s.closeHooks = nil
		s.hooksMu.Unlock()

		close(s.die)

		s.channelsMu.Lock()
		activeChannels := make([]*Channel, 0, len(s.channels))
		for _, ch := range s.channels {
			activeChannels = append(activeChannels, ch)
		}
		s.channels = make(map[uint32]*Channel)
		s.channelsMu.Unlock()

		for _, ch := range activeChannels {
			ch.localClose()
		}

		s.writer.Close()

		s.connMu.Lock()
		if s.conn != nil {
			s.conn.Close()
		}
		s.connMu.Unlock()

		for _, fn := range hooks {
			fn()
		}
	})
	return nil
}

func (s *Session) getConn() io.ReadWriteCloser {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return s.conn
}

func (s *Session) alterConnection(conn io.ReadWriteCloser) {
	s.resumeWithConnection(conn)
}

func stringToUint32(s string) (uint32, bool) {
	if len(s) == 0 || len(s) > 6 {
		return 0, false
	}
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		var val uint32
		if c >= '0' && c <= '9' {
			val = uint32(c - '0')
		} else if c >= 'a' && c <= 'z' {
			val = uint32(c - 'a' + 10)
		} else if c >= 'A' && c <= 'Z' {
			val = uint32(c - 'A' + 10)
		} else {
			return 0, false
		}
		n = n*36 + val + 1
	}
	return n, true
}

func uint32ToString(n uint32) (string, bool) {
	if n == 0 || n > 2238976116 {
		return "", false
	}
	var buf [6]byte
	idx := 6
	for n > 0 {
		idx--
		n--
		rem := n % 36
		if rem < 10 {
			buf[idx] = byte('0' + rem)
		} else {
			buf[idx] = byte('a' + (rem - 10))
		}
		n /= 36
	}
	return string(buf[idx:]), true
}

func genSessID(len uint8) string {
	return string(randomBytes(int(len)))
}

func randomBytes(length int) []byte {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("randomBytes() ERROR:%v \r\n", err)
	}
	return b
}
