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

	channelsMu sync.RWMutex
	channels   map[uint32]*Channel

	writer *writeScheduler
	flow   *SessionFlow

	die       chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool
	suspended atomic.Bool

	header [17]byte

	unknownChannelErrors atomic.Uint32
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
		MaxFrameDataSize:          DEFAULT_MAX_FRAME_LEN,
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
		AllowConnectionResumption: false,
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
	if cfg.MaxFrameDataSize == 0 {
		cfg.MaxFrameDataSize = DEFAULT_MAX_FRAME_LEN
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

	s := &Session{
		id:       id,
		config:   cfg,
		conn:     conn,
		channels: make(map[uint32]*Channel),
		die:      make(chan struct{}),
	}

	s.flow = NewSessionFlow(int32(cfg.InitialSessionWindow), s)
	s.writer = newWriteScheduler(s, conn, int(cfg.MaxWriteBufferSize))

	go s.readLoop()
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
		// Fallback to async delivery to prevent flow control deadlocks
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

func (s *Session) readLoop() {

	for {
		s.connMu.RLock()
		c := s.conn
		s.connMu.RUnlock()

		if c == nil || s.isClosed() {
			return
		}

		_, err := io.ReadFull(c, s.header[:17])
		if err != nil {
			s.handleDisconnect()
			return
		}

		DataLength := binary.BigEndian.Uint32(s.header[0:4])
		FRAME_FLAG := s.header[4]
		channelID := binary.BigEndian.Uint32(s.header[5:9])
		offset := binary.BigEndian.Uint64(s.header[9:17])

		switch FRAME_FLAG {
		case FLG_DATA:
			if DataLength == 0 {
				continue
			}
			if DataLength > s.config.MaxFrameDataSize {
				s.handleDisconnect()
				return
			}

			s.channelsMu.RLock()
			ch, ok := s.channels[channelID]
			s.channelsMu.RUnlock()
			if !ok {
				s.unknownChannelErrors.Add(1)
				if s.unknownChannelErrors.Load() > s.config.MaxUnknownChannelErrors {
					return
				}
				continue
			}
			pNewbuf := defaultAllocator.Get(int(DataLength))
			_, err := io.ReadFull(c, *pNewbuf)
			if err != nil {
				defaultAllocator.Put(pNewbuf)
				s.handleDisconnect()
				return
			}

			if ok {
				if s.config.Reliability {
					ch.feedReliable(offset, pNewbuf, DataLength)
				} else {
					if err := ch.Feed(pNewbuf); err != nil {
						defaultAllocator.Put(pNewbuf)
					}
				}
			} else {
				defaultAllocator.Put(pNewbuf)
			}

		case FLG_ACK:
			if s.config.Reliability {
				s.channelsMu.RLock()
				ch, ok := s.channels[channelID]
				s.channelsMu.RUnlock()
				if ok {
					ch.onAck(offset)
				}
			}

		case FLG_UPD:
			delta := int32(DataLength)
			if channelID == 0 {
				if s.flow != nil {
					s.flow.AddCredits(delta)
				}
			} else {
				s.channelsMu.RLock()
				ch, ok := s.channels[channelID]
				s.channelsMu.RUnlock()
				if ok {
					ch.flow.AddCredits(delta)
				}
			}

		case FLG_FIN:
			s.channelsMu.RLock()
			ch, ok := s.channels[channelID]
			s.channelsMu.RUnlock()
			if ok {
				if s.config.Reliability {
					ch.handleFinReliable(offset)
				} else {
					ch.remoteClose()
				}
			}

		case FLG_PING:
			pongFrame := writeFrame{
				flag:   FLG_PONG,
				chID:   0,
				pBuf:   nil,
				length: 0,
			}
			s.writeControlFrame(pongFrame)
		}
	}
}

func (s *Session) handleDisconnect() {
	if !s.config.AllowConnectionResumption || s.isClosed() {
		s.Close()
		return
	}

	s.connMu.Lock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.connMu.Unlock()

	s.suspended.Store(true)

	// Grace period timer for reconnection
	go func() {
		select {
		case <-s.die:
			return
		case <-time.After(s.config.ConnectionResumeTimeout):
			if s.suspended.Load() {
				s.Close()
			}
		}
	}()
}

func (s *Session) resumeWithConnection(conn io.ReadWriteCloser) {
	s.connMu.Lock()
	s.conn = conn
	s.connMu.Unlock()

	s.writer.alterConn(conn)
	s.suspended.Store(false)

	// Retransmit any unacknowledged frames across all channels
	if s.config.Reliability {
		s.channelsMu.RLock()
		for _, ch := range s.channels {
			ch.retransmitAllUnacked()
		}
		s.channelsMu.RUnlock()
	}

	go s.readLoop()
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

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
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
