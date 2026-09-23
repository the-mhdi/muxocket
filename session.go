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
	ErrSessionClosed = errors.New("session has been closed")
)

const maxBatchFrames int = 16

const (
	DEFAULT_MAX_FRAME_DATA_LEN   uint32 = 32 << 10
	DEFAULT_MAX_FRAME_LEN        uint32 = DEFAULT_MAX_FRAME_DATA_LEN + 9
	DEFAULT_MAX_CHANNEL_DATA_LEN uint32 = 32 << 10
	DEFAULT_MIN_FRAME_LEN        uint32 = 5
)

const (
	FLG_DATA uint8 = 1
	FLG_NOOP uint8 = 2
	FLG_FIN  uint8 = 3
	FLG_PING uint8 = 4
	FLG_PONG uint8 = 5
	FLG_UPD  uint8 = 6 // WINDOW_UPDATE
)

type Session struct {
	id string

	config *Config
	conn   io.ReadWriteCloser

	channelsMu sync.RWMutex
	channels   map[uint32]*Channel

	writer *writeScheduler

	// Connection-level flow control
	flow *SessionFlow

	die       chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool

	header [9]byte

	mu sync.Mutex // protects conn for concurrent writes
}

type PacketFrame struct {
	DataLength uint32 // acts as credit update value in flow control frames
	Flag       uint8
	ChID       uint32
	Data       []byte
}

type Config struct {
	MaxFrameDataSize       uint32
	MaxChannelDataSize     uint32
	MaxWriteBufferSize     uint32
	InitialStreamWindow    uint32 // Flow control window per channel (Default 1 MB)
	InitialSessionWindow   uint32 // Flow control window for session (Default 4 MB)
	DrainChannelAfterClose bool
	KeepAlive              bool
	KeepAliveInterval      time.Duration
	KeepAliveTimeout       time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		MaxFrameDataSize:     DEFAULT_MAX_FRAME_LEN,
		MaxChannelDataSize:   DEFAULT_MAX_CHANNEL_DATA_LEN,
		MaxWriteBufferSize:   32,
		InitialStreamWindow:  DefaultInitialStreamWindow,
		InitialSessionWindow: DefaultInitialSessionWindow,
		KeepAlive:            true,
		KeepAliveInterval:    10 * time.Second,
		KeepAliveTimeout:     30 * time.Second,
	}
}

func NewSession(conn io.ReadWriteCloser, cfg *Config) *Session {
	return NewSessionWithID(conn, cfg, genSessID(32))
}

func NewSessionWithID(conn io.ReadWriteCloser, cfg *Config, id string) *Session {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.MaxChannelDataSize == 0 {
		cfg.MaxChannelDataSize = DEFAULT_MAX_CHANNEL_DATA_LEN
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

// writeControlFrameNonBlocking ensures Read() never blocks if ctrlQueue is saturated
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
		return false
	}
}

func (s *Session) readLoop() {
	defer s.Close()
	for {
		_, err := io.ReadFull(s.conn, s.header[:])
		if err != nil {
			return
		}

		DataLength := binary.BigEndian.Uint32(s.header[0:4])
		FRAME_FLAG := s.header[4]
		channelID := binary.BigEndian.Uint32(s.header[5:9])

		switch FRAME_FLAG {
		case FLG_DATA:
			if DataLength == 0 {
				continue
			}
			if DataLength > s.config.MaxFrameDataSize {
				return
			}

			pNewbuf := defaultAllocator.Get(int(DataLength))
			_, err := io.ReadFull(s.conn, *pNewbuf)
			if err != nil {
				defaultAllocator.Put(pNewbuf)
				return
			}

			s.channelsMu.RLock()
			ch, ok := s.channels[channelID]
			s.channelsMu.RUnlock()

			if ok {
				if err := ch.Feed(pNewbuf); err != nil {
					defaultAllocator.Put(pNewbuf)
				}
			} else {
				defaultAllocator.Put(pNewbuf)
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
				ch.remoteClose()
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
		s.conn.Close()
	})
	return nil
}

func (s *Session) getConn() io.ReadWriteCloser {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *Session) alterConnection(conn io.ReadWriteCloser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn = conn
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
