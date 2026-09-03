package muxocket

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrSessionClosed = errors.New("session closed")
)

const (
	DEFAULT_MAX_FRAME_DATA_LEN   uint32 = 32 << 10
	DEFAULT_MAX_FRAME_LEN        uint32 = DEFAULT_MAX_FRAME_DATA_LEN + 9
	DEFAULT_MAX_CHANNEL_DATA_LEN uint32 = 32 << 10 //ringbuffer performs better at < 32KB since l1 cache of most modern cpus are around 32k
	DEFAULT_MIN_FRAME_LEN        uint32 = 5
)

const (
	FLG_DATA uint8 = 1
	FLG_SYN  uint8 = 2
	FLG_FIN  uint8 = 3
	FLG_PING uint8 = 4

	maxBatchFrames = 64 // Max frames coalesced per flush
)

type Session struct {
	config *Config
	conn   io.ReadWriteCloser

	channelsMu sync.RWMutex
	channels   map[uint32]*Channel

	writer *writeScheduler

	die       chan struct{}
	closeOnce sync.Once
	closed    atomic.Bool

	header [9]byte // Private to readLoop (no concurrent access)

}

type Config struct {
	MaxFrameDataSize       uint32 // def 32KB
	MaxChannelDataSize     uint32 // if not set def 16KB
	MaxWriteBufferSize     uint32
	DrainChannelAfterClose bool
	KeepAlive              bool
	KeepAliveInterval      time.Duration
	KeepAliveTimeout       time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		MaxFrameDataSize:   DEFAULT_MAX_FRAME_LEN,
		MaxChannelDataSize: DEFAULT_MAX_CHANNEL_DATA_LEN,
		MaxWriteBufferSize: 16,
		KeepAlive:          true,
		KeepAliveInterval:  10 * time.Second,
		KeepAliveTimeout:   30 * time.Second,
	}
}

type PacketFrame struct {
	DataLength uint32
	Flag       uint8
	ChannID    uint32
	Data       []byte
}

func NewSession(conn io.ReadWriteCloser, cfg *Config) *Session {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.MaxChannelDataSize == 0 {
		cfg.MaxChannelDataSize = DEFAULT_MAX_CHANNEL_DATA_LEN
	}
	if cfg.MaxFrameDataSize == 0 {
		cfg.MaxFrameDataSize = DEFAULT_MAX_FRAME_LEN
	}

	s := &Session{
		config:   cfg,
		conn:     conn,
		channels: make(map[uint32]*Channel),
		die:      make(chan struct{}),
	}

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
		return nil, errors.New("channel name has to be 1 to 6 chars long [a-z, A-Z]")
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

func (s *Session) readLoop() {
	defer s.Close()
	for {
		_, err := io.ReadFull(s.conn, s.header[:])
		if err != nil {
			return
		}

		DataLength := binary.BigEndian.Uint32(s.header[0:4])

		if DataLength > s.config.MaxFrameDataSize {
			return
		}

		FRAME_FLAG := s.header[4]
		switch FRAME_FLAG {

		case FLG_DATA:
			if DataLength == 0 {
				continue
			}
			channelID := binary.BigEndian.Uint32(s.header[5:9])
			pNewbuf := defaultAllocator.Get(int(DataLength))
			_, err := io.ReadFull(s.conn, *pNewbuf)
			if err != nil {
				// recycle the buffer immediately.
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
				// Channel closed or missing: recycle buffer immediately
				defaultAllocator.Put(pNewbuf)
			}
		case FLG_FIN:
			channelID := binary.BigEndian.Uint32(s.header[5:9])
			s.channelsMu.RLock()
			ch, ok := s.channels[channelID]
			s.channelsMu.RUnlock()
			if ok {
				ch.remoteClose()
			}

		}

	}
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
			val = uint32(c - 'A' + 10) // Case-insensitive
		} else {
			return 0, false // Invalid character
		}

		// Bijective base-36 accumulation: prevents "0" vs "00" collision
		n = n*36 + val + 1
	}

	return n, true
}

func uint32ToString(n uint32) (string, bool) {
	// 2238976116 is the maximum value for a 6-character base-36 string ("zzzzzz")
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
