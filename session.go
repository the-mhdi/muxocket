package muxocket

import (
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

const PROTOCOL_VERSION uint8 = 1

var (
	ErrSessionClosed    = errors.New("session has been closed")
	ErrSessionSuspended = errors.New("session is suspended awaiting reconnect")
)

const (
	FLG_DATA uint8 = 1
	FLG_NOOP uint8 = 2
	FLG_FIN  uint8 = 3
	FLG_PING uint8 = 4
	FLG_PONG uint8 = 5
	FLG_UPD  uint8 = 6 // WINDOW_UPDATE
	FLG_ACK  uint8 = 7 // ARQ ACKNOWLEDGEMENT
	// FLG_GOAWAY is the last frame of a graceful Close: the peer closes the
	// session immediately instead of suspending it for resumption.
	FLG_GOAWAY uint8 = 8 //session level RST
	// FLG_RST tells the peer that the sender has fully closed the channel and
	// discards anything else it receives on it. The peer stops writing and
	// sends its FIN, so both sides can finalize. Never sent by an older
	// muxocket; older peers treat it as an unknown flag.
	FLG_RST uint8 = 9 //Channel level RST
)

const (
	DEFAULT_MAX_FRAME_DATA_LEN   uint32 = 32 << 10
	DEFAULT_MAX_FRAME_LEN        uint32 = DEFAULT_MAX_FRAME_DATA_LEN + 17
	DEFAULT_MAX_CHANNEL_DATA_LEN uint32 = DEFAULT_MAX_FRAME_DATA_LEN
	DEFAULT_MIN_FRAME_LEN        uint32 = 5
)

const (
	DefaultSystemPacketReadBuffer  int = 4 * 1024 * 1024
	DefaultSystemPacketWriteBuffer int = 4 * 1024 * 1024
)

const MaxBatchFramesInWriter int = 24
const MaxClosedIDs int = 64 // maximum number of recently closed channel IDs to remember (Reliability only). it is to prevent a malicious peer from sending a lot of late frames to exhaust memory.

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
	goAwayRecv           atomic.Bool

	// dialer holds client-side resumption state (nil on the listener side).
	dialer atomic.Pointer[dialer]

	hooksMu    sync.Mutex
	closeHooks []func()

	// Shared ARQ timer: one goroutine/ticker per session scans only the
	// channels that currently have unacknowledged data. Replaces one
	// goroutine + ticker per reliable channel.
	arqOnce sync.Once
	arqMu   sync.Mutex
	arqSet  map[*Channel]struct{}

	// Frames for channels this side hasn't opened yet (guarded by
	// channelsMu). The protocol has no channel-open frame, so the peer may
	// legitimately send before our OpenChannel; these are delivered when the
	// channel is opened instead of being dropped.
	pending      map[uint32]*pendingQueue
	pendingBytes int

	// closedIDs holds recently closed channel IDs (guarded by channelsMu,
	// Reliability only). Late retransmits for a closed channel are dropped
	// instead of stashed, so they can't leak into a later channel with the
	// same label. Cleared for an ID when OpenChannel is called for it again.
	closedIDs map[uint32]time.Time
}

type pendingQueue struct {
	frames  []pendingFrame
	bytes   int
	expires time.Time
}

type pendingFrame struct {
	flag   uint8
	offset uint64
	pBuf   *[]byte
	length uint32
}

type PacketFrame struct {
	DataLength uint32
	Flag       uint8
	ChID       uint32
	Offset     uint64
	Data       []byte
}

type packetReader interface {
	ReadPacket() (pBuf *[]byte, err error)
}

type Config struct {
	MaxFrameDataSize uint32

	// high mtu - low MaxWriteBufferSize | low mtu - high MaxWriteBufferSize
	MaxWriteBufferSize   uint32 //over ip or udp or any protocol with low mtus, we better increase this from default of 32 to 128 or higher
	InitialStreamWindow  uint32
	InitialSessionWindow uint32

	//only applicable to packet based protocols
	SystemPacketReadBuffer  int
	SystemPacketWriteBuffer int

	//DrainChannelAfterClose  bool
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

	// Pending channel behavior: early frames are stashed until the local OpenChannel, or dropped after TTL. Closed channels are remembered for a while to drop late frames instead of stashing them.
	MaxPendingChannels              uint          //per session //default: 4
	MaxPendingEarlyFramesPerSession uint          //default: 8
	MaxPendingEarlyBytesPerSession  uint          // can not be bigger than MaxPendingEarlyFramesPerSession * MaxFrameDataSize, if not set or too big it defaluts to MaxPendingEarlyFramesPerSession * MaxFrameDataSize
	PendingEarlyFramesTTL           time.Duration // how long early frames wait for a local OpenChannel.
	ClosedChannelFrameLingerTTL     time.Duration // how long after late frames for a closed channel are dropped waiting for connection resumption on rebliability on.

	//Close behavior
	LingerOnCloseSession bool          //default false //end a stream transport(conn) gracefully after Close has flushed
	LingerCloseTimeout   time.Duration //default: 5s

	ChannelCloseTimeout time.Duration //default: 4s //how long to wait for a peer to close a channel after we have closed it(send FIN).
}

func DefaultConfig() *Config {
	return &Config{
		// NOTE: this used to be DEFAULT_MAX_FRAME_LEN (32 KiB + 17). The allocator
		// rounds up to the next power of two, so every full-size frame was
		// backed by a 64 KiB slab: ~2x memory for every in-flight/buffered frame.
		MaxFrameDataSize:                DEFAULT_MAX_FRAME_DATA_LEN,
		MaxWriteBufferSize:              32,
		InitialStreamWindow:             DefaultInitialStreamWindow,
		InitialSessionWindow:            DefaultInitialSessionWindow,
		SystemPacketReadBuffer:          DefaultSystemPacketReadBuffer,  // def 4 * 1024 * 1024
		SystemPacketWriteBuffer:         DefaultSystemPacketWriteBuffer, // def 4 * 1024 * 1024
		MaxUnknownChannelErrors:         128,
		KeepAlive:                       true,
		KeepAliveInterval:               5 * time.Second,
		KeepAliveTimeout:                30 * time.Second,
		Reliability:                     false,
		RetransmitTimeout:               150 * time.Millisecond,
		MaxRetransmit:                   8,
		AckInterval:                     10 * time.Millisecond,
		AllowConnectionResumption:       false,
		ConnectionResumeTimeout:         5 * time.Second,
		MaxPendingChannels:              4,
		MaxPendingEarlyFramesPerSession: 8,
		MaxPendingEarlyBytesPerSession:  0, // will be set to MaxPendingEarlyFramesPerSession * MaxFrameDataSize if not set
		PendingEarlyFramesTTL:           3 * time.Second,
		ClosedChannelFrameLingerTTL:     5 * time.Second,
		LingerOnCloseSession:            false,
		LingerCloseTimeout:              3 * time.Second,
		ChannelCloseTimeout:             DefaultChannelCloseTimeout,
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

	if cfg.SystemPacketReadBuffer == 0 {
		cfg.SystemPacketReadBuffer = DefaultSystemPacketReadBuffer
	}

	if cfg.SystemPacketWriteBuffer == 0 {
		cfg.SystemPacketWriteBuffer = DefaultSystemPacketWriteBuffer
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

	if cfg.MaxPendingChannels == 0 {
		cfg.MaxPendingChannels = 4
	}
	if cfg.MaxPendingEarlyFramesPerSession == 0 {
		cfg.MaxPendingEarlyFramesPerSession = 8
	}

	if cfg.MaxPendingEarlyBytesPerSession == 0 {
		cfg.MaxPendingEarlyBytesPerSession = cfg.MaxPendingEarlyFramesPerSession * uint(cfg.MaxFrameDataSize)
	}

	if cfg.MaxPendingEarlyBytesPerSession > cfg.MaxPendingEarlyFramesPerSession*uint(cfg.MaxFrameDataSize) {
		cfg.MaxPendingEarlyBytesPerSession = cfg.MaxPendingEarlyFramesPerSession * uint(cfg.MaxFrameDataSize)
	}

	if cfg.PendingEarlyFramesTTL == 0 {
		cfg.PendingEarlyFramesTTL = 3 * time.Second
	}
	if cfg.ClosedChannelFrameLingerTTL == 0 {
		cfg.ClosedChannelFrameLingerTTL = 5 * time.Second
	}

	if cfg.LingerCloseTimeout == 0 {
		cfg.LingerCloseTimeout = 5 * time.Second
	}

	if cfg.ChannelCloseTimeout == 0 {
		cfg.ChannelCloseTimeout = DefaultChannelCloseTimeout
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
	delete(s.closedIDs, id)
	var frames []pendingFrame
	if q := s.pending[id]; q != nil {
		if time.Now().After(q.expires) {
			s.releasePendingLocked(id, q)
		} else {
			frames = q.frames
			s.pendingBytes -= q.bytes
			delete(s.pending, id)
		}
	}
	if frames != nil {
		// Hold feedMu before publishing the channel: readLoop will block on it
		// for any newer frame, so early frames are delivered first, in order.
		ch.feedMu.Lock()
	}
	s.channels[id] = ch
	s.channelsMu.Unlock()

	if frames != nil {
		s.deliverPending(ch, frames)
		ch.feedMu.Unlock()
	}
	s.channelsMu.Lock() // re-acquired for the deferred Unlock
	return ch, nil
}

func (s *Session) ensureARQ() {
	s.arqOnce.Do(func() {
		s.arqMu.Lock()
		if s.arqSet == nil {
			s.arqSet = make(map[*Channel]struct{})
		}
		s.arqMu.Unlock()
		go s.arqLoop()
	})
}

// arqAdd / arqRemove are called with ch.unackedMu held (lock order:
// unackedMu -> arqMu), which makes the empty-check-then-remove in arqLoop
// atomic with respect to Write registering new frames.
func (s *Session) arqAdd(ch *Channel) {
	s.arqMu.Lock()
	if s.arqSet == nil {
		s.arqSet = make(map[*Channel]struct{})
	}
	s.arqSet[ch] = struct{}{}
	s.arqMu.Unlock()
}

func (s *Session) arqRemove(ch *Channel) {
	s.arqMu.Lock()
	delete(s.arqSet, ch)
	s.arqMu.Unlock()
}

func (s *Session) arqLoop() {
	rto := s.config.RetransmitTimeout
	tick := rto / 2
	if tick < time.Millisecond {
		tick = time.Millisecond
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	var batch []*Channel // reused across ticks
	for {
		select {
		case <-s.die:
			return
		case <-ticker.C:
		}
		// While suspended there is no transport: retransmitting would only
		// burn MaxRetransmit attempts and close healthy channels. Resumption
		// retransmits everything anyway.
		if s.suspended.Load() {
			continue
		}

		batch = batch[:0]
		s.arqMu.Lock()
		for ch := range s.arqSet {
			batch = append(batch, ch)
		}
		s.arqMu.Unlock()

		for i, ch := range batch {
			ch.unackedMu.Lock()
			if len(ch.unacked) == 0 {
				ch.inARQ = false
				s.arqRemove(ch)
				ch.unackedMu.Unlock()
				ch.maybeFinalize()
			} else {
				ch.unackedMu.Unlock()
				ch.checkRetransmissions(rto)
			}
			batch[i] = nil
		}
	}
}

func (s *Session) getChannel(id uint32) *Channel {
	s.channelsMu.RLock()
	ch := s.channels[id]
	s.channelsMu.RUnlock()
	return ch
}

/*
func (s *Session) RemoveChannel(id uint32) {
	s.channelsMu.Lock()
	if _, ok := s.channels[id]; ok {
		delete(s.channels, id)
		s.markClosedLocked(id)
	}
	s.channelsMu.Unlock()
}
*/

// removeChannelIf removes id only if it still maps to ch (a new channel with
// the same label may have been opened since).
func (s *Session) removeChannelIf(id uint32, ch *Channel) {
	s.channelsMu.Lock()
	if s.channels[id] == ch {
		delete(s.channels, id)
		s.markClosedLocked(id)
	}
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

/*
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
*/

func (s *Session) writeControlFrameNonBlocking(f writeFrame) bool {
	if s.isClosed() {
		releaseFrame(&f)
		return false
	}
	select {
	case <-s.die:
		releaseFrame(&f)
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
				releaseFrame(&f)
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

	// If this is a datagram transport (UDP / Raw IP), use the zero-copy packet path
	if pr, ok := c.(packetReader); ok {
		s.datagramReadLoop(c, pr)
		return
	}

	// Otherwise, use the streaming loop (for TCP etc)
	s.streamReadLoop(c)

}

func (s *Session) streamReadLoop(c io.ReadWriteCloser) {
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
				s.channelsMu.Lock()
				ch = s.channels[channelID]
				stashed, late := false, false
				if ch == nil && !s.isClosed() {
					late = s.recentlyClosedLocked(channelID)
					if !late {
						stashed = s.stashLocked(channelID, pendingFrame{flag: FLG_DATA, offset: offset, pBuf: pNewbuf, length: dataLength})
					}
				}
				s.channelsMu.Unlock()
				if stashed {
					continue
				}
				if late {
					// Normal straggler for a channel we just closed: drop it
					// without counting it as a protocol error.
					_ = defaultAllocator.Put(pNewbuf)
					s.creditDiscarded(dataLength)
					// The peer is still writing to a channel we've already
					// finalized: its RST was probably lost. Repeat it.
					s.sendReset(channelID, 0)
					continue
				}
			}
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

			ch.feedMu.Lock()
			if s.config.Reliability {
				ch.feedReliable(offset, pNewbuf, dataLength)
			} else if err := ch.feed(pNewbuf); err != nil {
				_ = defaultAllocator.Put(pNewbuf)
				s.creditDiscarded(dataLength)
			}
			ch.feedMu.Unlock()

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
			ch := s.getChannel(channelID)
			if ch == nil {
				s.channelsMu.Lock()
				if ch = s.channels[channelID]; ch == nil && !s.isClosed() {
					if !s.recentlyClosedLocked(channelID) {
						s.stashLocked(channelID, pendingFrame{flag: FLG_FIN, offset: offset})
					}
				}
				s.channelsMu.Unlock()
			}
			if ch != nil {
				ch.feedMu.Lock()
				if s.config.Reliability {
					ch.handleFinReliable(offset)
				} else {
					ch.remoteClose()
				}
				ch.feedMu.Unlock()
			}
		case FLG_RST:
			if dataLength != 0 {
				s.handleDisconnect(c)
				return
			}
			ch := s.getChannel(channelID)
			if ch == nil {
				s.channelsMu.Lock()
				if ch = s.channels[channelID]; ch == nil && !s.isClosed() {
					if !s.recentlyClosedLocked(channelID) {
						s.stashLocked(channelID, pendingFrame{flag: FLG_RST, offset: offset})
					}
				}
				s.channelsMu.Unlock()
			}
			if ch != nil {
				ch.peerReset()
			}

		case FLG_PING:
			// Never block the reader on a full control queue: a peer that
			// isn't reading would otherwise stall our whole receive path.
			select {
			case s.writer.ctrlQueue <- writeFrame{flag: FLG_PONG}:
			default:
			}

		case FLG_GOAWAY:
			s.goAwayRecv.Store(true)
			s.Close()
			return

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

func (s *Session) datagramReadLoop(c io.ReadWriteCloser, pr packetReader) {
	for {
		if s.isClosed() {
			return
		}

		pBuf, err := pr.ReadPacket()
		if err != nil {
			s.handleDisconnect(c)
			return
		}
		s.rxActivity.Store(true)

		data := *pBuf
		offsetInPacket := 0

		// A single UDP datagram may contain 1 or more frames
		for offsetInPacket+17 <= len(data) {
			hdr := data[offsetInPacket : offsetInPacket+17]
			dataLength := binary.BigEndian.Uint32(hdr[0:4])
			flag := hdr[4]
			channelID := binary.BigEndian.Uint32(hdr[5:9])
			offset := binary.BigEndian.Uint64(hdr[9:17])

			frameEnd := offsetInPacket + 17 + int(dataLength)
			if frameEnd > len(data) {
				// Malformed or truncated packet
				break
			}

			switch flag {
			case FLG_DATA:
				if dataLength == 0 {
					offsetInPacket = frameEnd
					continue
				}

				payload := data[offsetInPacket+17 : frameEnd]

				ch := s.getChannel(channelID)
				if ch == nil {
					s.creditDiscarded(dataLength)
					offsetInPacket = frameEnd
					continue
				}

				// Direct Handoff Condition:
				// If this DATA frame is the ONLY frame in the datagram, hand off pBuf directly!
				if offsetInPacket == 0 && frameEnd == len(data) {
					ch.feedMu.Lock()
					if s.config.Reliability {
						ch.feedReliablePayload(offset, payload, pBuf, dataLength)
					} else {
						_ = ch.feedPayload(payload, pBuf)
					}
					ch.feedMu.Unlock()
					pBuf = nil // Ownership transferred to channel; do not free here!
				} else {
					// Fallback: If multiple frames were bundled in one datagram, allocate a copy
					// so multiple channels don't race on the same backing slab.
					pCopy := defaultAllocator.Get(int(dataLength))
					copy(*pCopy, payload)
					ch.feedMu.Lock()
					if s.config.Reliability {
						ch.feedReliable(offset, pCopy, dataLength)
					} else {
						_ = ch.feed(pCopy)
					}
					ch.feedMu.Unlock()
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
				ch := s.getChannel(channelID)
				if ch == nil {
					s.channelsMu.Lock()
					if ch = s.channels[channelID]; ch == nil && !s.isClosed() {
						if !s.recentlyClosedLocked(channelID) {
							s.stashLocked(channelID, pendingFrame{flag: FLG_FIN, offset: offset})
						}
					}
					s.channelsMu.Unlock()
				}
				if ch != nil {
					ch.feedMu.Lock()
					if s.config.Reliability {
						ch.handleFinReliable(offset)
					} else {
						ch.remoteClose()
					}
					ch.feedMu.Unlock()
				}

			case FLG_RST:
				ch := s.getChannel(channelID)
				if ch == nil {
					s.channelsMu.Lock()
					if ch = s.channels[channelID]; ch == nil && !s.isClosed() {
						if !s.recentlyClosedLocked(channelID) {
							s.stashLocked(channelID, pendingFrame{flag: FLG_RST, offset: offset})
						}
					}
					s.channelsMu.Unlock()
				}
				if ch != nil {
					ch.peerReset()
				}
			case FLG_PING:
				// Never block the reader on a full control queue: a peer that
				// isn't reading would otherwise stall our whole receive path.
				select {
				case s.writer.ctrlQueue <- writeFrame{flag: FLG_PONG}:
				default:
				}

			case FLG_GOAWAY:
				s.goAwayRecv.Store(true)
				s.Close()
				return

			case FLG_PONG, FLG_NOOP:
				// liveness only (rxActivity already recorded)
			default:
				// Unknown flag: we can't know whether a payload follows, so the
				// framing is lost.
				s.handleDisconnect(c)
				return
			}

			offsetInPacket = frameEnd

		}

		// If pBuf was not handed off to a channel (e.g., pure ACK/UPD datagram or discarded frame),
		// recycle it back to the allocator immediately.
		if pBuf != nil {
			_ = defaultAllocator.Put(pBuf)
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
			s.pruneExpiredPending()
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
		// Async: we may be on the writer goroutine, and Close waits for it.
		go s.Close()
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

/*
func (s *Session) alterID(newID string) string {
	s.id = newID
	return s.id
}
*/

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

// releasePendingLocked frees a stashed queue's buffers and returns their
// flow-control credit (channelsMu held).
func (s *Session) releasePendingLocked(id uint32, q *pendingQueue) {
	for _, f := range q.frames {
		if f.pBuf != nil {
			_ = defaultAllocator.Put(f.pBuf)
		}
		s.creditDiscarded(f.length)
	}
	s.pendingBytes -= q.bytes
	delete(s.pending, id)
}

// pruneLocked drops expired stash queues and closed-ID markers (channelsMu held).
func (s *Session) pruneLocked(now time.Time) {
	for id, q := range s.pending {
		if now.After(q.expires) {
			s.releasePendingLocked(id, q)
		}
	}
	for id, t := range s.closedIDs {
		if now.After(t) {
			delete(s.closedIDs, id)
		}
	}
}

// markClosedLocked records id as recently closed and discards anything
// stashed for it (channelsMu held).
func (s *Session) markClosedLocked(id uint32) {
	if q := s.pending[id]; q != nil {
		s.releasePendingLocked(id, q)
	}
	// Only reliable sessions get stragglers after both FINs (ARQ
	// retransmits), and only there is dropping lossless: the peer resends
	// anything a quick legitimate re-open loses. Without Reliability on an
	// ordered transport the FIN is the channel's last frame, so nothing can
	// arrive late, and dropping would lose real data from a re-open.
	if !s.config.Reliability {
		return
	}
	if s.closedIDs == nil {
		s.closedIDs = make(map[uint32]time.Time)
	}
	now := time.Now()
	if len(s.closedIDs) >= MaxClosedIDs {
		s.pruneLocked(now)
		if len(s.closedIDs) >= MaxClosedIDs {
			// Evict the oldest entry so the most recently closed channel is always tracked
			var oldestID uint32
			var oldestTime time.Time
			first := true
			for k, exp := range s.closedIDs {
				if first || exp.Before(oldestTime) {
					oldestID = k
					oldestTime = exp
					first = false
				}
			}
			delete(s.closedIDs, oldestID)
		}
	}
	s.closedIDs[id] = now.Add(s.config.ClosedChannelFrameLingerTTL)
}

// recentlyClosedLocked reports whether id was closed within closedLinger.
func (s *Session) recentlyClosedLocked(id uint32) bool {
	t, ok := s.closedIDs[id]
	if !ok {
		return false
	}
	if time.Now().After(t) {
		delete(s.closedIDs, id)
		return false
	}
	return true
}

// stashLocked keeps an early frame (channelsMu held). Returns false if the
// limits are exceeded and the frame must be dropped.
func (s *Session) stashLocked(id uint32, f pendingFrame) bool {
	if s.recentlyClosedLocked(id) {
		return false
	}
	if s.pending == nil {
		s.pending = make(map[uint32]*pendingQueue)
	}
	now := time.Now()
	s.pruneLocked(now)
	q := s.pending[id]
	if q == nil && len(s.pending) >= int(s.config.MaxPendingChannels) {
		return false
	}

	if s.pendingBytes+int(f.length) > int(s.config.MaxPendingEarlyBytesPerSession) {
		return false
	}

	if q != nil && len(q.frames) >= int(s.config.MaxPendingEarlyFramesPerSession) {
		return false
	}

	if q == nil {
		q = &pendingQueue{expires: now.Add(s.config.PendingEarlyFramesTTL)}
		s.pending[id] = q
	}
	q.frames = append(q.frames, f)
	q.bytes += int(f.length)
	s.pendingBytes += int(f.length)
	return true
}

func (s *Session) deliverPending(ch *Channel, frames []pendingFrame) {
	for _, f := range frames {
		switch f.flag {
		case FLG_DATA:
			if s.config.Reliability {
				ch.feedReliable(f.offset, f.pBuf, f.length)
			} else if err := ch.feed(f.pBuf); err != nil {
				_ = defaultAllocator.Put(f.pBuf)
				s.creditDiscarded(f.length)
			}
		case FLG_FIN:
			if s.config.Reliability {
				ch.handleFinReliable(f.offset)
			} else {
				ch.remoteClose()
			}
		case FLG_RST:
			ch.peerReset()
		}
	}
}

// Done is closed when the session is closed.
func (s *Session) Done() <-chan struct{} { return s.die }

// IsClosed reports whether the session has been closed.
func (s *Session) IsClosed() bool { return s.isClosed() }

// RemoteAddr returns the peer address of the current transport, if known.
func (s *Session) RemoteAddr() net.Addr {
	if c, ok := s.getConn().(interface{ RemoteAddr() net.Addr }); ok {
		return c.RemoteAddr()
	}
	return nil
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
		for _, q := range s.pending {
			for _, f := range q.frames {
				if f.pBuf != nil {
					_ = defaultAllocator.Put(f.pBuf)
				}
			}
		}
		s.pending = nil
		s.closedIDs = nil
		s.pendingBytes = 0
		s.channelsMu.Unlock()

		s.arqMu.Lock()
		s.arqSet = nil
		s.arqMu.Unlock()

		graceful := s.goAwayRecv.Load()
		for _, ch := range activeChannels {
			if graceful {
				ch.peerGone()
			} else {
				ch.localClose()
			}
		}

		s.writer.Close()
		// Let the writer flush queued frames + GOAWAY (bounded).
		select {
		case <-s.writer.exited:
		case <-time.After(2 * gracefulFlushTimeout):
		}

		s.connMu.Lock()
		if s.conn != nil {
			if s.config.LingerOnCloseSession {
				lingerClose(s.conn, s.config.LingerCloseTimeout)
			} else {
				s.conn.Close()
			}
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

// lingerClose ends a stream transport gracefully after Close has flushed
// its last frames and GOAWAY.
//
// Closing a socket while unread bytes sit in its receive buffer makes the
// kernel send a TCP RST instead of a FIN, and an RST makes the peer's
// kernel discard data it has received but not yet handed to the
// application. At the end of a session the peer is usually still sending
// small frames (window updates, its own FIN or GOAWAY), so a plain Close
// could destroy the tail of the data we just flushed. This happens more
// often over TLS, where the receiver has more unread data queued.
//
// So, like nginx's lingering_close: half-close (TLS close_notify + TCP FIN
// via CloseWrite), read and discard until the peer closes too or
// lingerTimeout passes, then close. Transports without CloseWrite
// (datagram sub-connections) are closed right away. This is only used for
// a deliberate Close; a broken transport is still dropped immediately so
// resumption can start.
func lingerClose(c io.ReadWriteCloser, timeout time.Duration) {
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		_ = c.Close()
		return
	}
	type deadliner interface {
		SetReadDeadline(time.Time) error
		SetWriteDeadline(time.Time) error
	}
	d, hasDeadline := c.(deadliner)
	if hasDeadline {
		_ = d.SetWriteDeadline(time.Now().Add(timeout))
	}
	if err := cw.CloseWrite(); err != nil {
		_ = c.Close()
		return
	}
	go func() {
		defer c.Close()
		if hasDeadline {
			_ = d.SetReadDeadline(time.Now().Add(timeout))
		} else {
			t := time.AfterFunc(timeout, func() { _ = c.Close() })
			defer t.Stop()
		}
		buf := make([]byte, 2048)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
}

// sendReset queues an FLG_RST for chID without ever blocking the caller (it
// may be the readLoop). Dropped if the control queue is full: RSTs are
// repeated whenever more data arrives for the channel.
func (s *Session) sendReset(chID uint32, offset uint64) {
	if s.isClosed() {
		return
	}
	select {
	case s.writer.ctrlQueue <- writeFrame{flag: FLG_RST, chID: chID, offset: offset}:
	default:
	}
}

func (s *Session) pruneExpiredPending() {
	s.channelsMu.Lock()
	if len(s.pending) > 0 || len(s.closedIDs) > 0 {
		s.pruneLocked(time.Now())
	}
	s.channelsMu.Unlock()
}
