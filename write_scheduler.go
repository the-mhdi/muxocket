package muxocket

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type writeFrame struct {
	pBuf   *[]byte
	length uint32
	chID   uint32
	flag   uint8
	offset uint64 // 64-bit stream offset

	// ack, when set, owns pBuf through a reference count (ARQ frames). The
	// writer releases its reference after the bytes hit the wire instead of
	// returning pBuf to the allocator directly.
	ack *unackedFrame
	// ackCh marks a coalesced FLG_ACK: the cumulative offset is read from the
	// channel at flush time, so N received frames produce at most one queued
	// ACK per channel instead of N frames (or N goroutines when ctrlQueue is
	// full).
	ackCh *Channel
}

// unackedFrame is shared between the channel's retransmission queue and any
// number of in-flight writeFrames. refs counts all holders; the slab buffer is
// returned to the allocator only when the last one lets go. Previously onAck /
// cleanupReliability could recycle a buffer that was still queued in the
// writer (e.g. a retransmission, or the first send during close), so recycled
// memory belonging to someone else was put on the wire.
type unackedFrame struct {
	pBuf        *[]byte
	offset      uint64
	length      uint32
	sentAt      time.Time
	retransmits int
	refs        atomic.Int32
}

func (f *unackedFrame) retain() { f.refs.Add(1) }

func (f *unackedFrame) release() {
	if f.refs.Add(-1) == 0 && f.pBuf != nil {
		_ = defaultAllocator.Put(f.pBuf)
	}
}

type reorderFrame struct {
	pBuf   *[]byte
	offset uint64
	length uint32
}

// datagramWriter is implemented by message-oriented transports (UDP/IP). The
// scheduler packs whole frames into datagrams no larger than maxDatagramSize()
// and never splits a frame across datagrams, so a lost datagram loses whole
// frames (recoverable by ARQ) instead of desynchronising the byte stream.
type datagramWriter interface {
	maxDatagramSize() int
}

type writeScheduler struct {
	session   *Session
	connMu    sync.RWMutex
	conn      io.Writer
	connReady chan struct{} // signalled when conn changes
	writes    chan writeFrame
	ctrlQueue chan writeFrame
	closed    atomic.Bool
	die       chan struct{}

	dgram []byte // scratch buffer for datagram packing
}

func newWriteScheduler(s *Session, conn io.Writer, queueDepth int) *writeScheduler {
	if queueDepth <= 0 {
		queueDepth = 128
	}

	ws := &writeScheduler{
		session:   s,
		conn:      conn,
		connReady: make(chan struct{}, 1),
		writes:    make(chan writeFrame, queueDepth),
		ctrlQueue: make(chan writeFrame, 64),
		die:       make(chan struct{}),
	}

	go ws.writeLoop()
	return ws
}

func (ws *writeScheduler) alterConn(conn io.Writer) {
	ws.connMu.Lock()
	ws.conn = conn
	ws.connMu.Unlock()
	select {
	case ws.connReady <- struct{}{}:
	default:
	}
}

func (ws *writeScheduler) currentConn() io.Writer {
	ws.connMu.RLock()
	defer ws.connMu.RUnlock()
	return ws.conn
}

func releaseFrame(f *writeFrame) {
	if f.ack != nil {
		f.ack.release()
	} else if f.pBuf != nil {
		_ = defaultAllocator.Put(f.pBuf)
	}
	f.pBuf = nil
	f.ack = nil
	f.ackCh = nil
}

func (ws *writeScheduler) writeLoop() {
	var (
		hdrs      [maxBatchFrames][17]byte
		rawBufs   [maxBatchFrames * 2][]byte
		frameRefs [maxBatchFrames]writeFrame
	)

	releaseBatch := func(n int) {
		for i := 0; i < n; i++ {
			releaseFrame(&frameRefs[i])
		}
	}

	for {
		var firstFrame writeFrame

		select {
		case <-ws.die:
			ws.drainAndCleanup()
			return
		case cf := <-ws.ctrlQueue:
			firstFrame = cf
		default:
			select {
			case <-ws.die:
				ws.drainAndCleanup()
				return
			case cf := <-ws.ctrlQueue:
				firstFrame = cf
			case f := <-ws.writes:
				firstFrame = f
			}
		}

		frameRefs[0] = firstFrame
		batchCount := 1

		for batchCount < maxBatchFrames {
			select {
			case cf := <-ws.ctrlQueue:
				frameRefs[batchCount] = cf
				batchCount++
			case f := <-ws.writes:
				frameRefs[batchCount] = f
				batchCount++
			default:
				goto FLUSH
			}
		}

	FLUSH:
		// While suspended (conn == nil) wait for a resumed transport instead of
		// silently dropping the batch. The old code `continue`d here, dropping
		// frames and skipping the buffer release.
		var writer io.Writer
		for {
			writer = ws.currentConn()
			if writer != nil {
				break
			}
			select {
			case <-ws.die:
				releaseBatch(batchCount)
				ws.drainAndCleanup()
				return
			case <-ws.connReady:
			}
		}

		// Resolve coalesced ACKs as late as possible so they carry the newest
		// cumulative offset.
		for i := 0; i < batchCount; i++ {
			if ch := frameRefs[i].ackCh; ch != nil {
				ch.ackPending.Store(false)
				frameRefs[i].offset = ch.ackOffset.Load()
			}
		}

		var err error
		if dw, ok := writer.(datagramWriter); ok {
			err = ws.flushDatagrams(writer, frameRefs[:batchCount], dw.maxDatagramSize())
		} else {
			bufSlice := rawBufs[:0]
			for i := 0; i < batchCount; i++ {
				f := &frameRefs[i]
				h := &hdrs[i]
				putHeader(h, f)
				bufSlice = append(bufSlice, h[:17])
				if f.length > 0 && f.pBuf != nil {
					bufSlice = append(bufSlice, (*f.pBuf)[:f.length])
				}
			}
			netBuf := net.Buffers(bufSlice)
			_, err = netBuf.WriteTo(writer)
			// net.Buffers.WriteTo consumes the slice; clear stale references so
			// the backing array doesn't pin payload slabs between batches.
			for i := range rawBufs {
				rawBufs[i] = nil
			}
		}

		releaseBatch(batchCount)

		if err != nil {
			// Don't exit: the old code returned here, so after a successful
			// resumption the session had no writer and every Write blocked
			// forever. Report the failure and wait for the next transport.
			if rwc, ok := writer.(io.ReadWriteCloser); ok {
				ws.session.handleDisconnect(rwc)
			} else {
				ws.session.handleDisconnect(nil)
			}
			if ws.session.isClosed() {
				ws.drainAndCleanup()
				return
			}
			// If handleDisconnect ignored us (stale) but conn is still the
			// failing one, avoid a hot loop.
			if ws.currentConn() == writer {
				ws.alterConnIfSame(writer)
			}
		}
	}
}

// alterConnIfSame clears the writer's conn if it is still w (used when a
// write failed but the session-level conn bookkeeping didn't change it).
func (ws *writeScheduler) alterConnIfSame(w io.Writer) {
	ws.connMu.Lock()
	if ws.conn == w {
		ws.conn = nil
	}
	ws.connMu.Unlock()
}

func putHeader(h *[17]byte, f *writeFrame) {
	binary.BigEndian.PutUint32(h[0:4], f.length)
	h[4] = f.flag
	binary.BigEndian.PutUint32(h[5:9], f.chID)
	binary.BigEndian.PutUint64(h[9:17], f.offset)
}

func (ws *writeScheduler) flushDatagrams(w io.Writer, frames []writeFrame, max int) error {
	if max < 17 {
		max = 17
	}
	if cap(ws.dgram) < max {
		ws.dgram = make([]byte, 0, max)
	}
	buf := ws.dgram[:0]
	var h [17]byte

	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		_, err := w.Write(buf)
		buf = buf[:0]
		return err
	}

	for i := range frames {
		f := &frames[i]
		var payload []byte
		if f.length > 0 && f.pBuf != nil {
			payload = (*f.pBuf)[:f.length]
		}
		need := 17 + len(payload)
		if len(buf)+need > max {
			if err := flush(); err != nil {
				return err
			}
		}
		putHeader(&h, f)
		if need > max {
			// Oversized frame (misconfiguration): send it on its own.
			tmp := make([]byte, 0, need)
			tmp = append(append(tmp, h[:]...), payload...)
			if _, err := w.Write(tmp); err != nil {
				return err
			}
			continue
		}
		buf = append(buf, h[:]...)
		buf = append(buf, payload...)
	}
	return flush()
}

func (ws *writeScheduler) drainAndCleanup() {
	for {
		select {
		case f := <-ws.writes:
			releaseFrame(&f)
		case cf := <-ws.ctrlQueue:
			releaseFrame(&cf)
		default:
			return
		}
	}
}

func (ws *writeScheduler) Close() {
	if ws.closed.CompareAndSwap(false, true) {
		close(ws.die)
	}
}
