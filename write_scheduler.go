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
	offset uint64

	ack         *unackedFrame
	ackCh       *Channel
	streamFlow  *StreamFlow
	sessionFlow *SessionFlow
}

type unackedFrame struct {
	pBuf        *[]byte
	offset      uint64
	length      uint32
	sentAt      time.Time
	retransmits int
	refs        atomic.Int32
	fin         bool
}

func (f *unackedFrame) end() uint64 {
	if f.fin {
		return f.offset + 1
	}
	return f.offset + uint64(f.length)
}

func (f *unackedFrame) retain() { f.refs.Add(1) }

var unackedPool = sync.Pool{New: func() any { return new(unackedFrame) }}

func newUnackedFrame(pBuf *[]byte, offset uint64, length uint32, fin bool, refs int32) *unackedFrame {
	f := unackedPool.Get().(*unackedFrame)
	f.pBuf = pBuf
	f.offset = offset
	f.length = length
	f.fin = fin
	f.retransmits = 0
	f.sentAt = time.Now()
	f.refs.Store(refs)
	return f
}

func (f *unackedFrame) release() {
	if f.refs.Add(-1) != 0 {
		return
	}
	if f.pBuf != nil {
		_ = defaultAllocator.Put(f.pBuf)
	}
	*f = unackedFrame{}
	unackedPool.Put(f)
}

type reorderFrame struct {
	payload []byte
	head    *[]byte
	offset  uint64
	length  uint32
}

type datagramWriter interface {
	maxDatagramSize() int
}

type writeScheduler struct {
	session   *Session
	connMu    sync.RWMutex
	conn      io.Writer
	connReady chan struct{}
	writes    chan writeFrame
	ctrlQueue chan writeFrame
	closed    atomic.Bool
	die       chan struct{}
	exited    chan struct{}

	dgram []byte
}

func newWriteScheduler(s *Session, conn io.Writer, queueDepth int) *writeScheduler {
	if queueDepth <= 0 {
		queueDepth = 128
	}
	ctrlDepth := queueDepth
	if ctrlDepth < 128 {
		ctrlDepth = 128
	}

	ws := &writeScheduler{
		session:   s,
		conn:      conn,
		connReady: make(chan struct{}, 1),
		writes:    make(chan writeFrame, queueDepth),
		ctrlQueue: make(chan writeFrame, ctrlDepth),
		die:       make(chan struct{}),
		exited:    make(chan struct{}),
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
	f.streamFlow = nil
	f.sessionFlow = nil
}

func (ws *writeScheduler) compactAndResolveControlFrames(b *batchState, n int) int {
	outIdx := 0

	for i := 0; i < n; i++ {
		f := &b.frames[i]

		if ch := f.ackCh; ch != nil {
			ch.ackPending.Store(false)
			f.offset = ch.ackOffset.Load()
		}

		if sf := f.streamFlow; sf != nil {
			delta := sf.unflushed.Swap(0)
			sf.updPending.Store(false)
			if delta <= 0 {
				releaseFrame(f)
				*f = writeFrame{}
				continue
			}
			f.length = uint32(delta)
		}

		if sf := f.sessionFlow; sf != nil {
			delta := sf.unflushed.Swap(0)
			sf.updPending.Store(false)
			if delta <= 0 {
				releaseFrame(f)
				*f = writeFrame{}
				continue
			}
			f.length = uint32(delta)
		}

		merged := false
		if f.flag == FLG_ACK {
			for j := 0; j < outIdx; j++ {
				if b.frames[j].flag == FLG_ACK && b.frames[j].chID == f.chID {
					if f.offset > b.frames[j].offset {
						b.frames[j].offset = f.offset
					}
					merged = true
					break
				}
			}
		} else if f.flag == FLG_UPD {
			for j := 0; j < outIdx; j++ {
				if b.frames[j].flag == FLG_UPD && b.frames[j].chID == f.chID {
					b.frames[j].length += f.length
					merged = true
					break
				}
			}
		}

		if merged {
			releaseFrame(f)
			*f = writeFrame{}
			continue
		}

		if outIdx != i {
			b.frames[outIdx] = *f
			*f = writeFrame{}
		}
		outIdx++
	}
	return outIdx
}

type batchState struct {
	hdrs   [MaxBatchFramesInWriter + 1][17]byte
	raw    [(MaxBatchFramesInWriter + 1) * 2][]byte
	frames [MaxBatchFramesInWriter + 1]writeFrame
	bufs   net.Buffers
}

func (ws *writeScheduler) writeBatch(b *batchState, writer io.Writer, n int) error {
	outCount := ws.compactAndResolveControlFrames(b, n)
	if outCount == 0 {
		return nil
	}
	frames := b.frames[:outCount]

	defer func() {
		for i := 0; i < outCount; i++ {
			releaseFrame(&frames[i])
			frames[i] = writeFrame{}
		}
	}()

	var err error
	if dw, ok := writer.(datagramWriter); ok {
		err = ws.flushDatagrams(writer, frames, dw.maxDatagramSize())
	} else {
		bufSlice := b.raw[:0]
		for i := range frames {
			f := &frames[i]
			h := &b.hdrs[i]
			putHeader(h, f)
			bufSlice = append(bufSlice, h[:17])
			if f.length > 0 && f.pBuf != nil {
				bufSlice = append(bufSlice, (*f.pBuf)[:f.length])
			}
		}
		b.bufs = bufSlice
		_, err = b.bufs.WriteTo(writer)
		b.bufs = nil
		for i := range b.raw {
			b.raw[i] = nil
		}
	}
	return err
}

func (ws *writeScheduler) collect(b *batchState, start int) int {
	n := start
	for n < MaxBatchFramesInWriter {
		select {
		case cf := <-ws.ctrlQueue:
			b.frames[n] = cf
		case f := <-ws.writes:
			b.frames[n] = f
		default:
			return n
		}
		n++
	}
	return n
}

func (ws *writeScheduler) writeLoop() {
	defer close(ws.exited)
	b := new(batchState)

	for {
		var firstFrame writeFrame

		select {
		case <-ws.die:
			ws.finalFlush(b)
			return
		case cf := <-ws.ctrlQueue:
			firstFrame = cf
		default:
			select {
			case <-ws.die:
				ws.finalFlush(b)
				return
			case cf := <-ws.ctrlQueue:
				firstFrame = cf
			case f := <-ws.writes:
				firstFrame = f
			}
		}

		b.frames[0] = firstFrame
		batchCount := ws.collect(b, 1)

		var writer io.Writer
		for {
			writer = ws.currentConn()
			if writer != nil {
				break
			}
			select {
			case <-ws.die:
				for i := 0; i < batchCount; i++ {
					releaseFrame(&b.frames[i])
					b.frames[i] = writeFrame{}
				}
				ws.drainAndCleanup()
				return
			case <-ws.connReady:
			}
		}

		if err := ws.writeBatch(b, writer, batchCount); err != nil {
			if rwc, ok := writer.(io.ReadWriteCloser); ok {
				ws.session.handleDisconnect(rwc)
			} else {
				ws.session.handleDisconnect(nil)
			}
			if ws.currentConn() == writer {
				ws.alterConnIfSame(writer)
			}
		}
	}
}

const gracefulFlushTimeout = 500 * time.Millisecond

func (ws *writeScheduler) finalFlush(b *batchState) {
	defer ws.drainAndCleanup()
	writer := ws.currentConn()
	if writer == nil {
		return
	}
	if d, ok := writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = d.SetWriteDeadline(time.Now().Add(gracefulFlushTimeout))
	}
	deadline := time.Now().Add(gracefulFlushTimeout)
	for time.Now().Before(deadline) {
		n := ws.collect(b, 0)
		if n == 0 {
			break
		}
		if err := ws.writeBatch(b, writer, n); err != nil {
			return
		}
	}
	if ws.session.goAwayRecv.Load() {
		return
	}
	b.frames[0] = writeFrame{flag: FLG_GOAWAY}
	_ = ws.writeBatch(b, writer, 1)
}

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
