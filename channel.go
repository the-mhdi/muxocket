package muxocket

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrChannelReset = errors.New("channel reset by peer")
)

const DefaultChannelCloseTimeout = 4 * time.Second

const maxRetainedUnacked = 1024

const (
	stateIdle    uint32 = 0
	stateWaiting uint32 = 1
)

var reorderPool = sync.Pool{
	New: func() any { return new(reorderFrame) },
}

type Channel struct {
	id      uint32
	session *Session

	ring   RingBuffer
	notify chan struct{}

	waitState atomic.Uint32
	readMu    sync.Mutex
	writeMu   sync.Mutex

	flow *StreamFlow

	closeOnce sync.Once
	closeChan chan struct{}
	drainOnce sync.Once
	closed    atomic.Bool
	readDone  atomic.Bool
	drainable atomic.Bool

	writeClosed  atomic.Bool
	finQueued    atomic.Bool
	resetByPeer  atomic.Bool
	lastRst      atomic.Int64
	closeTimer   atomic.Pointer[time.Timer]
	writeOnce    sync.Once
	finalizeOnce sync.Once
	done         chan struct{}
	feedMu       sync.Mutex

	// Reliability Engine (ARQ & In-Order Reassembly)
	writeOffset uint64
	readOffset  uint64
	unackedMu   sync.Mutex
	unacked     []*unackedFrame
	reorderMu   sync.Mutex
	reorderMap  map[uint64]*reorderFrame
	finOffset   uint64
	hasFin      bool
	inARQ       bool

	// Coalesced ACK state
	ackOffset      atomic.Uint64
	ackPending     atomic.Bool
	ackTimer       atomic.Pointer[time.Timer]
	inOrderPackets atomic.Uint32
}

func (c *Channel) maxReorderBytes() uint64 {
	return uint64(c.session.config.InitialStreamWindow) * 2
}

func newChannel(id uint32, session *Session) *Channel {
	ch := &Channel{
		id:         id,
		session:    session,
		ring:       NewBufferRing(8),
		notify:     make(chan struct{}, 1),
		closeChan:  make(chan struct{}),
		done:       make(chan struct{}),
		reorderMap: make(map[uint64]*reorderFrame),
	}
	ch.closed.Store(false)
	ch.flow = NewStreamFlow(id, int32(session.config.InitialStreamWindow), ch, session)

	if session.config.Reliability {
		session.ensureARQ()
	}

	return ch
}

func (c *Channel) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.closed.Load() || c.writeClosed.Load() || c.session.isClosed() {
		return 0, c.writeErr()
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed.Load() {
		return 0, c.writeErr()
	}

	maxChunk := int(c.session.config.MaxFrameDataSize)
	totalSent := 0

	for len(b) > 0 {
		desired := len(b)
		if desired > maxChunk {
			desired = maxChunk
		}

		sz, err := c.flow.AcquireCredits(int32(desired))
		if err != nil {
			if err == io.ErrClosedPipe {
				err = c.writeErr()
			}
			return totalSent, err
		}

		pBuf := defaultAllocator.Get(int(sz))
		copy(*pBuf, b[:sz])
		if err := c.queueDataLocked(pBuf, sz); err != nil {
			return totalSent, err
		}

		totalSent += int(sz)
		b = b[sz:]
	}

	return totalSent, nil
}

func (c *Channel) queueDataLocked(pBuf *[]byte, sz int32) error {
	currOffset := atomic.AddUint64(&c.writeOffset, uint64(sz)) - uint64(sz)

	frame := writeFrame{
		flag:   FLG_DATA,
		chID:   c.id,
		pBuf:   pBuf,
		length: uint32(sz),
		offset: currOffset,
	}

	if c.session.config.Reliability {
		uf := newUnackedFrame(pBuf, currOffset, uint32(sz), false, 2)
		frame.ack = uf
		c.unackedMu.Lock()
		c.unacked = append(c.unacked, uf)
		if !c.inARQ {
			c.inARQ = true
			c.session.arqAdd(c)
		}
		c.unackedMu.Unlock()
	}

	if err := c.session.writeDataFrame(frame); err != nil {
		if frame.ack != nil {
			frame.ack.release()
		} else {
			_ = defaultAllocator.Put(pBuf)
		}
		c.flow.Refund(sz)
		return err
	}
	return nil
}

func (c *Channel) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.readAborted() {
		return 0, io.ErrClosedPipe
	}

	c.readMu.Lock()
	defer func() {
		c.readMu.Unlock()
		if c.readAborted() {
			c.tryDrainRing()
		}
	}()

	totalRead := 0
	sawDone := false

	for {
		for len(b) > 0 {
			n, drainedBuf := c.ring.PartialRead(b)
			if drainedBuf != nil {
				defaultAllocator.Put(drainedBuf)
			}

			if n > 0 {
				totalRead += n
				b = b[n:]
				continue
			}
			break
		}

		if totalRead > 0 {
			c.flow.OnRead(totalRead)
			return totalRead, nil
		}

		if c.readAborted() {
			return 0, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			if sawDone {
				c.ring.Close()
				return 0, io.EOF
			}
			sawDone = true
			continue
		}

		c.waitState.Store(stateWaiting)

		n, drainedBuf := c.ring.PartialRead(b)
		if drainedBuf != nil {
			defaultAllocator.Put(drainedBuf)
		}
		if n > 0 {
			c.waitState.Store(stateIdle)
			select {
			case <-c.notify:
			default:
			}

			totalRead += n
			b = b[n:]
			for len(b) > 0 {
				n2, d2 := c.ring.PartialRead(b)
				if d2 != nil {
					defaultAllocator.Put(d2)
				}
				if n2 > 0 {
					totalRead += n2
					b = b[n2:]
					continue
				}
				break
			}
			c.flow.OnRead(totalRead)
			return totalRead, nil
		}

		if c.readAborted() {
			c.waitState.Store(stateIdle)
			return 0, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			c.waitState.Store(stateIdle)
			if sawDone {
				c.ring.Close()
				return 0, io.EOF
			}
			sawDone = true
			continue
		}

		select {
		case <-c.notify:
		case <-c.closeChan:
			return 0, io.ErrClosedPipe
		}
		c.waitState.Store(stateIdle)
	}
}

var (
	_ io.ReaderFrom = (*Channel)(nil)
	_ io.WriterTo   = (*Channel)(nil)
)

func (c *Channel) ReadFrom(r io.Reader) (int64, error) {
	if c.closed.Load() || c.writeClosed.Load() || c.session.isClosed() {
		return 0, c.writeErr()
	}
	maxChunk := int(c.session.config.MaxFrameDataSize)
	var total int64
	var spare *[]byte
	defer func() {
		if spare != nil {
			_ = defaultAllocator.Put(spare)
		}
	}()

	for {
		pBuf := spare
		spare = nil
		if pBuf == nil {
			pBuf = defaultAllocator.Get(maxChunk)
		} else {
			*pBuf = (*pBuf)[:maxChunk]
		}

		n, rerr := r.Read(*pBuf)
		if n > 0 {
			sent, keep, err := c.sendFromRead(pBuf, n)
			total += int64(sent)
			if keep {
				spare = pBuf
			}
			if err != nil {
				return total, err
			}
		} else {
			spare = pBuf
		}

		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

func (c *Channel) sendFromRead(pBuf *[]byte, n int) (sent int, keep bool, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() || c.writeClosed.Load() {
		return 0, true, c.writeErr()
	}

	maxChunk := int(c.session.config.MaxFrameDataSize)
	copySmall := c.session.config.Reliability && n <= maxChunk/2
	data := (*pBuf)[:n]
	keep = true

	for sent < n {
		sz, err := c.flow.AcquireCredits(int32(n - sent))
		if err != nil {
			return sent, keep, err
		}
		var fb *[]byte
		if sent == 0 && int(sz) == n && !copySmall {
			*pBuf = data
			fb, keep = pBuf, false
		} else {
			fb = defaultAllocator.Get(int(sz))
			copy(*fb, data[sent:sent+int(sz)])
		}
		if err := c.queueDataLocked(fb, sz); err != nil {
			return sent, keep, err
		}
		sent += int(sz)
	}
	return sent, keep, nil
}

func (c *Channel) WriteTo(w io.Writer) (int64, error) {
	if c.readAborted() {
		return 0, io.ErrClosedPipe
	}

	c.readMu.Lock()
	defer func() {
		c.readMu.Unlock()
		if c.readAborted() {
			c.tryDrainRing()
		}
	}()

	var total int64
	sawDone := false

	for {
		for {
			buf, drained, ok := c.ring.Peek()
			if !ok {
				break
			}
			if drained != nil {
				_ = defaultAllocator.Put(drained)
				continue
			}
			n, err := w.Write(buf)
			if n > 0 {
				total += int64(n)
				if d := c.ring.Advance(n); d != nil {
					_ = defaultAllocator.Put(d)
				}
				c.flow.OnRead(n)
			}
			if err != nil {
				return total, err
			}
			if n < len(buf) {
				return total, io.ErrShortWrite
			}
		}

		if c.readAborted() {
			return total, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			if sawDone {
				c.ring.Close()
				return total, nil
			}
			sawDone = true
			continue
		}

		c.waitState.Store(stateWaiting)
		if _, _, ok := c.ring.Peek(); ok {
			c.waitState.Store(stateIdle)
			select {
			case <-c.notify:
			default:
			}
			continue
		}
		if c.readAborted() {
			c.waitState.Store(stateIdle)
			return total, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			c.waitState.Store(stateIdle)
			continue
		}

		select {
		case <-c.notify:
		case <-c.closeChan:
			c.waitState.Store(stateIdle)
			return total, io.ErrClosedPipe
		}
		c.waitState.Store(stateIdle)
	}
}

func (c *Channel) feedReliable(offset uint64, pBuf *[]byte, length uint32) {
	c.feedReliablePayload(offset, (*pBuf)[:length], pBuf, length)
}

func (c *Channel) cumulativeAckLocked() uint64 {
	if c.hasFin && c.readOffset >= c.finOffset {
		return c.finOffset + 1
	}
	return c.readOffset
}

func (c *Channel) creditSession(n uint32) {
	if f := c.session.flow; f != nil && f.enabled && n > 0 {
		f.OnRead(int32(n))
	}
}

func (c *Channel) sendAck(cumulativeOffset uint64) {
	if t := c.ackTimer.Load(); t != nil {
		t.Stop()
	}

	c.ackOffset.Store(cumulativeOffset)
	if !c.ackPending.CompareAndSwap(false, true) {
		return
	}
	frame := writeFrame{
		flag:  FLG_ACK,
		chID:  c.id,
		ackCh: c,
	}
	if !c.session.writeControlFrameNonBlocking(frame) {
		c.ackPending.Store(false)
	}
}

func (c *Channel) scheduleDelayedAck(offset uint64) {
	c.ackOffset.Store(offset)
	if c.ackPending.Load() {
		return
	}

	interval := c.session.config.AckInterval
	if interval <= 0 {
		c.sendAck(offset)
		return
	}

	// Fast path: If the receive ring already has more data queued,
	// the next packet will trigger an ACK; skip arming the timer.
	if c.ring.Length() > 0 {
		return
	}

	// Zero-alloc timer reuse:
	if t := c.ackTimer.Load(); t != nil {
		t.Reset(interval)
		return
	}

	t := time.AfterFunc(interval, func() {
		c.reorderMu.Lock()
		curOffset := c.cumulativeAckLocked()
		c.reorderMu.Unlock()
		c.sendAck(curOffset)
	})
	if !c.ackTimer.CompareAndSwap(nil, t) {
		t.Stop()
	}
}

func (c *Channel) onAck(ackOffset uint64) {
	c.unackedMu.Lock()
	drained := false
	defer func() {
		c.unackedMu.Unlock()
		if drained {
			c.maybeFinalize()
		}
	}()

	idx := 0
	for idx < len(c.unacked) {
		f := c.unacked[idx]
		if f.end() <= ackOffset {
			f.release()
			c.unacked[idx] = nil
			idx++
		} else {
			break
		}
	}
	if idx > 0 {
		n := copy(c.unacked, c.unacked[idx:])
		for i := n; i < len(c.unacked); i++ {
			c.unacked[i] = nil
		}
		c.unacked = c.unacked[:n]
		if n == 0 {
			drained = true
			if c.inARQ {
				c.inARQ = false
				c.session.arqRemove(c)
			}
			if cap(c.unacked) > maxRetainedUnacked {
				c.unacked = nil
			}
		}
	}
}

func (c *Channel) checkRetransmissions(rto time.Duration) {
	var due []*unackedFrame
	giveUp := false

	c.unackedMu.Lock()
	now := time.Now()
	for _, f := range c.unacked {
		shift := f.retransmits
		if shift > 6 {
			shift = 6
		}
		if now.Sub(f.sentAt) < rto<<shift {
			continue
		}
		f.sentAt = now
		f.retransmits++
		if f.retransmits > c.session.config.MaxRetransmit {
			giveUp = true
			break
		}
		f.retain()
		due = append(due, f)
	}
	c.unackedMu.Unlock()

	c.sendRetransmissions(due)
	if giveUp {
		go c.localClose()
	}
}

func (c *Channel) sendRetransmissions(due []*unackedFrame) {
	for i, f := range due {
		flag := FLG_DATA
		if f.fin {
			flag = FLG_FIN
		}
		frame := writeFrame{
			flag:   flag,
			chID:   c.id,
			pBuf:   f.pBuf,
			length: f.length,
			offset: f.offset,
			ack:    f,
		}
		if err := c.session.writeDataFrame(frame); err != nil {
			for _, g := range due[i:] {
				g.release()
			}
			return
		}
	}
}

func (c *Channel) retransmitAllUnacked() {
	c.unackedMu.Lock()
	now := time.Now()
	due := make([]*unackedFrame, 0, len(c.unacked))
	for _, f := range c.unacked {
		f.sentAt = now
		f.retain()
		due = append(due, f)
	}
	c.unackedMu.Unlock()

	c.sendRetransmissions(due)
}

func (c *Channel) feed(buffer *[]byte) error {
	if c.closed.Load() || c.session.isClosed() {
		if c.closed.Load() && !c.session.config.Reliability {
			c.resetPeer(false)
		}
		return io.ErrClosedPipe
	}

	c.ring.Push(*buffer, buffer)

	if c.waitState.Load() == stateWaiting {
		c.wakeReader()
	}
	return nil
}

func (c *Channel) feedPayload(payload []byte, head *[]byte) error {
	if c.closed.Load() || c.session.isClosed() {
		if c.closed.Load() && !c.session.config.Reliability {
			c.resetPeer(false)
		}
		if head != nil {
			_ = defaultAllocator.Put(head)
		}
		return io.ErrClosedPipe
	}

	c.ring.Push(payload, head)

	if c.waitState.Load() == stateWaiting {
		c.wakeReader()
	}
	return nil
}

func (c *Channel) feedReliablePayload(offset uint64, payload []byte, head *[]byte, length uint32) {
	shouldClose := false

	c.reorderMu.Lock()
	switch {
	case c.reorderMap == nil:
		if head != nil {
			_ = defaultAllocator.Put(head)
		}
		c.creditSession(length)

	case offset+uint64(length) <= c.readOffset:
		if head != nil {
			_ = defaultAllocator.Put(head)
		}
		c.sendAck(c.cumulativeAckLocked())

	case offset == c.readOffset:
		if err := c.feedPayload(payload, head); err != nil {
			c.creditSession(length)
			c.resetPeer(false)
		}
		c.readOffset += uint64(length)

		for len(c.reorderMap) > 0 {
			nextFrame, exists := c.reorderMap[c.readOffset]
			if !exists {
				break
			}
			delete(c.reorderMap, c.readOffset)
			if err := c.feedPayload(nextFrame.payload, nextFrame.head); err != nil {
				c.creditSession(nextFrame.length)
			}
			c.readOffset += uint64(nextFrame.length)
			*nextFrame = reorderFrame{}
			reorderPool.Put(nextFrame)
		}

		shouldClose = c.hasFin && c.readOffset >= c.finOffset
		ackRatio := c.session.config.StreamingAckRatio
		// ACK immediately if:
		// 1. Channel is closing (FIN reached)
		// 2. AckRatio <= 1
		// 3. We hit the N-packet threshold
		// 4. Single frame is large (>= MaxFrameDataSize), preventing lockstep stalls
		if shouldClose || ackRatio <= 1 || c.inOrderPackets.Add(1)%ackRatio == 0 || (length >= c.session.config.MaxFrameDataSize && c.session.config.ImmediateACKForLargePackets) {
			c.sendAck(c.cumulativeAckLocked())
		} else {
			c.scheduleDelayedAck(c.cumulativeAckLocked())
		}

	case offset > c.readOffset:
		if offset-c.readOffset > c.maxReorderBytes() {
			if head != nil {
				_ = defaultAllocator.Put(head)
			}
		} else if _, exists := c.reorderMap[offset]; !exists {
			rf := reorderPool.Get().(*reorderFrame)
			rf.payload = payload
			rf.head = head
			rf.offset = offset
			rf.length = length
			c.reorderMap[offset] = rf
		} else {
			if head != nil {
				_ = defaultAllocator.Put(head)
			}
		}
		c.sendAck(c.cumulativeAckLocked())

	default:
		if head != nil {
			_ = defaultAllocator.Put(head)
		}
		c.sendAck(c.cumulativeAckLocked())
	}
	c.reorderMu.Unlock()

	if shouldClose {
		c.remoteClose()
	}
}

func (c *Channel) wakeReader() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *Channel) CloseWrite() error {
	if c.session.isClosed() {
		return ErrSessionClosed
	}
	c.closeWrite()
	c.maybeFinalize()
	return nil
}

func (c *Channel) closeWrite() {
	c.writeOnce.Do(func() {
		c.writeClosed.Store(true)
		c.flow.WakeWriter()

		if c.writeMu.TryLock() {
			c.sendFinLocked()
			c.writeMu.Unlock()
		} else {
			go func() {
				c.writeMu.Lock()
				c.sendFinLocked()
				c.writeMu.Unlock()
				c.maybeFinalize()
			}()
		}
	})
}

func (c *Channel) sendFinLocked() {
	frame := writeFrame{
		flag:   FLG_FIN,
		chID:   c.id,
		offset: atomic.LoadUint64(&c.writeOffset),
	}
	if c.session.config.Reliability {
		uf := newUnackedFrame(nil, frame.offset, 0, true, 2)
		frame.ack = uf
		c.unackedMu.Lock()
		c.unacked = append(c.unacked, uf)
		if !c.inARQ {
			c.inARQ = true
			c.session.arqAdd(c)
		}
		c.unackedMu.Unlock()
	}
	c.finQueued.Store(true)
	if !c.session.writeDataFrameNonBlocking(frame) {
		go func() {
			if c.session.writeDataFrame(frame) != nil && frame.ack != nil {
				frame.ack.release()
			}
		}()
	}
}

func (c *Channel) Close() error {
	c.closeWrite()
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeChan)
		c.wakeReader()
		c.flow.WakeWriter()
		c.tryDrainRing()
		if !c.readDone.Load() {
			c.resetPeer(true)
			c.armCloseTimer()
		}
	})
	c.maybeFinalize()
	return nil
}

func (c *Channel) remoteClose() {
	c.drainable.Store(true)
	c.readDone.Store(true)
	c.wakeReader()
	c.flow.WakeWriter()
	c.maybeFinalize()
}

func (c *Channel) maybeFinalize() {
	if !c.finQueued.Load() || !c.readDone.Load() {
		return
	}
	c.unackedMu.Lock()
	pending := len(c.unacked)
	c.unackedMu.Unlock()
	if pending > 0 {
		return
	}
	c.finalize()
}

func (c *Channel) finalize() {
	c.finalizeOnce.Do(func() {
		if t := c.closeTimer.Swap(nil); t != nil {
			t.Stop()
		}
		if t := c.ackTimer.Swap(nil); t != nil {
			t.Stop()
		}
		c.cleanupReliability()
		c.readMu.Lock()
		if !c.drainable.Load() || c.ring.Length() == 0 {
			c.ring.Close()
		}
		c.readMu.Unlock()
		c.session.removeChannelIf(c.id, c)
		close(c.done)
	})
}

func (c *Channel) localClose() {
	c.writeOnce.Do(func() { c.writeClosed.Store(true) })
	c.finQueued.Store(true)
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeChan)
	})
	c.readDone.Store(true)
	c.wakeReader()
	c.flow.WakeWriter()
	if !c.drainable.Load() {
		c.tryDrainRing()
	}
	c.finalize()
}

func (c *Channel) peerGone() {
	c.writeOnce.Do(func() { c.writeClosed.Store(true) })
	c.finQueued.Store(true)
	c.drainable.Store(true)
	c.readDone.Store(true)
	c.wakeReader()
	c.flow.WakeWriter()
	c.finalize()
}

func (c *Channel) readAborted() bool {
	return c.closed.Load() || (c.session.isClosed() && !c.drainable.Load())
}

func (c *Channel) Done() <-chan struct{} { return c.done }

func (c *Channel) Label() string {
	l, _ := uint32ToString(c.id)
	return l
}

func (c *Channel) cleanupReliability() {
	if t := c.ackTimer.Swap(nil); t != nil {
		t.Stop()
	}
	if t := c.closeTimer.Swap(nil); t != nil {
		t.Stop()
	}
	c.unackedMu.Lock()
	unacked := c.unacked
	c.unacked = nil
	if c.inARQ {
		c.inARQ = false
		c.session.arqRemove(c)
	}
	c.unackedMu.Unlock()
	for _, f := range unacked {
		f.release()
	}

	c.reorderMu.Lock()
	for _, f := range c.reorderMap {
		if f.head != nil {
			defaultAllocator.Put(f.head)
			f.head = nil
		}
		*f = reorderFrame{}
		reorderPool.Put(f)
	}
	c.reorderMap = nil
	c.reorderMu.Unlock()
}

func (c *Channel) tryDrainRing() {
	if c.readMu.TryLock() {
		c.drainRing()
		c.readMu.Unlock()
	}
}

func (c *Channel) drainRing() {
	c.drainOnce.Do(func() {
		var discardedBytes int32
		for {
			buf, head, ok := c.ring.Pop()
			if !ok {
				break
			}
			discardedBytes += int32(len(buf))
			if head != nil {
				defaultAllocator.Put(head)
			}
		}

		if discardedBytes > 0 && c.session.flow != nil && c.session.flow.enabled {
			c.session.flow.OnRead(discardedBytes)
		}
		c.ring.Close()
	})
}

func (c *Channel) handleFinReliable(finOffset uint64) {
	c.reorderMu.Lock()
	if c.reorderMap == nil {
		c.reorderMu.Unlock()
		return
	}
	c.hasFin = true
	c.finOffset = finOffset
	shouldClose := c.readOffset >= finOffset
	c.sendAck(c.cumulativeAckLocked())
	c.reorderMu.Unlock()

	if shouldClose {
		c.remoteClose()
	}
}

func (c *Channel) writeErr() error {
	if c.resetByPeer.Load() {
		return ErrChannelReset
	}
	return io.ErrClosedPipe
}

func (c *Channel) resetPeer(force bool) {
	if c.readDone.Load() {
		return
	}
	now := time.Now().UnixNano()
	if !force {
		last := c.lastRst.Load()
		if now-last < int64(c.session.config.RetransmitTimeout) || !c.lastRst.CompareAndSwap(last, now) {
			return
		}
	} else {
		c.lastRst.Store(now)
	}
	c.session.sendReset(c.id, atomic.LoadUint64(&c.writeOffset))
}

func (c *Channel) armCloseTimer() {
	d := c.session.config.ChannelCloseTimeout
	if d <= 0 {
		return
	}
	t := time.AfterFunc(d, func() {
		select {
		case <-c.done:
		default:
			c.localClose()
		}
	})
	c.closeTimer.Store(t)
	select {
	case <-c.done:
		t.Stop()
	default:
	}
}

func (c *Channel) peerReset() {
	c.resetByPeer.Store(true)
	c.closeWrite()
	c.maybeFinalize()
}
