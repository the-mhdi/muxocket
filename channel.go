package muxocket

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	stateIdle    uint32 = 0
	stateWaiting uint32 = 1
)

type Channel struct {
	id      uint32
	session *Session

	ring   RingBuffer
	notify chan struct{}

	waitState atomic.Uint32 // stateIdle or stateWaiting (for Read)
	readMu    sync.Mutex
	writeMu   sync.Mutex // serialises Write so offsets/unacked stay ordered and calls don't interleave

	flow *StreamFlow

	closeOnce sync.Once
	closeChan chan struct{} // Closed once to broadcast-unblock all readers & writers
	drainOnce sync.Once
	closed    atomic.Bool // Local write/read closed
	readDone  atomic.Bool

	// Reliability Engine (ARQ & In-Order Reassembly)
	writeOffset uint64
	readOffset  uint64
	unackedMu   sync.Mutex
	unacked     []*unackedFrame
	reorderMu   sync.Mutex
	reorderMap  map[uint64]*reorderFrame
	finOffset   uint64
	hasFin      bool

	// Coalesced ACK state (see sendAck / writeLoop)
	ackOffset  atomic.Uint64
	ackPending atomic.Bool
}

// maxReorderBytes bounds out-of-order buffering per channel. A peer could
// otherwise send frames at arbitrary future offsets and grow reorderMap
// without limit (memory DoS). A well-behaved sender never has more than its
// stream window in flight.
func (c *Channel) maxReorderBytes() uint64 {
	return uint64(c.session.config.InitialStreamWindow) * 2
}

func newChannel(id uint32, session *Session) *Channel {
	ch := &Channel{
		id:         id,
		session:    session,
		ring:       NewBufferRing(8),
		notify:     make(chan struct{}, 1),
		closeChan:  make(chan struct{}), // Initialize broadcast channel
		reorderMap: make(map[uint64]*reorderFrame),
	}
	ch.closed.Store(false)
	ch.flow = NewStreamFlow(id, int32(session.config.InitialStreamWindow), ch, session)

	if session.config.Reliability {
		go ch.arqLoop()
	}

	return ch
}

func (c *Channel) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.closed.Load() || c.session.isClosed() {
		return 0, io.ErrClosedPipe
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	maxChunk := int(c.session.config.MaxFrameDataSize)
	totalSent := 0

	for len(b) > 0 {
		desired := len(b)
		if desired > maxChunk {
			desired = maxChunk
		}

		sz, err := c.flow.AcquireCredits(int32(desired))
		if err != nil {
			return totalSent, err
		}

		chunk := b[:sz]
		pBuf := defaultAllocator.Get(int(sz))
		copy(*pBuf, chunk)

		currOffset := atomic.AddUint64(&c.writeOffset, uint64(sz)) - uint64(sz)

		frame := writeFrame{
			flag:   FLG_DATA,
			chID:   c.id,
			pBuf:   pBuf,
			length: uint32(sz),
			offset: currOffset,
		}

		// Track in unacked queue prior to transmission if ARQ is active.
		// refs = 2: one for the unacked queue, one for the writer.
		if c.session.config.Reliability {
			uf := &unackedFrame{
				pBuf:   pBuf,
				offset: currOffset,
				length: uint32(sz),
				sentAt: time.Now(),
			}
			uf.refs.Store(2)
			frame.ack = uf
			c.unackedMu.Lock()
			c.unacked = append(c.unacked, uf)
			c.unackedMu.Unlock()
		}

		if err := c.session.writeDataFrame(frame); err != nil {
			if frame.ack != nil {
				frame.ack.release() // writer's reference; unacked keeps its own
			} else {
				_ = defaultAllocator.Put(pBuf)
			}
			c.flow.Refund(sz)
			return totalSent, err
		}

		totalSent += int(sz)
		b = b[sz:]
	}

	return totalSent, nil
}

func (c *Channel) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.closed.Load() || c.session.isClosed() {
		return 0, io.ErrClosedPipe
	}

	c.readMu.Lock()
	defer func() {
		// Unlock first, then re-check: either we observe closed and drain,
		// or Close() observed the lock free and drained itself.
		c.readMu.Unlock()
		if c.closed.Load() || c.session.isClosed() {
			c.tryDrainRing()
		}
	}()

	totalRead := 0

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

		if c.closed.Load() || c.session.isClosed() {
			return 0, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			return 0, io.EOF
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

		if c.closed.Load() || c.session.isClosed() {
			c.waitState.Store(stateIdle)
			return 0, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			c.waitState.Store(stateIdle)
			return 0, io.EOF
		}

		select {
		case <-c.notify:
		case <-c.closeChan:
			return 0, io.ErrClosedPipe
		}
		c.waitState.Store(stateIdle)
	}
}

// feedReliable handles reordering, deduplication, and sequential assembly.
//
// Fixes vs. the previous version:
//   - remoteClose() was called while holding reorderMu; when the channel was
//     already closed locally it calls cleanupReliability(), which locks
//     reorderMu again -> self-deadlock of the session's readLoop.
//   - after cleanupReliability() reorderMap is nil; a late out-of-order frame
//     panicked with "assignment to entry in nil map".
//   - buffers rejected by feed() (closed channel) were leaked.
//   - reorderMap was unbounded.
func (c *Channel) feedReliable(offset uint64, pBuf *[]byte, length uint32) {
	shouldClose := false

	c.reorderMu.Lock()
	switch {
	case c.reorderMap == nil || c.closed.Load():
		// Channel torn down (or closed locally); just drop it.
		_ = defaultAllocator.Put(pBuf)

	case offset+uint64(length) <= c.readOffset:
		// 1. Packet already acknowledged and received
		_ = defaultAllocator.Put(pBuf)
		c.sendAck(c.readOffset)

	case offset == c.readOffset:
		// 2. Next contiguous in-order slice
		if err := c.feed(pBuf); err != nil {
			_ = defaultAllocator.Put(pBuf)
		}
		c.readOffset += uint64(length)

		// Drain contiguous backlog
		for len(c.reorderMap) > 0 {
			nextFrame, exists := c.reorderMap[c.readOffset]
			if !exists {
				break
			}
			delete(c.reorderMap, c.readOffset)
			if err := c.feed(nextFrame.pBuf); err != nil {
				_ = defaultAllocator.Put(nextFrame.pBuf)
			}
			c.readOffset += uint64(nextFrame.length)
		}

		// If FIN was previously received and all gaps are now filled, close the stream
		shouldClose = c.hasFin && c.readOffset >= c.finOffset
		c.sendAck(c.readOffset)

	case offset > c.readOffset:
		// 3. Out-of-order slice (gap detected): buffer and issue duplicate ACK
		if offset-c.readOffset > c.maxReorderBytes() {
			_ = defaultAllocator.Put(pBuf) // beyond any legal window
		} else if _, exists := c.reorderMap[offset]; !exists {
			c.reorderMap[offset] = &reorderFrame{
				pBuf:   pBuf,
				offset: offset,
				length: length,
			}
		} else {
			_ = defaultAllocator.Put(pBuf)
		}
		c.sendAck(c.readOffset)

	default:
		// Partially overlapping retransmission (offset < readOffset < end).
		// Frames are never re-chunked, so this only happens with a broken
		// peer; drop it and re-ACK.
		_ = defaultAllocator.Put(pBuf)
		c.sendAck(c.readOffset)
	}
	c.reorderMu.Unlock()

	if shouldClose {
		c.remoteClose()
	}
}

// sendAck publishes the latest cumulative offset and enqueues at most one ACK
// frame per channel; the writer reads the newest offset at flush time.
func (c *Channel) sendAck(cumulativeOffset uint64) {
	c.ackOffset.Store(cumulativeOffset)
	if !c.ackPending.CompareAndSwap(false, true) {
		return // an ACK is already queued; it will carry the new offset
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

// onAck releases acknowledged chunks back to the allocator.
func (c *Channel) onAck(ackOffset uint64) {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()

	idx := 0
	for idx < len(c.unacked) {
		f := c.unacked[idx]
		if f.offset+uint64(f.length) <= ackOffset {
			f.release()
			c.unacked[idx] = nil // don't let the backing array pin acked frames
			idx++
		} else {
			break
		}
	}
	if idx > 0 {
		c.unacked = c.unacked[idx:]
		if len(c.unacked) == 0 {
			c.unacked = nil // drop the (possibly large) backing array
		}
	}
}

func (c *Channel) arqLoop() {
	rto := c.session.config.RetransmitTimeout
	ticker := time.NewTicker(rto / 2)
	defer ticker.Stop()

	for {
		select {
		case <-c.session.die:
			return
		case <-ticker.C:
			if c.closed.Load() {
				c.unackedMu.Lock()
				empty := len(c.unacked) == 0
				c.unackedMu.Unlock()
				if empty {
					return
				}
			}
			c.checkRetransmissions(rto)
		}
	}
}

// checkRetransmissions collects due frames under the lock but sends them
// after releasing it. The old version called the blocking writeDataFrame while
// holding unackedMu; when the write queue was full, onAck (called from
// readLoop) blocked on the same mutex, stalling the receive path and therefore
// the ACKs that would have drained the queue (deadlock under load).
func (c *Channel) checkRetransmissions(rto time.Duration) {
	var due []*unackedFrame
	giveUp := false

	c.unackedMu.Lock()
	now := time.Now()
	for _, f := range c.unacked {
		if now.Sub(f.sentAt) < rto {
			continue
		}
		f.sentAt = now
		f.retransmits++
		if f.retransmits > c.session.config.MaxRetransmit {
			giveUp = true
			break
		}
		f.retain() // reference held by the in-flight retransmission
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
		frame := writeFrame{
			flag:   FLG_DATA,
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
		return io.ErrClosedPipe
	}

	c.ring.Push(*buffer, buffer)

	if c.waitState.Load() == stateWaiting {
		c.wakeReader()
	}
	return nil
}

func (c *Channel) wakeReader() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *Channel) Close() error {
	var err error
	if c.closed.Load() == true {
		return nil
	}

	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeChan) // 1. Broadcast to instantly unblock all writers and readers

		c.wakeReader()

		c.flow.WakeWriter()

		finalOffset := atomic.LoadUint64(&c.writeOffset)

		frame := writeFrame{
			flag:   FLG_FIN,
			chID:   c.id,
			pBuf:   nil,
			length: 0,
			offset: finalOffset,
		}

		// 2. Do not block indefinitely if the write queue is saturated
		if !c.session.writeDataFrameNonBlocking(frame) {
			go func() {
				_ = c.session.writeDataFrame(frame)
			}()
		}

		c.tryDrainRing()

		if c.readDone.Load() {
			c.cleanupReliability()

			c.session.removeChannel(c.id)
		}

	})
	return err
}

func (c *Channel) remoteClose() {
	c.readDone.Store(true)
	c.wakeReader()
	c.flow.WakeWriter()

	if c.closed.Load() {
		c.cleanupReliability()
		c.session.removeChannel(c.id)
	}
}

func (c *Channel) localClose() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.readDone.Store(true)
		close(c.closeChan) // unblock writers parked in AcquireCredits / readers

		c.wakeReader()
		c.flow.WakeWriter()

		c.tryDrainRing()

		c.cleanupReliability()
		c.session.removeChannel(c.id)
	})
}

func (c *Channel) cleanupReliability() {
	c.unackedMu.Lock()
	unacked := c.unacked
	c.unacked = nil
	c.unackedMu.Unlock()
	for _, f := range unacked {
		f.release() // frames still queued in the writer keep their own ref
	}

	c.reorderMu.Lock()
	for _, f := range c.reorderMap {
		if f.pBuf != nil {
			defaultAllocator.Put(f.pBuf)
			f.pBuf = nil
		}
	}
	c.reorderMap = nil
	c.reorderMu.Unlock()
}

// tryDrainRing drains the ring only if no Read is in progress. The ring is
// single-consumer: the old `reading.Load() == 0` check raced with a Read that
// had passed its closed-check but not yet incremented `reading`, giving two
// concurrent consumers. An active reader drains in its own deferred cleanup.
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

		// Replenish the connection-wide session window for discarded data!
		if discardedBytes > 0 && c.session.flow != nil && c.session.flow.enabled {
			c.session.flow.OnRead(discardedBytes)
		}
	})
}

func (c *Channel) handleFinReliable(finOffset uint64) {
	c.reorderMu.Lock()
	c.hasFin = true
	c.finOffset = finOffset
	shouldClose := c.readOffset >= finOffset
	c.reorderMu.Unlock() // Unlock before triggering remoteClose to prevent self-deadlock

	if shouldClose {
		c.remoteClose()
	}
}
