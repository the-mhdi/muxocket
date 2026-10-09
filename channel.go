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
	// drainable: the peer finished sending (FIN with all data, or GOAWAY), so
	// data already received stays readable after the session closes and Read
	// then returns io.EOF instead of io.ErrClosedPipe.
	drainable atomic.Bool

	// Half-close: writeClosed means our FIN has been (or is being) queued;
	// reading continues until the peer's FIN. finalizeOnce removes the
	// channel once both directions are done and (ARQ) everything is acked.
	writeClosed  atomic.Bool
	finQueued    atomic.Bool // FIN is tracked/queued; safe to finalize after it's acked
	writeOnce    sync.Once
	finalizeOnce sync.Once
	done         chan struct{} // closed by finalize
	// feedMu serialises producers into the ring (readLoop vs. delivery of
	// frames that arrived before OpenChannel) and keeps their order.
	feedMu sync.Mutex

	// Reliability Engine (ARQ & In-Order Reassembly)
	writeOffset uint64
	readOffset  uint64
	unackedMu   sync.Mutex
	unacked     []*unackedFrame
	reorderMu   sync.Mutex
	reorderMap  map[uint64]*reorderFrame
	finOffset   uint64
	hasFin      bool
	inARQ       bool // registered in session.arqSet; guarded by unackedMu

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
		return 0, io.ErrClosedPipe
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed.Load() {
		return 0, io.ErrClosedPipe
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
			if !c.inARQ {
				c.inARQ = true
				c.session.arqAdd(c)
			}
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
	if c.readAborted() {
		return 0, io.ErrClosedPipe
	}

	c.readMu.Lock()
	defer func() {
		// Unlock first, then re-check: either we observe closed and drain,
		// or Close() observed the lock free and drained itself.
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
			// readDone is set after the last data was pushed, but the ring
			// may have been sampled just before that push: look once more,
			// or the tail of the stream was lost behind a premature EOF.
			if sawDone {
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
	case c.reorderMap == nil:
		// Channel torn down; just drop it.
		_ = defaultAllocator.Put(pBuf)

	case offset+uint64(length) <= c.readOffset:
		// 1. Packet already acknowledged and received
		_ = defaultAllocator.Put(pBuf)
		c.sendAck(c.cumulativeAckLocked())

	case offset == c.readOffset:
		// 2. Next contiguous in-order slice
		if err := c.feed(pBuf); err != nil {
			// Locally closed: discard but still advance and ACK, so the
			// sender doesn't retransmit into the void until MaxRetransmit.
			_ = defaultAllocator.Put(pBuf)
			c.creditSession(length)
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
				c.creditSession(nextFrame.length)
			}
			c.readOffset += uint64(nextFrame.length)
		}

		// If FIN was previously received and all gaps are now filled, close the stream
		shouldClose = c.hasFin && c.readOffset >= c.finOffset
		c.sendAck(c.cumulativeAckLocked())

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
		c.sendAck(c.cumulativeAckLocked())

	default:
		// Partially overlapping retransmission (offset < readOffset < end).
		// Frames are never re-chunked, so this only happens with a broken
		// peer; drop it and re-ACK.
		_ = defaultAllocator.Put(pBuf)
		c.sendAck(c.cumulativeAckLocked())
	}
	c.reorderMu.Unlock()

	if shouldClose {
		c.remoteClose()
	}
}

// cumulativeAckLocked returns the ACK to send (reorderMu held). Once all data
// up to the FIN has arrived, the FIN itself is acknowledged by ACKing one
// unit past it, like TCP's FIN sequence number.
func (c *Channel) cumulativeAckLocked() uint64 {
	if c.hasFin && c.readOffset >= c.finOffset {
		return c.finOffset + 1
	}
	return c.readOffset
}

// creditSession returns session-window credit for bytes that were received
// but discarded (reliable mode: they won't be retransmitted, so nobody else
// will credit them).
func (c *Channel) creditSession(n uint32) {
	if f := c.session.flow; f != nil && f.enabled && n > 0 {
		f.OnRead(int32(n))
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
			drained = true
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
		// Exponential backoff (capped at 64x). With a fixed RTO every frame
		// was resent every RTO while the path was congested, which made the
		// congestion worse, and MaxRetransmit was exhausted after
		// MaxRetransmit*RTO (~1.2s by default): a short loss burst on a busy
		// link killed the channel. Default give-up time is now ~28s.
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

// CloseWrite half-closes the channel: no more writes, and the peer's Read
// returns io.EOF after all data written so far. Reading from this side keeps
// working until the peer closes its write side. With Reliability the FIN is
// retransmitted until acknowledged.
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
		c.flow.WakeWriter() // unpark a Write blocked on credits

		// The FIN must follow every data frame already accepted by Write, so
		// it's sent under writeMu. If a Write is in progress (e.g. blocked on
		// a full queue), don't block the caller: send it from a goroutine.
		if c.writeMu.TryLock() {
			c.sendFinLocked()
			c.writeMu.Unlock()
		} else {
			go func() {
				c.writeMu.Lock()
				c.sendFinLocked()
				c.writeMu.Unlock()
			}()
		}
	})
}

// sendFinLocked queues the FIN (writeMu held).
func (c *Channel) sendFinLocked() {
	frame := writeFrame{
		flag:   FLG_FIN,
		chID:   c.id,
		offset: atomic.LoadUint64(&c.writeOffset),
	}
	if c.session.config.Reliability {
		uf := &unackedFrame{offset: frame.offset, sentAt: time.Now(), fin: true}
		uf.refs.Store(2)
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

// Close fully closes the channel: it half-closes the write side (pending data
// and the FIN are still delivered) and stops reading; further incoming data
// is discarded. The channel is removed from the session once the peer has
// closed too and, with Reliability, everything has been acknowledged.
func (c *Channel) Close() error {
	c.closeWrite()
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeChan) // unblock readers and writers parked on credits
		c.wakeReader()
		c.flow.WakeWriter()
		c.tryDrainRing()
	})
	c.maybeFinalize()
	return nil
}

func (c *Channel) remoteClose() {
	// Everything the peer wrote is in the ring now; keep it readable even if
	// the session goes away before the application has read it.
	c.drainable.Store(true)
	c.readDone.Store(true)
	c.wakeReader()
	c.flow.WakeWriter()
	c.maybeFinalize()
}

// maybeFinalize removes the channel once both directions are finished and,
// with Reliability, nothing is left to retransmit (including our FIN).
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
		c.cleanupReliability()
		c.session.removeChannelIf(c.id, c)
		close(c.done)
	})
}

// localClose tears the channel down immediately (session closing, or peer
// unreachable after MaxRetransmit). Nothing more is sent.
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

// peerGone ends the channel after the peer closed the session gracefully
// (GOAWAY). Unlike localClose, buffered data stays readable: the peer flushed
// everything before GOAWAY, so discarding it here would truncate the stream.
func (c *Channel) peerGone() {
	c.writeOnce.Do(func() { c.writeClosed.Store(true) })
	c.finQueued.Store(true)
	c.drainable.Store(true)
	c.readDone.Store(true)
	c.wakeReader()
	c.flow.WakeWriter()
	c.finalize()
}

// readAborted reports whether Read must fail instead of returning data.
func (c *Channel) readAborted() bool {
	return c.closed.Load() || (c.session.isClosed() && !c.drainable.Load())
}

// Done is closed once the channel is fully finished: both sides closed their
// write direction and (with Reliability) all data and the FIN were
// acknowledged - or the channel/session was torn down.
func (c *Channel) Done() <-chan struct{} { return c.done }

// Label returns the channel name (lower-cased; labels are case-insensitive).
func (c *Channel) Label() string {
	l, _ := uint32ToString(c.id)
	return l
}

func (c *Channel) cleanupReliability() {
	c.unackedMu.Lock()
	unacked := c.unacked
	c.unacked = nil
	if c.inARQ {
		c.inARQ = false
		c.session.arqRemove(c)
	}
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
	if c.reorderMap == nil {
		c.reorderMu.Unlock()
		return
	}
	c.hasFin = true
	c.finOffset = finOffset
	shouldClose := c.readOffset >= finOffset
	// ACK the FIN (or, while data is still missing, re-ACK what we have).
	c.sendAck(c.cumulativeAckLocked())
	c.reorderMu.Unlock() // Unlock before triggering remoteClose to prevent self-deadlock

	if shouldClose {
		c.remoteClose()
	}
}
