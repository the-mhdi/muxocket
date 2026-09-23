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

	ring      RingBuffer
	notify    chan struct{}
	waitState atomic.Uint32 // stateIdle or stateWaiting (for Read)
	reading   atomic.Int32
	readMu    sync.Mutex // Guarantees thread-safe consumer reads on ring buffer

	flow *StreamFlow

	closeOnce sync.Once
	closed    atomic.Bool // Local write/read closed
	readDone  atomic.Bool // Remote peer closed (FIN received)

	// Reliability Engine (ARQ & In-Order Reassembly)
	writeOffset uint64 // Tracks local contiguous byte stream position
	readOffset  uint64 // Tracks contiguous byte stream delivered to user
	unackedMu   sync.Mutex
	unacked     []*unackedFrame
	reorderMu   sync.Mutex
	reorderMap  map[uint64]*reorderFrame
}

func newChannel(id uint32, session *Session) *Channel {
	ch := &Channel{
		id:         id,
		session:    session,
		ring:       NewBufferRing(8),
		notify:     make(chan struct{}, 1),
		reorderMap: make(map[uint64]*reorderFrame),
	}
	ch.closed.Store(false)
	ch.flow = NewStreamFlow(id, int32(session.config.InitialStreamWindow), ch, session)

	if session.config.Reliable {
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

	maxChunk := int(c.session.config.MaxChannelDataSize)
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

		// Track in unacked queue prior to transmission if ARQ is active
		if c.session.config.Reliable {
			c.unackedMu.Lock()
			c.unacked = append(c.unacked, &unackedFrame{
				pBuf:        pBuf,
				offset:      currOffset,
				length:      uint32(sz),
				sentAt:      time.Now(),
				retransmits: 0,
			})
			c.unackedMu.Unlock()
		}

		if err := c.session.writeDataFrame(frame); err != nil {
			if !c.session.config.Reliable {
				defaultAllocator.Put(pBuf)
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

	// Protect consumer invariants in SPSC RingBuffer
	c.readMu.Lock()
	defer c.readMu.Unlock()

	c.reading.Add(1)
	defer func() {
		c.reading.Add(-1)
		if c.closed.Load() || c.session.isClosed() {
			c.drainRing()
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

		<-c.notify
		c.waitState.Store(stateIdle)
	}
}

// feedReliable handles reordering, deduplication, and sequential assembly.
func (c *Channel) feedReliable(offset uint64, pBuf *[]byte, length uint32) {
	c.reorderMu.Lock()
	defer c.reorderMu.Unlock()

	// 1. Packet already acknowledged and received
	if offset+uint64(length) <= c.readOffset {
		defaultAllocator.Put(pBuf)
		c.sendAck(c.readOffset)
		return
	}

	// 2. Next contiguous in-order slice
	if offset == c.readOffset {
		c.Feed(pBuf)
		c.readOffset += uint64(length)

		// Drain contiguous backlog
		for {
			nextFrame, exists := c.reorderMap[c.readOffset]
			if !exists {
				break
			}
			delete(c.reorderMap, c.readOffset)
			c.Feed(nextFrame.pBuf)
			c.readOffset += uint64(nextFrame.length)
		}

		c.sendAck(c.readOffset)
		return
	}

	// 3. Out-of-order slice (gap detected): buffer and issue Fast Retransmit duplicate ACK
	if offset > c.readOffset {
		if _, exists := c.reorderMap[offset]; !exists {
			c.reorderMap[offset] = &reorderFrame{
				pBuf:   pBuf,
				offset: offset,
				length: length,
			}
		} else {
			defaultAllocator.Put(pBuf)
		}
		c.sendAck(c.readOffset)
	}
}

func (c *Channel) sendAck(cumulativeOffset uint64) {
	frame := writeFrame{
		flag:   FLG_ACK,
		chID:   c.id,
		offset: cumulativeOffset,
		length: 0,
		pBuf:   nil,
	}
	c.session.writeControlFrameNonBlocking(frame)
}

// onAck releases acknowledged chunks back to the allocator.
func (c *Channel) onAck(ackOffset uint64) {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()

	idx := 0
	for idx < len(c.unacked) {
		f := c.unacked[idx]
		if f.offset+uint64(f.length) <= ackOffset {
			if f.pBuf != nil {
				defaultAllocator.Put(f.pBuf)
				f.pBuf = nil
			}
			idx++
		} else {
			break
		}
	}
	if idx > 0 {
		c.unacked = c.unacked[idx:]
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

func (c *Channel) checkRetransmissions(rto time.Duration) {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()

	if len(c.unacked) == 0 {
		return
	}

	now := time.Now()
	for _, f := range c.unacked {
		if now.Sub(f.sentAt) >= rto {
			f.sentAt = now
			f.retransmits++

			if f.retransmits > c.session.config.MaxRetransmit {
				go c.localClose()
				return
			}

			frame := writeFrame{
				flag:   FLG_DATA,
				chID:   c.id,
				pBuf:   f.pBuf,
				length: f.length,
				offset: f.offset,
			}
			c.session.writeDataFrame(frame)
		}
	}
}

func (c *Channel) retransmitAllUnacked() {
	c.unackedMu.Lock()
	defer c.unackedMu.Unlock()

	now := time.Now()
	for _, f := range c.unacked {
		f.sentAt = now
		frame := writeFrame{
			flag:   FLG_DATA,
			chID:   c.id,
			pBuf:   f.pBuf,
			length: f.length,
			offset: f.offset,
		}
		c.session.writeDataFrame(frame)
	}
}

func (c *Channel) Feed(buffer *[]byte) error {
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
	c.closeOnce.Do(func() {
		c.closed.Store(true)

		c.wakeReader()
		c.flow.WakeWriter()

		err = c.session.writeDataFrame(writeFrame{
			flag:   FLG_FIN,
			chID:   c.id,
			pBuf:   nil,
			length: 0,
		})

		if c.reading.Load() == 0 {
			c.drainRing()
		}

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

		c.wakeReader()
		c.flow.WakeWriter()

		if c.reading.Load() == 0 {
			c.drainRing()
		}

		c.cleanupReliability()
		c.session.removeChannel(c.id)
	})
}

func (c *Channel) cleanupReliability() {
	c.unackedMu.Lock()
	for _, f := range c.unacked {
		if f.pBuf != nil {
			defaultAllocator.Put(f.pBuf)
			f.pBuf = nil
		}
	}
	c.unacked = nil
	c.unackedMu.Unlock()

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

func (c *Channel) drainRing() {
	for {
		_, head, ok := c.ring.Pop()
		if !ok {
			break
		}
		if head != nil {
			defaultAllocator.Put(head)
		}
	}
}
