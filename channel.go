package muxocket

import (
	"io"
	"sync"
	"sync/atomic"
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
	waitState atomic.Uint32 // stateIdle or stateWaiting
	reading   atomic.Int32  // Tracks active reader count for safe Close() cleanup

	closeOnce sync.Once
	closed    atomic.Bool // Local write/read closed
	readDone  atomic.Bool // Remote peer closed (FIN received)
}

func newChannel(id uint32, session *Session) *Channel {
	return &Channel{
		id:      id,
		session: session,
		ring:    NewBufferRing(16),
		notify:  make(chan struct{}, 1),
	}
}

// Write is lock-free: checks atomic state and enqueues frames to write scheduler.
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
		sz := len(b)
		if sz > maxChunk {
			sz = maxChunk
		}
		chunk := b[:sz]

		pBuf := defaultAllocator.Get(sz)
		copy(*pBuf, chunk)

		frame := writeFrame{
			flag:   FLG_DATA,
			chID:   c.id,
			pBuf:   pBuf,
			length: uint32(sz),
		}

		if err := c.session.writeDataFrame(frame); err != nil {
			defaultAllocator.Put(pBuf)
			return totalSent, err
		}

		totalSent += sz
		b = b[sz:]
	}

	return totalSent, nil
}

// Read is lock-free, Pure Byte Stream, and Multi-Chunk Drain.
// It drains as many chunks as will fit into b before returning.
func (c *Channel) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.closed.Load() || c.session.isClosed() {
		return 0, io.ErrClosedPipe
	}

	c.reading.Add(1)
	defer func() {
		c.reading.Add(-1)
		// If channel closed while reading, ensure ring is drained to prevent buffer leaks
		if c.closed.Load() || c.session.isClosed() {
			c.drainRing()
		}
	}()

	totalRead := 0

	for {
		// 1. Multi-Chunk Drain: consume all available chunks that fit into b
		for len(b) > 0 {
			n, drainedBuf := c.ring.PartialRead(b)
			if drainedBuf != nil {
				defaultAllocator.Put(drainedBuf)
			}

			if n > 0 {
				totalRead += n
				b = b[n:]
				continue // Keep draining next slot in ring
			}
			break // No more data in ring right now
		}

		// 2. If any bytes were drained, return immediately without blocking (Pure Byte Stream)
		if totalRead > 0 {
			return totalRead, nil
		}

		// 3. Ring is completely empty: check termination states
		if c.closed.Load() || c.session.isClosed() {
			return 0, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			return 0, io.EOF
		}

		// 4. Mark waiting state before re-checking (Lock-Free Double Check)
		c.waitState.Store(stateWaiting)

		// Double check: did Feed push data right as we transitioned to waitState?
		n, drainedBuf := c.ring.PartialRead(b)
		if drainedBuf != nil {
			defaultAllocator.Put(drainedBuf)
		}
		if n > 0 {
			c.waitState.Store(stateIdle)
			// Drain any signal that might have been sent
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
			return totalRead, nil
		}

		// Re-evaluate termination before sleeping
		if c.closed.Load() || c.session.isClosed() {
			c.waitState.Store(stateIdle)
			return 0, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			c.waitState.Store(stateIdle)
			return 0, io.EOF
		}

		// 5. Block until Feed, Close, or remoteClose wakes us
		<-c.notify
		c.waitState.Store(stateIdle)
	}
}

// Feed is lock-free: pushes directly into SPSC ring buffer and wakes reader only if needed.
func (c *Channel) Feed(buffer *[]byte) error {
	if c.closed.Load() || c.session.isClosed() {
		return io.ErrClosedPipe
	}

	c.ring.Push(*buffer, buffer)

	// Lock-free wakeup: only signal if reader is waiting
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

		// 1. Send FLG_FIN in strict FIFO order behind all pending writes
		err = c.session.writeDataFrame(writeFrame{
			flag:   FLG_FIN,
			chID:   c.id,
			pBuf:   nil,
			length: 0,
		})

		// 2. Wake any sleeping reader so it returns io.ErrClosedPipe
		c.wakeReader()

		// 3. If no reader is active, drain ring safely to recycle buffers
		if c.reading.Load() == 0 {
			c.drainRing()
		}

		// 4. If remote peer already sent FIN, unregister channel
		if c.readDone.Load() {
			c.session.removeChannel(c.id)
		}
	})
	return err
}

// remoteClose is called by Session.readLoop when FLG_FIN arrives from peer.
func (c *Channel) remoteClose() {
	c.readDone.Store(true)
	c.wakeReader()

	if c.closed.Load() {
		c.session.removeChannel(c.id)
	}
}

// localClose is called when the entire Session dies.
func (c *Channel) localClose() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.readDone.Store(true)

		c.wakeReader()

		if c.reading.Load() == 0 {
			c.drainRing()
		}

		c.session.removeChannel(c.id)
	})
}

// drainRing recycles all unread pooled buffers in the ring buffer.
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
