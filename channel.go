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
	waitState atomic.Uint32 // stateIdle or stateWaiting (for Read)
	reading   atomic.Int32

	flow *StreamFlow

	closeOnce sync.Once
	closed    atomic.Bool // Local write/read closed
	readDone  atomic.Bool // Remote peer closed (FIN received)
}

func newChannel(id uint32, session *Session) *Channel {
	ch := &Channel{
		id:      id,
		session: session,
		ring:    NewBufferRing(8),
		notify:  make(chan struct{}, 1),
	}
	ch.flow = NewStreamFlow(id, int32(session.config.InitialStreamWindow), ch, session)
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

		// 1. Lock-free credit acquisition (does not block other channels)
		sz, err := c.flow.AcquireCredits(int32(desired))
		if err != nil {
			return totalSent, err
		}

		chunk := b[:sz]
		pBuf := defaultAllocator.Get(int(sz))
		copy(*pBuf, chunk)

		frame := writeFrame{
			flag:   FLG_DATA,
			chID:   c.id,
			pBuf:   pBuf,
			length: uint32(sz),
		}

		// 2. Push to write scheduler
		if err := c.session.writeDataFrame(frame); err != nil {
			defaultAllocator.Put(pBuf)
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

	c.reading.Add(1)
	defer func() {
		c.reading.Add(-1)
		if c.closed.Load() || c.session.isClosed() {
			c.drainRing()
		}
	}()

	totalRead := 0

	for {
		// 1. Multi-chunk drain: pull as many frames as fit into b
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

		// 2. Return data and replenish flow control window non-blockingly
		if totalRead > 0 {
			c.flow.OnRead(totalRead)
			return totalRead, nil
		}

		// 3. Evaluate termination states
		if c.closed.Load() || c.session.isClosed() {
			return 0, io.ErrClosedPipe
		}
		if c.readDone.Load() {
			return 0, io.EOF
		}

		// 4. Lock-free double-check before sleeping
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

		// 5. Sleep until Feed or Close wakes us
		<-c.notify
		c.waitState.Store(stateIdle)
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

		c.session.removeChannel(c.id)
	})
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
