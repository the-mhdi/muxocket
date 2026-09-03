package muxocket

import (
	"io"
	"sync"
	"sync/atomic"
)

type Channel struct {
	id      uint32
	session *Session

	mu       sync.Mutex
	notEmpty *sync.Cond
	ring     RingBuffer
	//currBuf  *[]byte
	currOff int

	closeOnce sync.Once
	closed    atomic.Bool // Local channel closed
	readDone  atomic.Bool // Remote peer closed (FIN received)
}

func newChannel(id uint32, session *Session) *Channel {
	ch := &Channel{
		id:      id,
		session: session,
		ring:    NewBufferRing(16),
	}
	ch.notEmpty = sync.NewCond(&ch.mu)
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

func (c *Channel) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		// 1. Consume partially read buffer if present
		n, drainedBuf := c.ring.PartialRead(b)

		if drainedBuf != nil {
			defaultAllocator.Put(drainedBuf)
		}

		if n > 0 {
			return n, nil
		}

		// 3. Ring is empty: evaluate termination states
		if c.session.isClosed() || c.closed.Load() {
			// Local close or session shutdown terminates pending reads
			return 0, io.ErrClosedPipe
		}

		if c.readDone.Load() {
			// Remote peer cleanly closed write side and all data is drained
			return 0, io.EOF
		}

		// 4. Block until incoming packet (Feed) or termination (Close/remoteClose)
		c.notEmpty.Wait()
	}
}

func (c *Channel) Feed(buffer *[]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If closed locally or session died, reject packet so caller can recycle buffer
	if c.closed.Load() || c.session.isClosed() {
		return io.ErrClosedPipe
	}

	c.ring.Push(*buffer, buffer)
	c.notEmpty.Signal()
	return nil
}

func (c *Channel) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// 1. Send FLG_FIN in strict FIFO order behind all pending writes
		err = c.session.writeDataFrame(writeFrame{
			flag:   FLG_FIN,
			chID:   c.id,
			pBuf:   nil,
			length: 0,
		})

		// 2. Mark closed locally and unblock pending readers
		c.mu.Lock()
		c.closed.Store(true)

		/*if c.currBuf != nil {
			defaultAllocator.Put(c.currBuf)
			c.currBuf = nil
		}*/
		for {
			_, head, ok := c.ring.Pop()
			if !ok {
				break
			}
			if head != nil {
				defaultAllocator.Put(head)
			}
		}
		c.notEmpty.Broadcast()

		// 3. Atomically check if remote already sent FIN
		shouldRemove := c.readDone.Load()
		c.mu.Unlock()

		// 4. If both sides are closed, prune from session map (OUTSIDE c.mu to prevent lock inversion)
		if shouldRemove {
			c.session.removeChannel(c.id)
		}
	})
	return err
}

// remoteClose is called by Session.readLoop when FLG_FIN arrives from the peer.
func (c *Channel) remoteClose() {
	c.mu.Lock()
	c.readDone.Store(true)
	c.notEmpty.Broadcast()

	// Atomically check if local side already closed
	shouldRemove := c.closed.Load()
	c.mu.Unlock()

	// If both sides are closed, prune from session map (OUTSIDE c.mu)
	if shouldRemove {
		c.session.removeChannel(c.id)
	}
}

// localClose is called when the entire Session dies.
func (c *Channel) localClose() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.readDone.Store(true)

		c.mu.Lock()
		/*if c.currBuf != nil {
			defaultAllocator.Put(c.currBuf)
			c.currBuf = nil
		}*/

		for {
			_, head, ok := c.ring.Pop()
			if !ok {
				break
			}
			if head != nil {
				defaultAllocator.Put(head)
			}
		}
		c.notEmpty.Broadcast()
		c.mu.Unlock()

		c.session.removeChannel(c.id)
	})
}
