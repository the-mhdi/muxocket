package muxocket

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// VIRTUAL DATAGRAM CONNECTION ADAPTER (packetSubConn)
// Bridges UDP datagrams into an io.ReadWriteCloser stream for Session
// ============================================================================

type packetSubConn struct {
	ln         *Listener
	remoteAddr net.Addr

	queue     RingBuffer
	reading   atomic.Int32
	waitState atomic.Uint32 // stateIdle or stateWaiting (for Read)
	readMu    sync.RWMutex
	notify    chan struct{}
	drainOnce sync.Once
	//readDone  atomic.Bool
	//currBuf   []byte
	closed atomic.Bool
	die    chan struct{}

	closeOnce sync.Once

	readDeadline  atomic.Pointer[time.Time]
	writeDeadline atomic.Pointer[time.Time]
}

func newPacketSubConn(ln *Listener, raddr net.Addr) *packetSubConn {
	return &packetSubConn{
		ln:         ln,
		remoteAddr: raddr,
		queue:      NewBufferRing(8), // Datagram queue depth
		die:        make(chan struct{}),
	}
}

// ListenPacket creates a datagram-oriented listener (UDP, Raw IP).
// config is optional; if omitted, DefaultConfig() is used.
func ListenPacket(packetConn net.PacketConn, MTU int, config ...*Config) (*Listener, error) {
	if packetConn == nil {
		return nil, errors.New("packetConn cannot be nil")
	}

	var cfg *Config
	if len(config) > 0 && config[0] != nil {
		cfg = config[0]
	} else {
		cfg = DefaultConfig()
	}

	ln := &Listener{
		pconn:                     packetConn,
		sessionConfig:             cfg,
		handshakeTimeout:          5 * time.Second,
		AllowConnectionResumption: true,
		ConnectionResumeTimeout:   cfg.ConnectionResumeTimeout,
		sessions:                  make(map[string]*activeSession),
		peerConns:                 make(map[string]*packetSubConn),
		acceptChan:                make(chan *Session, 64),
		die:                       make(chan struct{}),
	}

	// Start packet reading loop to route UDP datagrams
	go ln.packetReadLoop(MTU)

	return ln, nil
}

// packetReadLoop reads incoming UDP datagrams and routes them to per-client subConns
func (ln *Listener) packetReadLoop(MTU int) {
	for {
		if ln.closed.Load() {
			return
		}
		pBuf := defaultAllocator.Get(MTU)
		n, raddr, err := ln.pconn.ReadFrom(*pBuf)
		if err != nil {
			defaultAllocator.Put(pBuf)
			if ln.closed.Load() {
				return
			}
			continue
		}
		if n == 0 {
			defaultAllocator.Put(pBuf)
			continue
		}

		raddrStr := raddr.String()
		ln.peerMu.RLock()
		subConn, exists := ln.peerConns[raddrStr]
		ln.peerMu.RUnlock()

		if exists && !subConn.closed.Load() {
			subConn.feed(pBuf)
			continue
		}

		newSubConn := newPacketSubConn(ln, raddr)
		ln.peerMu.Lock()
		ln.peerConns[raddrStr] = newSubConn
		ln.peerMu.Unlock()

		newSubConn.feed(pBuf)
		go ln.handleIncomingPacketConn(newSubConn)
	}
}

func (s *packetSubConn) feed(buffer *[]byte) error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}

	s.queue.Push(*buffer, buffer)

	if s.waitState.Load() == stateWaiting {
		s.wakeReader()
	}
	return nil
}

func (s *packetSubConn) wakeReader() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *packetSubConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if s.closed.Load() || s.ln.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	s.reading.Add(1)
	defer func() {

		if s.closed.Load() || s.ln.closed.Load() {
			s.drainRing()
		}
		s.reading.Add(-1)
	}()

	totalRead := 0

	for {
		var timerCh <-chan time.Time
		if dl := s.readDeadline.Load(); dl != nil && !dl.IsZero() {
			d := time.Until(*dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timerCh = t.C
		}

		for len(b) > 0 {
			n, drainedBuf := s.queue.PartialRead(b)
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
			return totalRead, nil
		}

		if s.closed.Load() || s.ln.closed.Load() {
			return 0, io.ErrClosedPipe
		}

		s.waitState.Store(stateWaiting)

		n, drainedBuf := s.queue.PartialRead(b)
		if drainedBuf != nil {
			defaultAllocator.Put(drainedBuf)
		}

		if n > 0 {
			s.waitState.Store(stateIdle)
			select {
			case <-s.notify:
			default:
			}

			totalRead += n
			b = b[n:]
			for len(b) > 0 {
				n2, d2 := s.queue.PartialRead(b)
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

		if s.closed.Load() || s.ln.closed.Load() {
			s.waitState.Store(stateIdle)
			return 0, io.ErrClosedPipe
		}

		select {
		case <-s.die:
			return 0, io.ErrClosedPipe
		case <-timerCh:
			return 0, os.ErrDeadlineExceeded
		case <-s.notify:
		}

		s.waitState.Store(stateIdle)
	}
}

func (s *packetSubConn) Write(b []byte) (int, error) {
	if s.closed.Load() || s.ln.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return s.ln.pconn.WriteTo(b, s.remoteAddr)
}

// writeBuffers coalesces frame header + payload into a single UDP datagram
func (s *packetSubConn) writeBuffers(v *net.Buffers) (int64, error) {
	if s.closed.Load() || s.ln.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	var total int
	for _, b := range *v {
		total += len(b)
	}
	if total == 0 {
		return 0, nil
	}

	pBuf := defaultAllocator.Get(total)
	var buf []byte
	if pBuf != nil {
		buf = (*pBuf)[:total]
		defer defaultAllocator.Put(pBuf)
	} else {
		buf = make([]byte, total)
	}

	offset := 0
	for _, b := range *v {
		copy(buf[offset:], b)
		offset += len(b)
	}

	n, err := s.ln.pconn.WriteTo(buf, s.remoteAddr)
	if err != nil {
		return 0, err
	}
	*v = (*v)[:0]
	return int64(n), nil
}
func (s *packetSubConn) LocalAddr() net.Addr  { return s.ln.pconn.LocalAddr() }
func (s *packetSubConn) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *packetSubConn) SetDeadline(t time.Time) error {
	s.readDeadline.Store(&t)
	s.writeDeadline.Store(&t)
	return nil
}

func (s *packetSubConn) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(&t)
	return nil
}

func (s *packetSubConn) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(&t)
	return nil
}

func (s *packetSubConn) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.die)

		s.ln.peerMu.Lock()
		delete(s.ln.peerConns, s.remoteAddr.String())
		s.ln.peerMu.Unlock()
	})
	return nil
}

func (s *packetSubConn) drainRing() {
	s.drainOnce.Do(func() {
		var discardedBytes int32
		for {
			buf, head, ok := s.queue.Pop()
			if !ok {
				break
			}
			discardedBytes += int32(len(buf))
			if head != nil {
				defaultAllocator.Put(head)
			}
		}
	})
}
