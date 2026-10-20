package muxocket

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// VIRTUAL DATAGRAM CONNECTION ADAPTER (packetSubConn)
// Bridges UDP/IP datagrams into an io.ReadWriteCloser stream for Session
// ============================================================================

type packetSubConn struct {
	ln         *Listener
	remoteAddr net.Addr

	// Fast 0-alloc identifiers
	udpAddrPort netip.AddrPort
	ipAddr      netip.Addr

	queue     RingBuffer
	waitState atomic.Uint32 // stateIdle or stateWaiting (for Read)
	readMu    sync.Mutex
	notify    chan struct{}
	closed    atomic.Bool
	die       chan struct{}

	closeOnce sync.Once

	readDeadline  atomic.Pointer[time.Time]
	writeDeadline atomic.Pointer[time.Time]
}

func newPacketSubConn(ln *Listener, raddr net.Addr) *packetSubConn {
	sub := &packetSubConn{
		ln:         ln,
		remoteAddr: raddr,
		queue:      NewBufferRing(16),
		notify:     make(chan struct{}, 1),
		die:        make(chan struct{}),
	}
	if u, ok := raddr.(*net.UDPAddr); ok {
		sub.udpAddrPort = u.AddrPort()
	} else if ip, ok := raddr.(*net.IPAddr); ok {
		if a, ok := netip.AddrFromSlice(ip.IP); ok {
			sub.ipAddr = a.Unmap()
		}
	}
	return sub
}

// ListenPacket creates a datagram-oriented listener (UDP, Raw IP).
func ListenPacket(packetConn net.PacketConn, MTU int, config ...*Config) (*Listener, error) {
	if packetConn == nil {
		return nil, errors.New("packetConn cannot be nil")
	}
	if MTU < 64 || MTU > 65535 || MTU > MaxAllocSize {
		return nil, errors.New("MTU must be between 64 and 65535")
	}

	var cfg *Config
	if len(config) > 0 && config[0] != nil {
		c := *config[0]
		cfg = &c
	} else {
		cfg = DefaultConfig()
	}
	if maxData := uint32(MTU - 17); cfg.MaxFrameDataSize == 0 || cfg.MaxFrameDataSize > maxData {
		cfg.MaxFrameDataSize = maxData
	}

	var udpConn *net.UDPConn
	if u, ok := packetConn.(*net.UDPConn); ok {
		udpConn = u
		_ = u.SetReadBuffer(cfg.SystemPacketReadBuffer)
		_ = u.SetWriteBuffer(cfg.SystemPacketWriteBuffer)
	}

	if ipConn, ok := packetConn.(*net.IPConn); ok {
		_ = ipConn.SetReadBuffer(cfg.SystemPacketReadBuffer)
		_ = ipConn.SetWriteBuffer(cfg.SystemPacketWriteBuffer)
	}

	if ugConn, ok := packetConn.(*net.UnixConn); ok {
		_ = ugConn.SetReadBuffer(cfg.SystemPacketReadBuffer)
		_ = ugConn.SetWriteBuffer(cfg.SystemPacketWriteBuffer)
	}

	ln := &Listener{
		pconn:                     packetConn,
		udpConn:                   udpConn,
		sessionConfig:             cfg,
		handshakeTimeout:          10 * time.Second,
		AllowConnectionResumption: true,
		TransparentResumption:     true,
		ConnectionResumeTimeout:   cfg.ConnectionResumeTimeout,
		sessions:                  make(map[string]*activeSession),
		peerConns:                 make(map[string]*packetSubConn),
		peerUDPConns:              make(map[netip.AddrPort]*packetSubConn),
		peerIPConns:               make(map[netip.Addr]*packetSubConn),
		acceptChan:                make(chan *Session, 64),
		acceptDone:                make(chan struct{}),
		mtu:                       MTU,
		die:                       make(chan struct{}),
	}

	go ln.packetReadLoop(MTU)

	return ln, nil
}

func (ln *Listener) handleIncomingPacketConn(subConn *packetSubConn) {
	activeSess, isResumed, err := ln.handshake(subConn)
	if err != nil {
		_ = subConn.Close()
		return
	}

	if isResumed && ln.TransparentResumption {
		return
	}

	select {
	case <-ln.die:
		_ = subConn.Close()
	case ln.acceptChan <- activeSess.session:
	}
}

// packetReadLoop reads incoming datagrams and routes them with zero allocation on the fast paths.
func (ln *Listener) packetReadLoop(MTU int) {
	bufSize := MTU + 64
	if bufSize > MaxAllocSize {
		bufSize = MaxAllocSize
	}

	for {
		if ln.closed.Load() {
			return
		}
		pBuf := defaultAllocator.Get(bufSize)
		*pBuf = (*pBuf)[:bufSize]

		var n int
		var raddr net.Addr
		var udpAddrPort netip.AddrPort
		var ipAddr netip.Addr
		var isUDP, isIP bool
		var err error

		if ln.udpConn != nil {
			// Fast path 1: 0-alloc UDP ingress via ReadFromUDPAddrPort
			n, udpAddrPort, err = ln.udpConn.ReadFromUDPAddrPort(*pBuf)
			isUDP = true
		} else {
			// Fast path 2: Raw IP / PacketConn
			n, raddr, err = ln.pconn.ReadFrom(*pBuf)
			if err == nil {
				if ip, ok := raddr.(*net.IPAddr); ok {
					if a, ok := netip.AddrFromSlice(ip.IP); ok {
						ipAddr = a.Unmap()
						isIP = true
					}
				}
			}
		}

		if err == nil && n > MTU {
			defaultAllocator.Put(pBuf)
			continue
		}
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

		*pBuf = (*pBuf)[:n]

		// 0-alloc Map Lookup
		var subConn *packetSubConn
		var exists bool

		ln.peerMu.RLock()
		if isUDP {
			subConn, exists = ln.peerUDPConns[udpAddrPort]
		} else if isIP {
			subConn, exists = ln.peerIPConns[ipAddr]
		} else {
			subConn, exists = ln.peerConns[raddr.String()]
		}
		ln.peerMu.RUnlock()

		if exists && !subConn.closed.Load() {
			if subConn.feed(pBuf) != nil {
				_ = defaultAllocator.Put(pBuf)
			}
			continue
		}

		// New client registration
		var remoteAddr net.Addr
		if isUDP {
			remoteAddr = net.UDPAddrFromAddrPort(udpAddrPort)
		} else {
			remoteAddr = raddr
		}

		newSubConn := newPacketSubConn(ln, remoteAddr)
		ln.peerMu.Lock()
		if isUDP {
			ln.peerUDPConns[udpAddrPort] = newSubConn
		} else if isIP {
			ln.peerIPConns[ipAddr] = newSubConn
		}
		ln.peerConns[remoteAddr.String()] = newSubConn
		ln.peerMu.Unlock()

		if newSubConn.feed(pBuf) != nil {
			_ = defaultAllocator.Put(pBuf)
		}
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
	defer func() {
		if s.closed.Load() || s.ln.closed.Load() {
			for {
				_, head, ok := s.queue.Pop()
				if !ok {
					break
				}
				if head != nil {
					_ = defaultAllocator.Put(head)
				}
			}
		}
		s.readMu.Unlock()
	}()

	totalRead := 0

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

	for {
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
			s.waitState.Store(stateIdle)
			return 0, io.ErrClosedPipe
		case <-timerCh:
			s.waitState.Store(stateIdle)
			return 0, os.ErrDeadlineExceeded
		case <-s.notify:
			s.waitState.Store(stateIdle)
		}
	}
}

func (s *packetSubConn) ReadPacket() (*[]byte, error) {
	if s.closed.Load() || s.ln.closed.Load() {
		return nil, io.ErrClosedPipe
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		_, head, ok := s.queue.Pop()
		if ok && head != nil {
			return head, nil
		}

		if s.closed.Load() || s.ln.closed.Load() {
			return nil, io.ErrClosedPipe
		}

		s.waitState.Store(stateWaiting)
		select {
		case <-s.die:
			return nil, io.ErrClosedPipe
		case <-s.notify:
		}
		s.waitState.Store(stateIdle)
	}
}

func (s *packetSubConn) Write(b []byte) (int, error) {
	if s.closed.Load() || (s.ln != nil && s.ln.closed.Load()) {
		return 0, io.ErrClosedPipe
	}
	if s.ln == nil || s.ln.pconn == nil {
		return len(b), nil
	}

	var n int
	var err error
	if s.ln.udpConn != nil && s.udpAddrPort.IsValid() {
		// Fast 0-alloc write for UDP
		n, err = s.ln.udpConn.WriteToUDPAddrPort(b, s.udpAddrPort)
	} else {
		n, err = s.ln.pconn.WriteTo(b, s.remoteAddr)
	}

	if err != nil && isTransientDatagramErr(err) {
		return len(b), nil
	}
	return n, err
}

func (s *packetSubConn) maxDatagramSize() int {
	if s.ln == nil || s.ln.mtu <= 0 {
		return 1400
	}
	return s.ln.mtu
}

func (s *packetSubConn) LocalAddr() net.Addr {
	if s.ln != nil && s.ln.pconn != nil {
		return s.ln.pconn.LocalAddr()
	}
	return nil
}

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

		if s.ln != nil {
			s.ln.peerMu.Lock()
			if s.udpAddrPort.IsValid() {
				delete(s.ln.peerUDPConns, s.udpAddrPort)
			}
			if s.ipAddr.IsValid() {
				delete(s.ln.peerIPConns, s.ipAddr)
			}
			if s.remoteAddr != nil {
				delete(s.ln.peerConns, s.remoteAddr.String())
			}
			s.ln.peerMu.Unlock()
		}

		s.drainRing()
		s.readMu.Lock()
		s.queue.Close()
		s.readMu.Unlock()
	})
	return nil
}

func (s *packetSubConn) drainRing() {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for {
		_, head, ok := s.queue.Pop()
		if !ok {
			break
		}
		if head != nil {
			_ = defaultAllocator.Put(head)
		}
	}
}
