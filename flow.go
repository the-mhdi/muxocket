package muxocket

import (
	"io"
	"sync/atomic"
)

const (
	DefaultInitialStreamWindow  uint32 = 2 * 1024 * 1024 // 2 MB per channel
	DefaultInitialSessionWindow uint32 = 4 * 1024 * 1024 // 4 MB per session
	DefaultWindowUpdateRatio    uint32 = 4               // Replenish at 1/4 window consumed
)

type StreamFlow struct {
	chID        uint32
	channel     *Channel
	session     *Session
	sendCredits atomic.Int32
	consumed    atomic.Int32
	threshold   int32
	updating    atomic.Uint32
	winNotify   chan struct{}
	waitState   atomic.Uint32
}

func NewStreamFlow(chID uint32, initialWindow int32, ch *Channel, s *Session) *StreamFlow {
	if initialWindow <= 0 {
		initialWindow = int32(DefaultInitialStreamWindow)
	}

	thresh := initialWindow / int32(DefaultWindowUpdateRatio)
	if thresh <= 0 {
		thresh = 1
	}

	sf := &StreamFlow{
		chID:      chID,
		channel:   ch,
		session:   s,
		threshold: thresh,
		winNotify: make(chan struct{}, 1),
	}
	sf.sendCredits.Store(initialWindow)
	return sf
}

func (sf *StreamFlow) AcquireCredits(desired int32) (int32, error) {
	for {
		if sf.channel.closed.Load() || sf.session.isClosed() {
			return 0, io.ErrClosedPipe
		}

		cAvail := sf.sendCredits.Load()
		sAvail := int32(1 << 30)
		if sf.session.flow != nil && sf.session.flow.enabled {
			sAvail = sf.session.flow.sendCredits.Load()
		}

		avail := cAvail
		if sAvail < avail {
			avail = sAvail
		}

		if avail <= 0 {
			sf.waitState.Store(stateWaiting)

			cAvail = sf.sendCredits.Load()
			if sf.session.flow != nil && sf.session.flow.enabled {
				sAvail = sf.session.flow.sendCredits.Load()
			} else {
				sAvail = 1 << 30
			}
			if cAvail > 0 && sAvail > 0 {
				sf.waitState.Store(stateIdle)
				continue
			}

			if sf.channel.closed.Load() || sf.session.isClosed() {
				sf.waitState.Store(stateIdle)
				return 0, io.ErrClosedPipe
			}

			select {
			case <-sf.session.die:
				sf.waitState.Store(stateIdle)
				return 0, ErrSessionClosed
			case <-sf.winNotify:
				sf.waitState.Store(stateIdle)
				continue
			}
		}

		take := desired
		if take > avail {
			take = avail
		}

		if sf.session.flow != nil && sf.session.flow.enabled {
			if !sf.session.flow.TryDeduct(take) {
				continue
			}
		}

		if !sf.TryDeduct(take) {
			if sf.session.flow != nil && sf.session.flow.enabled {
				sf.session.flow.Refund(take)
			}
			continue
		}

		return take, nil
	}
}

func (sf *StreamFlow) TryDeduct(n int32) bool {
	for {
		curr := sf.sendCredits.Load()
		if curr < n {
			return false
		}
		if sf.sendCredits.CompareAndSwap(curr, curr-n) {
			return true
		}
	}
}

func (sf *StreamFlow) Refund(n int32) {
	if n <= 0 {
		return
	}
	sf.sendCredits.Add(n)
	sf.WakeWriter()
	if sf.session.flow != nil && sf.session.flow.enabled {
		sf.session.flow.Refund(n)
	}
}

func (sf *StreamFlow) AddCredits(delta int32) {
	if delta <= 0 {
		return
	}
	sf.sendCredits.Add(delta)
	sf.WakeWriter()
}

func (sf *StreamFlow) WakeWriter() {
	if sf.waitState.Load() == stateWaiting {
		select {
		case sf.winNotify <- struct{}{}:
		default:
		}
	}
}

func (sf *StreamFlow) OnRead(n int) {
	if n <= 0 {
		return
	}
	n32 := int32(n)

	if sf.consumed.Add(n32) >= sf.threshold {
		sf.flushUpdate()
	}

	if sf.session.flow != nil && sf.session.flow.enabled {
		sf.session.flow.OnRead(n32)
	}
}

func (sf *StreamFlow) flushUpdate() {
	if !sf.updating.CompareAndSwap(0, 1) {
		return
	}
	defer sf.updating.Store(0)

	curr := sf.consumed.Load()
	if curr < sf.threshold {
		return
	}
	delta := sf.consumed.Swap(0)
	if delta <= 0 {
		return
	}

	frame := writeFrame{
		flag:   FLG_UPD,
		chID:   sf.chID,
		length: uint32(delta),
		pBuf:   nil,
	}

	sf.session.writeControlFrameNonBlocking(frame)
}

type SessionFlow struct {
	session     *Session
	sendCredits atomic.Int32
	consumed    atomic.Int32
	threshold   int32
	updating    atomic.Uint32
	enabled     bool
}

func NewSessionFlow(initialWindow int32, s *Session) *SessionFlow {
	if initialWindow <= 0 {
		return &SessionFlow{session: s, enabled: false}
	}

	thresh := initialWindow / int32(DefaultWindowUpdateRatio)
	if thresh <= 0 {
		thresh = 1
	}

	sf := &SessionFlow{
		session:   s,
		threshold: thresh,
		enabled:   true,
	}
	sf.sendCredits.Store(initialWindow)
	return sf
}

func (sf *SessionFlow) TryDeduct(n int32) bool {
	for {
		curr := sf.sendCredits.Load()
		if curr < n {
			return false
		}
		if sf.sendCredits.CompareAndSwap(curr, curr-n) {
			return true
		}
	}
}

func (sf *SessionFlow) Refund(n int32) {
	if n <= 0 {
		return
	}
	sf.sendCredits.Add(n)
	sf.session.wakeWaitingChannels()
}

func (sf *SessionFlow) AddCredits(delta int32) {
	if delta <= 0 {
		return
	}
	sf.sendCredits.Add(delta)
	sf.session.wakeWaitingChannels()
}

func (sf *SessionFlow) OnRead(n int32) {
	if sf.consumed.Add(n) >= sf.threshold {
		sf.flushUpdate()
	}
}

func (sf *SessionFlow) flushUpdate() {
	if !sf.updating.CompareAndSwap(0, 1) {
		return
	}
	defer sf.updating.Store(0)

	curr := sf.consumed.Load()
	if curr < sf.threshold {
		return
	}
	delta := sf.consumed.Swap(0)
	if delta <= 0 {
		return
	}

	frame := writeFrame{
		flag:   FLG_UPD,
		chID:   0,
		length: uint32(delta),
		pBuf:   nil,
	}

	sf.session.writeControlFrameNonBlocking(frame)
}
