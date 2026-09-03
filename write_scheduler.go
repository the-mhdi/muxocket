package muxocket

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

type writeFrame struct {
	pBuf   *[]byte
	length uint32
	chID   uint32
	flag   uint8
}

type writeScheduler struct {
	session   *Session
	conn      io.Writer
	writes    chan writeFrame
	ctrlQueue chan writeFrame
	closed    atomic.Bool
	die       chan struct{}
	wg        sync.WaitGroup
}

func newWriteScheduler(s *Session, conn io.Writer, queueDepth int) *writeScheduler {
	if queueDepth <= 0 {
		queueDepth = 128
	}

	ws := &writeScheduler{
		session:   s,
		conn:      conn,
		writes:    make(chan writeFrame, queueDepth),
		ctrlQueue: make(chan writeFrame, 16),
		die:       make(chan struct{}),
	}

	ws.wg.Add(1)
	go ws.writeLoop()
	return ws
}

func (ws *writeScheduler) writeLoop() {
	defer ws.wg.Done()

	var (
		hdrs      [maxBatchFrames][9]byte
		rawBufs   [maxBatchFrames * 2][]byte
		frameRefs [maxBatchFrames]writeFrame
	)

	for {
		var firstFrame writeFrame

		// 1. Session-level control frames (PING, etc.) have priority
		select {
		case <-ws.die:
			ws.drainAndCleanup()
			return
		case cf := <-ws.ctrlQueue:
			firstFrame = cf
		default:
			select {
			case <-ws.die:
				ws.drainAndCleanup()
				return
			case cf := <-ws.ctrlQueue:
				firstFrame = cf
			case f := <-ws.writes:
				firstFrame = f
			}
		}

		frameRefs[0] = firstFrame
		batchCount := 1

		// 2. Coalesce up to maxBatchFrames
		for batchCount < maxBatchFrames {
			select {
			case cf := <-ws.ctrlQueue:
				frameRefs[batchCount] = cf
				batchCount++
			case f := <-ws.writes:
				frameRefs[batchCount] = f
				batchCount++
			default:
				goto FLUSH
			}
		}

	FLUSH:
		bufSlice := rawBufs[:0]
		for i := 0; i < batchCount; i++ {
			f := &frameRefs[i]
			h := &hdrs[i]

			binary.BigEndian.PutUint32(h[0:4], f.length)
			h[4] = f.flag
			binary.BigEndian.PutUint32(h[5:9], f.chID)

			bufSlice = append(bufSlice, h[:])
			if f.length > 0 && f.pBuf != nil {
				bufSlice = append(bufSlice, (*f.pBuf)[:f.length])
			}
		}

		netBuf := net.Buffers(bufSlice)
		_, err := netBuf.WriteTo(ws.conn)

		for i := 0; i < batchCount; i++ {
			if frameRefs[i].pBuf != nil {
				defaultAllocator.Put(frameRefs[i].pBuf)
				frameRefs[i].pBuf = nil
			}
		}

		if err != nil {
			go ws.session.Close()
			ws.drainAndCleanup()
			return
		}
	}
}

func (ws *writeScheduler) drainAndCleanup() {
	for {
		select {
		case f := <-ws.writes:
			if f.pBuf != nil {
				defaultAllocator.Put(f.pBuf)
			}
		case cf := <-ws.ctrlQueue:
			if cf.pBuf != nil {
				defaultAllocator.Put(cf.pBuf)
			}
		default:
			return
		}
	}
}

func (ws *writeScheduler) Close() {
	if ws.closed.CompareAndSwap(false, true) {
		close(ws.die)
		ws.wg.Wait()
	}
}
