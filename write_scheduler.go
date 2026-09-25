package muxocket

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type writeFrame struct {
	pBuf   *[]byte
	length uint32
	chID   uint32
	flag   uint8
	offset uint64 // 64-bit stream offset

}
type unackedFrame struct {
	pBuf        *[]byte
	offset      uint64
	length      uint32
	sentAt      time.Time
	retransmits int
}

type reorderFrame struct {
	pBuf   *[]byte
	offset uint64
	length uint32
}
type writeScheduler struct {
	session   *Session
	connMu    sync.RWMutex
	conn      io.Writer
	writes    chan writeFrame
	ctrlQueue chan writeFrame
	closed    atomic.Bool
	die       chan struct{}
	// wg        sync.WaitGroup
}

func newWriteScheduler(s *Session, conn io.Writer, queueDepth int) *writeScheduler {
	if queueDepth <= 0 {
		queueDepth = 128
	}

	ws := &writeScheduler{
		session:   s,
		conn:      conn,
		writes:    make(chan writeFrame, queueDepth),
		ctrlQueue: make(chan writeFrame, 64),
		die:       make(chan struct{}),
	}

	//ws.wg.Add(1)
	go ws.writeLoop()
	return ws
}

func (ws *writeScheduler) alterConn(conn io.Writer) {
	ws.connMu.Lock()
	ws.conn = conn
	ws.connMu.Unlock()
}

func (ws *writeScheduler) writeLoop() {

	//defer ws.wg.Done()

	var (
		hdrs      [maxBatchFrames][17]byte
		rawBufs   [maxBatchFrames * 2][]byte
		frameRefs [maxBatchFrames]writeFrame
	)

	for {
		var firstFrame writeFrame

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

		for batchCount < maxBatchFrames {
			select {
			case cf := <-ws.ctrlQueue:
				frameRefs[batchCount] = cf
				batchCount++
			case f := <-ws.writes:
				frameRefs[batchCount] = f
				batchCount++
			case <-ws.die:
				ws.drainAndCleanup()
				return
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

			//if ws.session.config.Reliable {
			binary.BigEndian.PutUint64(h[9:17], f.offset)
			//}

			bufSlice = append(bufSlice, h[:17])
			if f.length > 0 && f.pBuf != nil {
				bufSlice = append(bufSlice, (*f.pBuf)[:f.length])
			}
		}

		ws.connMu.RLock()
		writer := ws.conn
		ws.connMu.RUnlock()

		if writer == nil {
			continue
		}

		netBuf := net.Buffers(bufSlice)
		_, err := netBuf.WriteTo(writer)

		// Deallocate slab buffers immediately ONLY if ARQ is disabled.
		// If ARQ is active, slab buffers remain referenced in unacked queue.
		for i := 0; i < batchCount; i++ {
			if frameRefs[i].pBuf != nil {
				if !ws.session.config.Reliability || frameRefs[i].flag != FLG_DATA {
					defaultAllocator.Put(frameRefs[i].pBuf)
				}
				frameRefs[i].pBuf = nil
			}
		}

		if err != nil {
			ws.session.handleDisconnect()
			return
		}
	}
}

func (ws *writeScheduler) drainAndCleanup() {
	for {
		select {
		case f := <-ws.writes:
			if f.pBuf != nil && !ws.session.config.Reliability {
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
		//ws.wg.Wait()
	}
}
