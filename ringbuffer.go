package muxocket

import (
	"sync/atomic"
	"unsafe"
)

const (
	MinChunkCap     = 16       // minimum slots per chunk
	MaxChunkCap     = 64 << 10 // max slots in a chunk
	MaxRecycleSlots = 1 << 10  // max slots allowed in free-list
)

type cacheLinePad struct {
	_ [128 - unsafe.Sizeof(uint64(0))%128]byte
}

type RingBuffer struct {
	//Consumer Private Cacheline
	cChunk     *chunk
	cHead      uint64
	cachedTail uint64
	popped     uint64
	_          cacheLinePad

	//Shared Atomic Total Popped
	totalPopped uint64
	_           cacheLinePad

	//Recycled Chunk Free-List
	freeChunk unsafe.Pointer // *chunk
	_         cacheLinePad

	// Producer Private Cacheline
	pChunk *chunk
	pushed uint64
	_      cacheLinePad

	//Shared Atomic Total Pushed
	totalPushed uint64
	_           cacheLinePad
}

// slot is exactly 32 bytes
// Guaranteed zero cache line splitting across all 64-bit architectures.
type slot struct {
	buf  []byte  // 24B: Data uintptr (8B), Len int (8B), Cap int (8B)
	head *[]byte //  8B: Pointer to buffer
}

type chunk struct {
	slots []slot
	cap   uint64

	_    cacheLinePad
	tail uint64

	next unsafe.Pointer // *chunk
	_    cacheLinePad
}

func newChunk(capacity int) *chunk {
	if capacity < MinChunkCap {
		capacity = MinChunkCap
	}
	cap := 1
	for cap < capacity {
		cap <<= 1
	}
	return &chunk{
		slots: make([]slot, cap),
		cap:   uint64(cap),
	}
}

func NewBufferRing(initialCapacity int) RingBuffer {
	initChunk := newChunk(initialCapacity)
	return RingBuffer{
		cChunk: initChunk,
		pChunk: initChunk,
	}
}

func (r *RingBuffer) Length() int {
	pushed := atomic.LoadUint64(&r.totalPushed)
	popped := atomic.LoadUint64(&r.totalPopped)
	if pushed >= popped {
		return int(pushed - popped)
	}
	return 0
}

func (r *RingBuffer) Push(buf []byte, head *[]byte) {
	pc := r.pChunk

	if pc.tail >= pc.cap {
		var next *chunk
		currentLag := r.Length()

		if currentLag == 0 {
			atomic.StorePointer(&r.freeChunk, nil)
			next = newChunk(MinChunkCap)
		} else {
			// Backlog exists: reuse free-list chunk or allocate larger
			freePtr := atomic.SwapPointer(&r.freeChunk, nil)
			if freePtr != nil {
				next = (*chunk)(freePtr)
				next.tail = 0
				next.next = nil
			} else {
				nextCap := pc.cap
				if currentLag >= int(pc.cap) {
					nextCap = pc.cap * 2
					if nextCap > MaxChunkCap {
						nextCap = MaxChunkCap
					}
				}
				next = newChunk(int(nextCap))
			}
		}

		atomic.StorePointer(&pc.next, unsafe.Pointer(next))
		r.pChunk = next
		pc = next
	}

	idx := pc.tail
	s := &pc.slots[idx]
	s.buf = buf
	s.head = head

	atomic.StoreUint64(&pc.tail, idx+1)

	r.pushed++
	atomic.StoreUint64(&r.totalPushed, r.pushed)
}

// Pop is called ONLY by the Consumer goroutine.
func (r *RingBuffer) Pop() (buf []byte, head *[]byte, ok bool) {
	cc := r.cChunk

	for {
		if r.cHead >= r.cachedTail {
			r.cachedTail = atomic.LoadUint64(&cc.tail)
			if r.cHead >= r.cachedTail {
				if r.cHead >= cc.cap {
					nextPtr := atomic.LoadPointer(&cc.next)
					if nextPtr != nil {
						// Only retain chunks in free-list if <= MaxRecycleSlots
						if cc.cap <= MaxRecycleSlots {
							atomic.StorePointer(&r.freeChunk, unsafe.Pointer(cc))
						}

						cc = (*chunk)(nextPtr)
						r.cChunk = cc
						r.cHead = 0
						r.cachedTail = 0
						continue
					}
				}
				return nil, nil, false
			}
		}
		break
	}

	s := &cc.slots[r.cHead]
	buf = s.buf
	head = s.head
	s.buf = nil
	s.head = nil

	r.cHead++
	r.popped++
	atomic.StoreUint64(&r.totalPopped, r.popped)
	return buf, head, true
}

func (r *RingBuffer) PartialRead(b []byte) (n int, drainedBuf *[]byte) {
	cc := r.cChunk

	for {
		if r.cHead >= r.cachedTail {
			r.cachedTail = atomic.LoadUint64(&cc.tail)
			if r.cHead >= r.cachedTail {
				if r.cHead >= cc.cap {
					nextPtr := atomic.LoadPointer(&cc.next)
					if nextPtr != nil {
						if cc.cap <= MaxRecycleSlots {
							atomic.StorePointer(&r.freeChunk, unsafe.Pointer(cc))
						}

						cc = (*chunk)(nextPtr)
						r.cChunk = cc
						r.cHead = 0
						r.cachedTail = 0
						continue
					}
				}
				return 0, nil
			}
		}
		break
	}

	s := &cc.slots[r.cHead]
	buf := s.buf
	if buf == nil {
		drainedBuf = s.head
		s.buf = nil
		s.head = nil
		r.cHead++
		r.popped++
		atomic.StoreUint64(&r.totalPopped, r.popped)
		return 0, drainedBuf
	}

	n = copy(b, buf)
	s.buf = buf[n:]

	if len(s.buf) == 0 {
		drainedBuf = s.head
		s.buf = nil
		s.head = nil

		r.cHead++
		r.popped++
		atomic.StoreUint64(&r.totalPopped, r.popped)
	}

	return n, drainedBuf
}

// peekSlot returns the consumer's current slot, or nil if the ring is empty.
// Consumer only.
func (r *RingBuffer) peekSlot() *slot {
	cc := r.cChunk
	for {
		if r.cHead >= r.cachedTail {
			r.cachedTail = atomic.LoadUint64(&cc.tail)
			if r.cHead >= r.cachedTail {
				if r.cHead >= cc.cap {
					nextPtr := atomic.LoadPointer(&cc.next)
					if nextPtr != nil {
						if cc.cap <= MaxRecycleSlots {
							atomic.StorePointer(&r.freeChunk, unsafe.Pointer(cc))
						}
						cc = (*chunk)(nextPtr)
						r.cChunk = cc
						r.cHead = 0
						r.cachedTail = 0
						continue
					}
				}
				return nil
			}
		}
		return &cc.slots[r.cHead]
	}
}

func (r *RingBuffer) popSlot(s *slot) *[]byte {
	head := s.head
	s.buf = nil
	s.head = nil
	r.cHead++
	r.popped++
	atomic.StoreUint64(&r.totalPopped, r.popped)
	return head
}

// Peek returns the unread bytes of the oldest buffer without copying them.
// If that buffer is empty it is removed and returned as drained (buf is nil),
// so the caller can recycle it and call Peek again. ok is false when the ring
// is empty. The returned slice stays valid until Advance consumes it.
// Consumer only.
func (r *RingBuffer) Peek() (buf []byte, drained *[]byte, ok bool) {
	s := r.peekSlot()
	if s == nil {
		return nil, nil, false
	}
	if len(s.buf) == 0 {
		return nil, r.popSlot(s), true
	}
	return s.buf, nil, true
}

// Advance consumes n bytes of the buffer returned by Peek. When the buffer is
// fully consumed it is removed and returned for recycling. Consumer only.
func (r *RingBuffer) Advance(n int) (drained *[]byte) {
	s := r.peekSlot()
	if s == nil {
		return nil
	}
	s.buf = s.buf[n:]
	if len(s.buf) == 0 {
		return r.popSlot(s)
	}
	return nil
}
