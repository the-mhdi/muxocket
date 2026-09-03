package muxocket

type Flow interface {
	// sender side flow control.

	// Blocks until at least some credit is available.
	Acquire(n int) (int, error)

	// Return unused acquired credit if the write didn't happen.
	Release(n int)

	// Called after bytes are actually written.
	Sent(n int)

	// receiver side(inbound) flow control.

	// Called when bytes arrive from the peer.
	Receive(n int) error

	// Called when the application consumes received bytes.
	// May produce a WINDOW_UPDATE to send to the peer.
	Consume(n int) (update uint64, ok bool)

	// Peer increased our send window.
	Update(limit uint64)

	Close() error
}
