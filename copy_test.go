package muxocket

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func pipePairCfg(t *testing.T, cfg *Config) (*Session, *Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	cfg1, cfg2 := *cfg, *cfg
	s1 := NewSession(c1, &cfg1)
	s2 := NewSession(c2, &cfg2)
	t.Cleanup(func() { s1.Close(); s2.Close() })
	return s1, s2
}

func randBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func waitErr(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: timeout", what)
		return nil
	}
}

// Full tunnel shape: TCP -> io.Copy -> channel ... channel -> io.Copy -> TCP.
// io.Copy(ch, tcp) goes through TCPConn.WriteTo's fallback into ch.ReadFrom,
// io.Copy(tcp, ch) uses ch.WriteTo.
func tunnelRoundTrip(t *testing.T, s1, s2 *Session) {
	t.Helper()
	srcA, srcB, cleanA := createRawTCPPair(t) // app writes srcA, tunnel reads srcB
	defer cleanA()
	dstA, dstB, cleanB := createRawTCPPair(t) // tunnel writes dstA, app reads dstB
	defer cleanB()

	a, _ := s1.OpenChannel("tun")
	b, _ := s2.OpenChannel("tun")

	want := randBytes(5<<20+12345, 7)
	errs := make(chan error, 3)
	go func() {
		_, err := io.Copy(a, srcB)
		a.CloseWrite()
		errs <- err
	}()
	go func() {
		_, err := io.Copy(dstA, b)
		dstA.(*net.TCPConn).CloseWrite()
		errs <- err
	}()
	go func() {
		_, err := srcA.Write(want)
		srcA.(*net.TCPConn).CloseWrite()
		errs <- err
	}()

	got, err := io.ReadAll(dstB)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := waitErr(t, errs, "copy"); err != nil {
			t.Fatal(err)
		}
	}
	if sha256.Sum256(got) != sha256.Sum256(want) {
		t.Fatalf("data mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestCopy_TCPTunnel(t *testing.T) {
	s1, s2, cleanup := createTCPSessionPair(t)
	defer cleanup()
	tunnelRoundTrip(t, s1, s2)
}

func TestCopy_TCPTunnel_Reliable(t *testing.T) {
	s1, s2, cleanup := createReliableTCPSessionPair(t)
	defer cleanup()
	tunnelRoundTrip(t, s1, s2)
}

// Odd read sizes (1 byte, halves, data+EOF together) and a tiny window that
// forces sendFromRead to split reads across partial credit grants.
func TestReadFrom_ReadShapesAndSmallWindow(t *testing.T) {
	shapes := map[string]func(io.Reader) io.Reader{
		"one":  iotest.OneByteReader,
		"half": iotest.HalfReader,
		"eof":  iotest.DataErrReader,
		"full": func(r io.Reader) io.Reader { return r },
	}
	for _, reliable := range []bool{false, true} {
		for name, shape := range shapes {
			cfg := DefaultConfig()
			cfg.Reliability = reliable
			cfg.InitialStreamWindow = 10000 // not a multiple of anything
			s1, s2 := pipePairCfg(t, cfg)
			a, _ := s1.OpenChannel("rf")
			b, _ := s2.OpenChannel("rf")

			size := 300 << 10
			if name == "one" {
				size = 20 << 10
			}
			want := randBytes(size, int64(len(name)))
			errs := make(chan error, 1)
			go func() {
				n, err := a.ReadFrom(shape(bytes.NewReader(want)))
				if err == nil && n != int64(len(want)) {
					err = errors.New("short ReadFrom count")
				}
				a.CloseWrite()
				errs <- err
			}()
			got, err := io.ReadAll(b)
			if err != nil {
				t.Fatal(err)
			}
			if err := waitErr(t, errs, name); err != nil {
				t.Fatalf("reliable=%v %s: %v", reliable, name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("reliable=%v %s: mismatch (%d vs %d bytes)", reliable, name, len(got), len(want))
			}
		}
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadFrom_Errors(t *testing.T) {
	s1, s2 := pipePairCfg(t, DefaultConfig())
	a, _ := s1.OpenChannel("rfe")
	s2.OpenChannel("rfe")

	boom := errors.New("boom")
	if _, err := a.ReadFrom(errReader{boom}); err != boom {
		t.Fatalf("want reader error, got %v", err)
	}
	a.CloseWrite()
	if _, err := a.ReadFrom(bytes.NewReader([]byte("x"))); err != io.ErrClosedPipe {
		t.Fatalf("want ErrClosedPipe after CloseWrite, got %v", err)
	}
}

// ReadFrom blocked on an idle reader must not hold send credit.
func TestReadFrom_IdleReaderHoldsNoCredit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InitialStreamWindow = 64 << 10
	s1, s2 := pipePairCfg(t, cfg)
	a, _ := s1.OpenChannel("idle")
	b, _ := s2.OpenChannel("idle")

	pr, pw := io.Pipe()
	go a.ReadFrom(pr) // blocks in pr.Read
	time.Sleep(50 * time.Millisecond)

	done := make(chan error, 1)
	go func() { _, err := a.Write(make([]byte, 64<<10)); done <- err }() // whole window
	go io.Copy(io.Discard, b)
	if err := waitErr(t, done, "Write alongside idle ReadFrom"); err != nil {
		t.Fatal(err)
	}
	pw.Close()
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

type failWriter struct{ after int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("disk full")
	}
	if len(p) > w.after {
		p = p[:w.after]
	}
	w.after -= len(p)
	return len(p), nil
}

func TestWriteTo_WriterErrors(t *testing.T) {
	s1, s2 := pipePairCfg(t, DefaultConfig())
	a, _ := s1.OpenChannel("wte")
	b, _ := s2.OpenChannel("wte")
	a.Write([]byte("0123456789"))

	if _, err := b.WriteTo(shortWriter{}); err != io.ErrShortWrite {
		t.Fatalf("want ErrShortWrite, got %v", err)
	}
	// 5 bytes were accepted; the rest must still be readable in order.
	a.Write([]byte("abc"))
	fw := &failWriter{after: 3}
	n, err := b.WriteTo(fw)
	if err == nil || n != 3 {
		t.Fatalf("want 3 bytes then error, got %d, %v", n, err)
	}
	a.CloseWrite()
	rest, err := io.ReadAll(b)
	if err != nil || string(rest) != "89abc" {
		t.Fatalf("remaining data %q, %v; want \"89abc\"", rest, err)
	}
}

func TestWriteTo_EOFAndClose(t *testing.T) {
	s1, s2 := pipePairCfg(t, DefaultConfig())
	a, _ := s1.OpenChannel("wtc")
	b, _ := s2.OpenChannel("wtc")

	// Peer CloseWrite -> WriteTo returns nil with everything written.
	want := randBytes(200<<10, 3)
	go func() { a.Write(want); a.CloseWrite() }()
	var got bytes.Buffer
	if n, err := b.WriteTo(&got); err != nil || n != int64(len(want)) || !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("WriteTo = %d, %v (match=%v)", n, err, bytes.Equal(got.Bytes(), want))
	}

	// Local Close while WriteTo waits -> returns promptly.
	c, _ := s1.OpenChannel("wtc2")
	d, _ := s2.OpenChannel("wtc2")
	_ = c
	done := make(chan error, 1)
	go func() { _, err := d.WriteTo(io.Discard); done <- err }()
	time.Sleep(50 * time.Millisecond)
	d.Close()
	if err := waitErr(t, done, "WriteTo after Close"); err != io.ErrClosedPipe {
		t.Fatalf("want ErrClosedPipe, got %v", err)
	}
}

// A slow destination must throttle the sender via flow control (credit is
// returned only after w accepts the bytes), with no data loss.
type slowWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *slowWriter) Write(p []byte) (int, error) {
	time.Sleep(200 * time.Microsecond)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func TestWriteTo_SlowWriterBackpressure(t *testing.T) {
	// Small window: tests throttling. Default window: many frames arrive (and
	// reuse pooled buffers) while w is still busy with the current one, so
	// recycling a buffer before w is done with it would corrupt the output.
	for _, tc := range []struct {
		reliable bool
		window   uint32
	}{{false, 48 << 10}, {true, 48 << 10}, {false, 0}, {true, 0}} {
		reliable := tc.reliable
		cfg := DefaultConfig()
		cfg.Reliability = reliable
		if tc.window != 0 {
			cfg.InitialStreamWindow = tc.window
		}
		s1, s2 := pipePairCfg(t, cfg)
		a, _ := s1.OpenChannel("slow")
		b, _ := s2.OpenChannel("slow")

		want := randBytes(2<<20, 11)
		go func() { a.ReadFrom(bytes.NewReader(want)); a.CloseWrite() }()
		w := &slowWriter{}
		if _, err := b.WriteTo(w); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(w.buf.Bytes(), want) {
			t.Fatalf("reliable=%v window=%d: mismatch", reliable, tc.window)
		}
	}
}

// Channel -> channel relay (io.Copy picks src.WriteTo, which writes into the
// other channel's Write), plus ReadFrom racing a plain Write on one channel.
func TestCopy_ChannelRelayAndConcurrentWriters(t *testing.T) {
	s1, s2 := pipePairCfg(t, DefaultConfig())
	s3, s4 := pipePairCfg(t, DefaultConfig())
	in1, _ := s1.OpenChannel("r1")
	out1, _ := s2.OpenChannel("r1")
	in2, _ := s3.OpenChannel("r2")
	out2, _ := s4.OpenChannel("r2")

	go func() { io.Copy(in2, out1); in2.CloseWrite() }() // relay

	partA := bytes.Repeat([]byte{0xAA}, 1<<20)
	partB := bytes.Repeat([]byte{0xBB}, 1<<20+7)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); in1.ReadFrom(iotest.HalfReader(bytes.NewReader(partA))) }()
	go func() { defer wg.Done(); in1.Write(partB) }()
	go func() { wg.Wait(); in1.CloseWrite() }()

	got, err := io.ReadAll(out2)
	if err != nil {
		t.Fatal(err)
	}
	if na, nb := bytes.Count(got, []byte{0xAA}), bytes.Count(got, []byte{0xBB}); na != len(partA) || nb != len(partB) || na+nb != len(got) {
		t.Fatalf("got %d/%d bytes of A/B (total %d), want %d/%d", na, nb, len(got), len(partA), len(partB))
	}
}

func TestCopy_ChannelRelayExact(t *testing.T) {
	s1, s2 := pipePairCfg(t, DefaultConfig())
	cfg := DefaultConfig()
	cfg.Reliability = true
	s3, s4 := pipePairCfg(t, cfg)
	in1, _ := s1.OpenChannel("x1")
	out1, _ := s2.OpenChannel("x1")
	in2, _ := s3.OpenChannel("x2")
	out2, _ := s4.OpenChannel("x2")

	go func() { io.Copy(in2, out1); in2.CloseWrite() }()
	want := randBytes(3<<20+5, 5)
	go func() { io.Copy(in1, bytes.NewReader(want)); in1.CloseWrite() }()
	var got bytes.Buffer
	if _, err := io.Copy(&got, out2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("relay mismatch")
	}
}
