package mux

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/frand"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func newTestingPair(tb testing.TB) (dialed, accepted *Mux) {
	dialed, accepted = newTestingPairCustom(tb, nil)
	return
}

func newTestingPairCustom(tb testing.TB, wrapConn func(net.Conn) net.Conn) (dialed, accepted *Mux) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	errChan := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err == nil {
			accepted, err = AcceptAnonymous(conn, 3)
		}
		errChan <- err
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	if wrapConn != nil {
		conn = wrapConn(conn)
	}
	dialed, err = DialAnonymous(conn)
	if err != nil {
		tb.Fatal(err)
	}
	if err := <-errChan; err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		dialed.Close()
		accepted.Close()
	})

	return
}

func handleStreams(m *Mux, fn func(*Stream) error) chan error {
	errChan := make(chan error, 1)
	go func() {
		for {
			s, err := m.AcceptStream()
			if err != nil {
				select {
				case errChan <- err:
				default:
				}
				return
			}
			go func() {
				defer s.Close()
				if err := fn(s); err != nil {
					select {
					case errChan <- err:
					default:
					}
					return
				}
			}()
		}
	}()
	return errChan
}

// blockConn simulates TCP backpressure by blocking writes on demand
type blockConn struct {
	net.Conn

	closeOnce sync.Once
	blockCh   chan struct{} // close to make writes block
	blockedCh chan struct{} // signaled when a write is waiting
	closeCh   chan struct{} // closed by Close to release blocked writes
}

func newBlockConn(c net.Conn) *blockConn {
	return &blockConn{
		Conn:      c,
		blockCh:   make(chan struct{}),
		blockedCh: make(chan struct{}, 1),
		closeCh:   make(chan struct{}),
	}
}

func (c *blockConn) Write(b []byte) (int, error) {
	select {
	case <-c.blockCh:
		select {
		case c.blockedCh <- struct{}{}:
		default:
		}
		<-c.closeCh
		return 0, net.ErrClosed
	default:
		return c.Conn.Write(b)
	}
}

func (c *blockConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	return c.Conn.Close()
}

// A testPeer is the peer of a Mux created by newPipeMux, simulated by the
// test: it writes frames with writeFrames and reads them with nextFrame.
type testPeer struct {
	*packetReader
	conn net.Conn
}

// newPipeMux returns a Mux, using defaultConnSettings, and its simulated peer.
// Like newPipePair, it works inside a synctest bubble.
func newPipeMux(tb testing.TB) (*Mux, *testPeer) {
	c1, c2 := net.Pipe()
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	m := newMux(c1, &seqCipher{aead: aead}, defaultConnSettings)
	tb.Cleanup(func() {
		m.Close()
		c2.Close()
	})
	return m, &testPeer{
		packetReader: &packetReader{
			r:          c2,
			cipher:     &seqCipher{aead: aead},
			packetSize: defaultConnSettings.PacketSize,
			buf:        make([]byte, 0, defaultConnSettings.PacketSize*10),
		},
		conn: c2,
	}
}

// blockWriteLoop dials a stream and writes to it, then waits for the writeLoop
// to block on the unread pipe, so that subsequent frames stay buffered.
func blockWriteLoop(tb testing.TB, m *Mux) *Stream {
	tb.Helper()
	s := m.DialStream()
	if _, err := s.Write([]byte{1}); err != nil {
		tb.Fatal(err)
	}
	synctest.Wait()
	return s
}

// writeFrames writes frames to the Mux as a single packet.
func (p *testPeer) writeFrames(tb testing.TB, frames ...[]byte) {
	tb.Helper()
	settings := defaultConnSettings
	buf := make([]byte, settings.maxFrameSize()) // zeroes are padding
	off := 0
	for _, f := range frames {
		off += copy(buf[off:], f)
	}
	packet := encryptPackets(make([]byte, settings.PacketSize), buf, settings.PacketSize, p.cipher)
	if _, err := p.conn.Write(packet); err != nil {
		tb.Fatal(err)
	}
}

// encodeFrame returns a frame with the given header fields and payload.
func encodeFrame(id uint32, flags uint16, payload ...byte) []byte {
	h := frameHeader{id: id, flags: flags, length: uint16(len(payload))}
	return appendFrame(make([]byte, 0, frameHeaderSize+len(payload)), h, payload)
}

func TestMux(t *testing.T) {
	serverKey := ed25519.NewKeyFromSeed(frand.Bytes(ed25519.SeedSize))
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := Accept(conn, serverKey)
			if err != nil {
				return err
			}
			defer m.Close()
			s, err := m.AcceptStream()
			if err != nil {
				return err
			}
			defer s.Close()
			buf := make([]byte, 100)
			if n, err := s.Read(buf); err != nil {
				return err
			} else if _, err := fmt.Fprintf(s, "hello, %s!", buf[:n]); err != nil {
				return err
			}
			io.Copy(io.Discard, s) // blocks until the client closes, ensuring we can read what the server wrote before the mux is closed
			return s.Close()
		}()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := m.DialStream()
	defer s.Close()
	buf := make([]byte, 100)
	if _, err := s.Write([]byte("world")); err != nil {
		t.Fatal(err)
	} else if n, err := io.ReadFull(s, buf[:13]); err != nil {
		t.Fatal(err)
	} else if string(buf[:n]) != "hello, world!" {
		t.Fatal("bad hello:", string(buf[:n]))
	}
	if err := s.Close(); err != nil && err != ErrPeerClosedConn {
		t.Fatal(err)
	}

	if err := <-serverCh; err != nil && err != ErrPeerClosedStream {
		t.Fatal(err)
	}

	// all streams should have been deleted
	time.Sleep(time.Millisecond * 100)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.streams) != 0 {
		t.Error("streams not closed")
	}
}

func TestManyStreams(t *testing.T) {
	m1, m2 := newTestingPair(t)

	serverCh := handleStreams(m2, func(s *Stream) error {
		// simple echo handler
		buf := make([]byte, 100)
		n, _ := s.Read(buf)
		s.Write(buf[:n])
		return nil
	})

	// spawn 100 streams
	var wg sync.WaitGroup
	errChan := make(chan error, 100)
	for i := 0; i < cap(errChan); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := m1.DialStream()
			defer s.Close()
			msg := fmt.Sprintf("hello, %v!", i)
			buf := make([]byte, len(msg))
			if _, err := s.Write([]byte(msg)); err != nil {
				errChan <- err
			} else if _, err := io.ReadFull(s, buf); err != nil {
				errChan <- err
			} else if string(buf) != msg {
				errChan <- err
			} else if err := s.Close(); err != nil {
				errChan <- err
			}
		}(i)
	}
	wg.Wait()
	close(errChan)
	for err := range errChan {
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := m1.Close(); err != nil {
		t.Fatal(err)
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedConn {
		t.Fatal(err)
	}

	// all streams should have been deleted
	time.Sleep(time.Millisecond * 100)
	m1.mu.Lock()
	defer m1.mu.Unlock()
	if len(m1.streams) != 0 {
		t.Error("streams not closed:", len(m1.streams))
	}
}

func TestDeadline(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	m1, m2 := newTestingPair(t)

	serverCh := handleStreams(m2, func(s *Stream) error {
		// wait 100ms before reading/writing
		buf := make([]byte, 100)
		time.Sleep(100 * time.Millisecond)
		if _, err := s.Read(buf); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
		if _, err := s.Write([]byte("hello, world!")); err != nil {
			return err
		} else if err := s.Close(); err != nil {
			return err
		}
		return nil
	})

	// a Read deadline should not timeout a Write
	s := m1.DialStream()
	buf := []byte("hello, world!")
	s.SetReadDeadline(time.Now().Add(time.Millisecond))
	time.Sleep(2 * time.Millisecond)
	_, err := s.Write(buf)
	s.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatal("SetReadDeadline caused Write to fail:", err)
	} else if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatal(err)
	} else if string(buf) != "hello, world!" {
		t.Fatal("bad echo")
	} else if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		timeout bool
		fn      func(*Stream)
	}{
		{false, func(*Stream) {}}, // no deadline
		{false, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Hour)) // plenty of time
		}},
		{true, func(s *Stream) {
			s.SetDeadline(time.Now()) // too short
		}},
		{true, func(s *Stream) {
			s.SetDeadline(time.Now())
			s.SetReadDeadline(time.Time{}) // Write should still fail
		}},
		{true, func(s *Stream) {
			s.SetDeadline(time.Now())
			s.SetWriteDeadline(time.Time{}) // Read should still fail
		}},
		{false, func(s *Stream) {
			s.SetDeadline(time.Now())
			s.SetDeadline(time.Time{}) // should overwrite
		}},
		{false, func(s *Stream) {
			s.SetDeadline(time.Now())
			s.SetWriteDeadline(time.Time{}) // overwrites Read
			s.SetReadDeadline(time.Time{})  // overwrites Write
		}},
	}
	for i, test := range tests {
		err := func() error {
			s := m1.DialStream()
			defer s.Close()
			if _, err := s.Write([]byte{0}); err != nil {
				// establish stream before setting deadlines to avoid the server
				// getting an "received packet for unknown stream" error. That
				// happens when the first write fails due to the timeout and
				// then Close sending the final frame that isn't known to the
				// peer.
				return err
			}
			test.fn(s) // set deadlines

			// need to write a fairly large message; otherwise the packets just
			// get buffered and "succeed" instantly
			if _, err := s.Write(make([]byte, m1.settings.PacketSize*20)); err != nil {
				return err
			} else if _, err := io.ReadFull(s, buf[:13]); err != nil {
				return err
			} else if string(buf) != "hello, world!" {
				return errors.New("bad echo")
			}
			return s.Close()
		}()
		if isTimeout := errors.Is(err, os.ErrDeadlineExceeded); test.timeout != isTimeout {
			t.Errorf("test %v: expected timeout=%v, got %v", i, test.timeout, err)
		}
	}

	if err := m1.Close(); err != nil {
		t.Fatal(err)
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedConn && err != ErrPeerClosedStream {
		t.Fatal(err)
	}
}

// TestSetWriteDeadlineDuringWrite checks, under the race detector, that Write
// reads the write deadline while holding the Stream's lock, so that it does not
// race with SetWriteDeadline.
func TestSetWriteDeadlineDuringWrite(t *testing.T) {
	m1, m2 := newTestingPair(t)
	handleStreams(m2, func(s *Stream) error {
		io.Copy(io.Discard, s)
		return nil
	})

	s := m1.DialStream()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			s.SetWriteDeadline(time.Now().Add(time.Minute))
		}
	})
	for range 100 {
		if _, err := s.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestContext(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	const testTimeout = 5 * time.Second
	waitErr := func(name string, ch <-chan error) error {
		select {
		case err := <-ch:
			return err
		case <-time.After(testTimeout):
			return fmt.Errorf("timed out waiting for %s", name)
		}
	}
	m1, m2 := newTestingPair(t)

	serverCh := handleStreams(m2, func(s *Stream) error {
		// wait 250ms before reading
		time.Sleep(250 * time.Millisecond)
		var n uint64
		if err := binary.Read(s, binary.LittleEndian, &n); err != nil {
			return err
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(s, buf); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}

		// wait 250ms before replying
		time.Sleep(250 * time.Millisecond)
		echo := make([]byte, len(buf)+8)
		binary.LittleEndian.PutUint64(echo, n)
		copy(echo[8:], buf)
		if _, err := s.Write(echo); err != nil {
			return err
		}
		return nil
	})

	tests := []struct {
		err     error
		context func() context.Context
	}{
		{nil, func() context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
			t.Cleanup(cancel)
			return ctx
		}},
		{context.Canceled, func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
		{context.Canceled, func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(time.Millisecond*5, cancel)
			return ctx
		}},
		{context.DeadlineExceeded, func() context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*5)
			t.Cleanup(cancel)
			return ctx
		}},
	}
	for i, test := range tests {
		err := func() error {
			s := m1.DialStreamContext(test.context())
			defer s.Close()

			msg := make([]byte, m1.settings.PacketSize*10+8)
			frand.Read(msg[8 : 128+8])
			binary.LittleEndian.PutUint64(msg, uint64(len(msg)-8))
			if _, err := s.Write(msg); err != nil {
				return fmt.Errorf("write: %w", err)
			}

			resp := make([]byte, len(msg))
			if _, err := io.ReadFull(s, resp); err != nil {
				return fmt.Errorf("read: %w", err)
			} else if !bytes.Equal(msg, resp) {
				return errors.New("bad echo")
			}
			return s.Close()
		}()
		if !errors.Is(err, test.err) {
			t.Fatalf("test %v: expected error %v, got %v", i, test.err, err)
		}
	}

	if err := m1.Close(); err != nil {
		t.Fatal(err)
	} else if err := waitErr("server", serverCh); err != nil &&
		err != ErrPeerClosedConn &&
		err != ErrPeerClosedStream {
		m2.Close()
		t.Fatal(err)
	}
}

type statsConn struct {
	r, w int32
	net.Conn
}

func (c *statsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt32(&c.r, int32(n))
	return n, err
}

func (c *statsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt32(&c.w, int32(n))
	return n, err
}

func TestCovertStream(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	const testTimeout = 5 * time.Second
	waitErr := func(name string, ch <-chan error) error {
		select {
		case err := <-ch:
			return err
		case <-time.After(testTimeout):
			return fmt.Errorf("timed out waiting for %s", name)
		}
	}
	waitReady := func(name string, ch <-chan struct{}) error {
		select {
		case <-ch:
			return nil
		case <-time.After(testTimeout):
			return fmt.Errorf("timed out waiting for %s", name)
		}
	}

	clientDone := make(chan struct{})
	var signalClientDoneOnce sync.Once
	signalClientDone := func() {
		signalClientDoneOnce.Do(func() { close(clientDone) })
	}
	defer signalClientDone()

	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := AcceptAnonymous(conn, 3)
			if err != nil {
				return err
			}
			defer m.Close()
			// regular stream arrives first since covert data is in the padding
			s, err := m.AcceptStream()
			if err != nil {
				return err
			}
			defer s.Close()

			// read s in a goroutine to unblock the readLoop for the covert frame
			type readRes struct {
				data []byte
				err  error
			}
			readChan := make(chan readRes, 1)
			go func() {
				buf := make([]byte, 100)
				n, err := s.Read(buf)
				readChan <- readRes{buf[:n], err}
			}()

			// accept covert stream
			cs, err := m.AcceptStream()
			if err != nil {
				return err
			}
			defer cs.Close()

			// respond to covert stream
			buf := make([]byte, 100)
			n, err := cs.Read(buf)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cs, "hello, %s!", buf[:n]); err != nil {
				return err
			}
			if err := cs.Close(); err != nil {
				return err
			}

			// respond to regular stream
			res := <-readChan
			if res.err != nil {
				return res.err
			}
			if _, err := fmt.Fprintf(s, "hello, %s!", res.data); err != nil {
				return err
			}
			select {
			case <-clientDone:
			case <-time.After(testTimeout):
				return errors.New("timed out waiting for client to read responses")
			}
			return m.Close()
		}()
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn = &statsConn{Conn: conn} // track raw number of bytes on wire

	m, err := DialAnonymous(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	covertCh := make(chan error, 1)
	bufChan := make(chan struct{})
	go func() {
		s := m.DialCovertStream()
		defer s.Close()
		buf := make([]byte, 100)
		if _, err := s.Write([]byte("covert")); err != nil {
			covertCh <- err
			return
		}
		bufChan <- struct{}{}
		if n, err := io.ReadFull(s, buf[:14]); err != nil {
			covertCh <- err
		} else if string(buf[:n]) != "hello, covert!" {
			covertCh <- fmt.Errorf("bad hello: %s %x", buf[:n], buf[:n])
		} else {
			covertCh <- s.Close()
		}
	}()

	// to generate padding for covert stream, send a regular packet
	s := m.DialStream()
	if err := waitReady("covert stream to buffer", bufChan); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	if _, err := s.Write([]byte("world")); err != nil {
		t.Log(waitErr("server", serverCh))
		t.Fatal(err)
	} else if n, err := io.ReadFull(s, buf[:13]); err != nil {
		t.Log(waitErr("server", serverCh))
		t.Fatal(err)
	} else if string(buf[:n]) != "hello, world!" {
		t.Fatalf("bad hello: %s", buf[:n])
	}

	if err := waitErr("covert stream", covertCh); err != nil && err != ErrPeerClosedConn {
		t.Fatal(err)
	}
	signalClientDone()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	} else if err := waitErr("server", serverCh); err != nil && err != ErrPeerClosedStream {
		t.Fatal(err)
	}
	// amount of data transferred should be the same as without covert stream
	expWritten := 32 + // key exchange
		connSettingsSize + chachaPoly1305TagSize + // settings
		m.settings.PacketSize // "world"

	expRead := 32 + 64 + // key exchange
		connSettingsSize + chachaPoly1305TagSize + // settings
		m.settings.PacketSize // "hello, world!"

	w := int(atomic.LoadInt32(&conn.(*statsConn).w))
	r := int(atomic.LoadInt32(&conn.(*statsConn).r))

	// NOTE: either peer may have sent the Close packet, or both; we don't care
	// either way
	if w > expWritten {
		expWritten += m.settings.PacketSize
	}
	if r > expRead {
		expRead += m.settings.PacketSize
	}
	if w != expWritten {
		t.Errorf("wrote %v bytes, expected %v", w, expWritten)
	}
	if r != expRead {
		t.Errorf("read %v bytes, expected %v", r, expRead)
	}
}

func TestWriteAfterStreamClose(t *testing.T) {
	m1, m2 := newTestingPair(t)

	_ = handleStreams(m2, func(s *Stream) error {
		defer s.Close()
		// simple echo handler
		buf := make([]byte, 100)
		n, err := s.Read(buf)
		if err != nil {
			return err
		} else if _, err := s.Write(buf[:n]); err != nil {
			return err
		}
		return nil
	})

	s := m1.DialStream()

	if _, err := s.Write([]byte("hello, world!")); err != nil {
		t.Fatal(err)
	}

	for i := range maxClosedFrames + 1 {
		if _, err := fmt.Fprintf(s, "foo bar {%d}!", i); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1 * time.Millisecond)
	}

	// a large write on a new client stream should fail. A smaller write might
	// succeed since stream.Write doesn't guarantee that the internal buffer was
	// flushed successfully.
	s2 := m1.DialStream()
	if _, err := s2.Write(frand.Bytes(1 << 20)); err == nil {
		t.Fatal("didn't fail")
	}
}

// TestConcurrentFirstWrites ensures that when two Writes on a newly-dialed
// Stream wait for buffer space at the same time, only the first frame
// buffered has flagFirst set.
func TestConcurrentFirstWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, peer := newPipeMux(t)
		payload := make([]byte, m.settings.maxPayloadSize())

		// background stream, to block the writeLoop and then fill writeBuf
		bs := blockWriteLoop(t, m)
		go bs.Write(make([]byte, 20*len(payload)))
		synctest.Wait()

		// both Writes wait for buffer space before either buffers a frame
		s := m.DialStream()
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				if _, err := s.Write(payload); err != nil {
					t.Error(err)
				}
			})
		}
		synctest.Wait()

		buf := make([]byte, len(payload))
		var flags []uint16
		for len(flags) < 2 {
			h, _, _, err := peer.nextFrame(buf)
			if err != nil {
				t.Fatal(err)
			} else if h.id == s.id {
				flags = append(flags, h.flags)
			}
		}
		wg.Wait()
		if flags[0] != flagFirst || flags[1] != 0 {
			t.Fatalf("expected flags [%v 0], got %v", flagFirst, flags)
		}
	})
}

// TestFirstFrameAfterClose ensures that a frame with flagFirst set that arrives
// after we close a stream is discarded rather than reopening the stream. Peers
// running older versions of this package can set flagFirst on more than one
// frame when Writes race.
func TestFirstFrameAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, peer := newPipeMux(t)

		peer.writeFrames(t, encodeFrame(idLowestStream+1, flagFirst, 1))
		s, err := m.AcceptStream()
		if err != nil {
			t.Fatal(err)
		} else if _, err := io.ReadFull(s, make([]byte, 1)); err != nil {
			t.Fatal(err)
		} else if err := s.Close(); err != nil {
			t.Fatal(err)
		}

		peer.writeFrames(t, encodeFrame(s.id, flagFirst, 'w'), encodeFrame(s.id, flagLast))
		synctest.Wait() // let readLoop handle the frames
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.err != nil {
			t.Fatal(m.err)
		} else if len(m.streams) != 0 {
			t.Fatalf("expected no open streams, got %v", len(m.streams))
		} else if cs, ok := m.closingStreams[s.id]; !ok || cs.frameCount != 2 {
			t.Fatalf("expected 2 discarded frames for closing stream, got %+v (closing=%v)", cs, ok)
		}
	})
}

// TestCloseUnestablishedStream ensures that closing a Stream that was never
// written to does not send a flagLast frame, which the peer would reject with
// ErrUnknownStream, and that racing Write and Close on a freshly-dialed Stream
// never leaves the peer with an orphaned stream: either no frames are sent at
// all, or both flagFirst and flagLast are sent.
func TestCloseUnestablishedStream(t *testing.T) {
	m1, m2 := newTestingPair(t)

	serverCh := handleStreams(m2, func(s *Stream) error {
		io.Copy(io.Discard, s)
		return nil
	})

	if err := m1.DialStream().Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	const attempts = 500
	for i := range attempts {
		s := m1.DialStream()
		var wg sync.WaitGroup
		wg.Go(func() { s.Write([]byte("x")) })
		wg.Go(func() { s.Close() })
		wg.Wait()

		select {
		case err := <-serverCh:
			t.Fatalf("attempt %d: m2 closed unexpectedly: %v", i, err)
		default:
		}
	}

	// any stream the peer accepted must have also received flagLast;
	// otherwise it stays in m2.streams with a blocked io.Copy goroutine.
	leaked := -1
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m2.mu.Lock()
		leaked = len(m2.streams)
		m2.mu.Unlock()
		if leaked == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if leaked != 0 {
		t.Fatalf("m2 has %d orphaned streams (Write/Close race left flagFirst without flagLast)", leaked)
	}

	if err := m1.Close(); err != nil {
		t.Fatal(err)
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedConn {
		t.Fatal(err)
	}
}

// TestCloseAfterPeerError ensures that closing a Stream that the peer has
// already closed with an error succeeds and keeps the peer's error.
func TestCloseAfterPeerError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, peer := newPipeMux(t)

		peer.writeFrames(t, encodeFrame(idLowestStream+1, flagFirst, 1))
		s, err := m.AcceptStream()
		if err != nil {
			t.Fatal(err)
		} else if _, err := io.ReadFull(s, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}

		peer.writeFrames(t, encodeFrame(s.id, flagLast|flagError, []byte("boom")...))
		synctest.Wait() // let readLoop handle the frame
		if err := s.Close(); err != nil {
			t.Fatal(err)
		} else if _, err := s.Write([]byte{1}); err == nil || err.Error() != "boom" {
			t.Fatalf("expected peer's error, got %v", err)
		}
	})
}

// TestCloseWriteRace ensures that concurrently calling Write and Close on the
// same Stream never causes the peer mux to close with ErrUnknownStream.
func TestCloseWriteRace(t *testing.T) {
	m1, m2 := newTestingPair(t)

	// surface m2's mux-level error as soon as it occurs.
	m2Err := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			s, err := m2.AcceptStream()
			if err != nil {
				select {
				case m2Err <- err:
				default:
				}
				return
			}
			wg.Go(func() {
				io.Copy(io.Discard, s)
				s.Close()
			})
		}
	})

	const attempts = 500
	for i := range attempts {
		// check if failure has already occurred
		select {
		case err := <-m2Err:
			if errors.Is(err, ErrUnknownStream) {
				t.Fatalf("attempt %d: m2 closed with ErrUnknownStream (Write/Close race reproduced)", i)
			}
			t.Fatalf("attempt %d: m2 closed unexpectedly: %v", i, err)
		default:
		}

		// establish a stream by dialing it and writing a byte
		s := m1.DialStream()
		if _, err := s.Write([]byte("x")); err != nil {
			t.Fatalf("attempt %d: establishing Write failed: %v", i, err)
		}

		// simultaneously write and close the stream. Simulating a stream that
		// gets interrupted by a close.
		var wg sync.WaitGroup
		wg.Go(func() {
			s.Write(make([]byte, 1<<16))
		})
		wg.Go(func() {
			s.Close()
		})
		wg.Wait()
	}

	// no ErrUnknownStream errors should have been observed
	select {
	case err := <-m2Err:
		if errors.Is(err, ErrUnknownStream) {
			t.Fatal("m2 closed with ErrUnknownStream (Write/Close race reproduced)")
		}
		t.Fatalf("m2 closed unexpectedly: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	m1.Close()
	wg.Wait()
}

func TestKeepaliveTimeout(t *testing.T) {
	settings := connSettings{
		PacketSize: 1220,
		MaxTimeout: 100 * time.Millisecond,
	}
	keepaliveInterval := settings.MaxTimeout - settings.MaxTimeout/4 // 75ms

	t.Run("idle", func(t *testing.T) {
		c1, c2 := net.Pipe()
		go io.Copy(io.Discard, c2)
		defer c2.Close()

		key := make([]byte, 32)
		aead, _ := chacha20poly1305.New(key)
		m := newMux(c1, &seqCipher{aead: aead}, settings)
		defer m.Close()

		_, err := m.AcceptStream()
		if !errors.Is(err, ErrInactiveConn) {
			t.Fatalf("expected ErrInactiveConn, got %v", err)
		}
	})

	t.Run("resets on activity", func(t *testing.T) {
		c1, c2 := net.Pipe()
		key := make([]byte, 32)
		aead1, _ := chacha20poly1305.New(key)
		cipher1 := &seqCipher{aead: aead1}
		cipher1.theirNonce[len(cipher1.theirNonce)-1] ^= 0x80
		aead2, _ := chacha20poly1305.New(key)
		cipher2 := &seqCipher{aead: aead2}
		cipher2.ourNonce[len(cipher2.ourNonce)-1] ^= 0x80

		m1 := newMux(c1, cipher1, settings)
		m2 := newMux(c2, cipher2, settings)
		m2.nextID++
		defer m1.Close()
		defer m2.Close()

		handleStreams(m2, func(s *Stream) error {
			io.Copy(io.Discard, s)
			return nil
		})

		// The idle timeout is maxKeepalives * keepaliveInterval = 300ms.
		// Send traffic for longer than that to prove the counter resets.
		s := m1.DialStream()
		deadline := time.Now().Add(keepaliveInterval * maxKeepalives * 2)
		for time.Now().Before(deadline) {
			if _, err := s.Write([]byte("ping")); err != nil {
				t.Fatal("mux closed during active period:", err)
			}
			time.Sleep(keepaliveInterval / 2)
		}
		s.Close()
	})
}

func BenchmarkMux(b *testing.B) {
	for _, numStreams := range []int{1, 2, 10, 100, 500, 1000} {
		b.Run(fmt.Sprint(numStreams), func(b *testing.B) {
			m1, m2 := newTestingPair(b)

			_ = handleStreams(m2, func(s *Stream) error {
				io.Copy(io.Discard, s)
				return nil
			})
			defer m1.Close() // ensure handleStreams exits

			// open each stream in a separate goroutine
			bufSize := defaultConnSettings.maxPayloadSize()
			buf := make([]byte, bufSize)
			b.ResetTimer()
			b.SetBytes(int64(bufSize * numStreams))
			b.ReportAllocs()
			start := time.Now()
			var wg sync.WaitGroup
			wg.Add(numStreams)
			for j := 0; j < numStreams; j++ {
				go func() {
					defer wg.Done()
					s := m1.DialStream()
					defer s.Close()
					for i := 0; i < b.N; i++ {
						if _, err := s.Write(buf); err != nil {
							panic(err)
						}
					}
				}()
			}
			wg.Wait()
			b.ReportMetric(float64(b.N*numStreams)/time.Since(start).Seconds(), "frames/sec")
		})
	}
}

func BenchmarkConn(b *testing.B) {
	// benchmark throughput of raw TCP conn (plus encryption overhead to make it fair)
	encryptionKey := make([]byte, 32)
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatal(err)
	}
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			aead, _ := chacha20poly1305.New(encryptionKey)
			cipher := &seqCipher{aead: aead}
			buf := make([]byte, defaultConnSettings.PacketSize)
			for {
				_, err := io.ReadFull(conn, buf)
				if err != nil {
					return err
				}
				if _, err := cipher.decryptInPlace(buf); err != nil {
					return err
				}
			}
		}()
	}()
	defer func() {
		if err := <-serverCh; err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	aead, _ := chacha20poly1305.New(encryptionKey)
	cipher := &seqCipher{aead: aead}
	buf := make([]byte, defaultConnSettings.PacketSize*10)
	b.ResetTimer()
	b.SetBytes(int64(defaultConnSettings.maxPayloadSize()))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cipher.encryptInPlace(buf)
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCovertStream(b *testing.B) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	serverCh := make(chan error, 1)
	go func() {
		serverCh <- func() error {
			conn, err := l.Accept()
			if err != nil {
				return err
			}
			m, err := AcceptAnonymous(conn, 3)
			if err != nil {
				return err
			}

			// background stream, to provide padding for covert streams
			bs, err := m.AcceptStream()
			if err != nil {
				return err
			}
			defer bs.Close()
			go io.Copy(bs, bs)

			cs, err := m.AcceptStream()
			if err != nil {
				return err
			}

			for n := 0; n < b.N*defaultConnSettings.maxPayloadSize(); {
				buf := make([]byte, defaultConnSettings.maxPayloadSize())
				r, err := cs.Read(buf)
				if err != nil {
					return err
				}
				n += r
			}
			cs.Write([]byte{1})
			cs.Close()
			return m.Close()
		}()
	}()
	defer func() {
		if err := <-serverCh; err != nil && err != ErrPeerClosedConn {
			b.Fatal(err)
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	m, err := DialAnonymous(conn)
	if err != nil {
		b.Fatal(err)
	}
	defer m.Close()

	// background stream, to provide padding for covert streams
	backBuf := make([]byte, 100)
	for i := range backBuf {
		backBuf[i] = 0x77
	}
	bs := m.DialStream()
	defer bs.Close()
	if _, err := bs.Write(backBuf); err != nil {
		b.Fatal(err)
	}
	go io.Copy(bs, bs)

	// open each stream in a separate goroutine
	bufSize := defaultConnSettings.maxPayloadSize()
	buf := make([]byte, bufSize)
	for i := range buf {
		buf[i] = 0xFF
	}
	b.ResetTimer()
	b.SetBytes(int64(bufSize))
	b.ReportAllocs()
	start := time.Now()
	cs := m.DialCovertStream()
	defer cs.Close()
	for i := 0; i < b.N; i++ {
		if _, err := cs.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
	cs.Read(buf[:1]) // ensure that server received all frames
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "frames/sec")
}

func TestCloseAfterTimeout(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	m1, m2 := newTestingPair(t)

	// on the server side, block on Read until the stream is closed
	serverDone := make(chan error, 1)
	_ = handleStreams(m2, func(s *Stream) error {
		_, err := io.Copy(io.Discard, s)
		serverDone <- err
		return err
	})

	s := m1.DialStream()

	// establish the stream with an initial write so the peer is aware of it
	if _, err := s.Write([]byte("established")); err != nil {
		t.Fatal(err)
	}

	// set a very short timeout and sleep past it
	s.SetDeadline(time.Now().Add(time.Millisecond))
	time.Sleep(10 * time.Millisecond)

	// write should fail with a timeout error
	_, err := s.Write([]byte("hello"))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded error, got %v", err)
	}

	// Close should still succeed after a timeout
	if err := s.Close(); err != nil {
		t.Fatal("expected Close to succeed, got", err)
	}

	// the server side should be unblocked
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal("expected peer closed stream error on server side without an error, got", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server side was not unblocked after Close")
	}

	if err := m1.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestCloseWithFullBuffer ensures that Close does not block when the write
// buffer is full, and that once the peer resumes reading, every closed stream
// sends its frames followed by exactly one flagLast frame, in close order.
func TestCloseWithFullBuffer(t *testing.T) {
	tests := []struct {
		name    string
		dial    func(*Mux) *Stream
		streams int
	}{
		{"regular", (*Mux).DialStream, 20},
		{"covert", (*Mux).DialCovertStream, 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, peer := newPipeMux(t)
				buf := make([]byte, m.settings.maxPayloadSize())

				// background stream, to block the writeLoop before filling
				// either buffer
				bs := blockWriteLoop(t, m)
				payload := bytes.Repeat([]byte{42}, m.settings.maxPayloadSize()/2-frameHeaderSize)
				streams := make([]*Stream, test.streams)
				expFlags := make(map[uint32]uint16)
				for i := range streams {
					streams[i] = test.dial(m)
					if _, err := streams[i].Write(payload); err != nil {
						t.Fatal(err)
					}
					expFlags[streams[i].id] = flagFirst
				}
				for _, s := range streams {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					} else if err := s.Close(); err != nil {
						t.Fatal(err)
					}
				}
				// keepalives provide the padding for covert frames
				var closed int
				for len(expFlags) > 0 {
					h, p, covert, err := peer.nextFrame(buf)
					if err != nil {
						t.Fatal(err)
					} else if h.id == bs.id || h.id == idKeepalive {
						continue
					}
					if flags, ok := expFlags[h.id]; !ok || h.flags != flags || covert != streams[0].covert {
						t.Fatalf("unexpected frame %+v (covert=%v)", h, covert)
					}
					if h.flags == flagFirst {
						if !bytes.Equal(p, payload) {
							t.Fatal("incorrect stream payload")
						}
						expFlags[h.id] = flagLast
					} else if h.id != streams[closed].id {
						t.Fatalf("expected flagLast frame for stream %v (close order), got stream %v", streams[closed].id, h.id)
					} else {
						delete(expFlags, h.id)
						closed++
					}
				}
				if _, err := bs.Write([]byte{2}); err != nil {
					t.Fatal(err)
				}
				h, p, _, err := peer.nextFrame(buf)
				if err != nil || h.id != bs.id || !bytes.Equal(p, []byte{2}) {
					t.Fatalf("expected background stream frame after flagLast frames, got %+v, %x, %v", h, p, err)
				}
			})
		})
	}
}

// TestCloseUnblocksWrite verifies that closing a Stream or its Mux (or
// cancelling the Stream's context) returns immediately and unblocks a Write that has stalled on backpressure: the writeLoop
// blocks on conn.Write, writeBuf fills up, and Write ends up waiting in
// bufferFrame for buffer space that never frees up.
func TestCloseUnblocksWrite(t *testing.T) {
	// blockedWrite dials a stream on a mux whose conn blocks all writes,
	// starts a 4 MiB Write, and returns once the Write has stalled in
	// bufferFrame.
	blockedWrite := func(t *testing.T, dial func(*Mux) *Stream) (*Stream, chan error) {
		t.Helper()
		var bc *blockConn
		m1, _ := newTestingPairCustom(t, func(conn net.Conn) net.Conn {
			bc = newBlockConn(conn)
			return bc
		})
		t.Cleanup(func() { bc.Close() }) // unblock writes so cleanup doesn't hang

		// block writes so the writeLoop stalls on conn.Write and writeBuf
		// fills up
		close(bc.blockCh)

		s := dial(m1)
		writeDone := make(chan error, 1)
		go func() {
			_, err := s.Write(make([]byte, 4<<20))
			writeDone <- err
		}()

		// wait for the writeLoop to block on conn.Write
		select {
		case <-bc.blockedCh:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for conn.Write to block")
		}

		// the Write should stall in bufferFrame once writeBuf refills
		select {
		case err := <-writeDone:
			t.Fatalf("Write returned before it was unblocked: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		return s, writeDone
	}

	waitWrite := func(t *testing.T, writeDone chan error, want error) {
		t.Helper()
		select {
		case err := <-writeDone:
			if !errors.Is(err, want) {
				t.Fatalf("expected %v from Write, got %v", want, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Write was not unblocked")
		}
	}

	// closing the stream or the mux should return immediately and unblock
	// the Write
	for _, test := range []struct {
		name  string
		close func(*Stream) error
		want  error
	}{
		{"stream close", (*Stream).Close, ErrClosedStream},
		{"mux close", func(s *Stream) error { return s.m.Close() }, ErrClosedConn},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, writeDone := blockedWrite(t, (*Mux).DialStream)
			if err := test.close(s); err != nil {
				t.Fatal("Close failed:", err)
			}
			waitWrite(t, writeDone, test.want)
		})
	}

	t.Run("context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s, writeDone := blockedWrite(t, func(m *Mux) *Stream {
			return m.DialStreamContext(ctx)
		})

		// cancelling the context should unblock the Write
		cancel()
		waitWrite(t, writeDone, context.Canceled)

		if err := s.Close(); err != nil {
			t.Fatal("Close failed:", err)
		}
	})
}

func BenchmarkPackets(b *testing.B) {
	for _, packetSize := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20} {
		b.Run(fmt.Sprintf("%dx%d", ipv6MTU, packetSize), func(b *testing.B) {
			defaultConnSettings.PacketSize = ipv6MTU * packetSize

			m1, m2 := newTestingPair(b)

			_ = handleStreams(m2, func(s *Stream) error {
				io.Copy(io.Discard, s)
				return nil
			})

			// open each stream in a separate goroutine
			bufSize := defaultConnSettings.maxPayloadSize()
			buf := make([]byte, bufSize)
			b.ResetTimer()
			b.SetBytes(int64(bufSize))
			b.ReportAllocs()
			s := m1.DialStream()
			defer s.Close()
			for i := 0; i < b.N; i++ {
				if _, err := s.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestNewStreamDuringShutdown checks that opening streams while the mux
// is being torn down does not leak any goroutines. If readLoop creates a
// stream after the mux has entered its error state, nothing will ever wake
// that stream's consumeFrame and the readLoop goroutine parks forever.
func TestNewStreamDuringShutdown(t *testing.T) {
	const (
		iterations     = 200
		streamsPerConn = 256
	)
	payload := make([]byte, 16) // a flagFirst frame carrying a 16-byte specifier

	for range iterations {
		dialed, accepted := newTestingPair(t)

		// fire new-stream frames without reading or closing them, so that a
		// stream raced past setErr parks in consumeFrame with a full readBuf.
		for range streamsPerConn {
			s := dialed.DialStream()
			s.SetDeadline(time.Now().Add(time.Second))
			if _, err := s.Write(payload); err != nil {
				break
			}
		}

		// let the frames reach the server, then tear the mux down while
		// readLoop is still creating streams from them.
		time.Sleep(time.Millisecond)
		accepted.Close()
		dialed.Close()
	}
}
