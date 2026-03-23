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
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/frand"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func newTestingPair(tb testing.TB) (dialed, accepted *Mux) {
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

func TestContext(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
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
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedConn && err != ErrPeerClosedStream {
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
			// accept covert stream
			cs, err := m.AcceptStream()
			if err != nil {
				return err
			}
			covertCh := make(chan error)
			go func() {
				defer cs.Close()
				buf := make([]byte, 100)
				if n, err := cs.Read(buf); err != nil {
					covertCh <- err
				} else if _, err := fmt.Fprintf(cs, "hello, %s!", buf[:n]); err != nil {
					covertCh <- err
				} else {
					covertCh <- cs.Close()
				}
			}()
			// accept regular stream
			s, err := m.AcceptStream()
			if err != nil {
				return err
			}
			defer s.Close()
			buf := make([]byte, 100)
			n, err := s.Read(buf)
			if err != nil {
				return err
			}
			// wait for covert stream to buffer before writing
			if err := <-covertCh; err != nil {
				return err
			}
			if _, err := fmt.Fprintf(s, "hello, %s!", buf[:n]); err != nil {
				return err
			} else if err := s.Close(); err != nil {
				return err
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
	<-bufChan // wait for covert stream to buffer
	buf := make([]byte, 100)
	if _, err := s.Write([]byte("world")); err != nil {
		t.Log(<-serverCh)
		t.Fatal(err)
	} else if n, err := io.ReadFull(s, buf[:13]); err != nil {
		t.Log(<-serverCh)
		t.Fatal(err)
	} else if string(buf[:n]) != "hello, world!" {
		t.Fatalf("bad hello: %s", buf[:n])
	}

	if err := <-covertCh; err != nil && err != ErrPeerClosedConn {
		t.Fatal(err)
	} else if err := m.Close(); err != nil {
		t.Fatal(err)
	} else if err := <-serverCh; err != nil && err != ErrPeerClosedStream {
		t.Fatal(err)
	}
	// wait for read/write goroutines to exit
	time.Sleep(time.Second)

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
		t.Log("handler finished")
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
