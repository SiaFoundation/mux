package mux

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"lukechampine.com/frand"
)

func newTestingPair(tb testing.TB) (dialed, accepted *Mux) {
	return newTestingPairWithVersion(tb, 4)
}

func newTestingPairWithVersion(tb testing.TB, peerVersion uint8) (dialed, accepted *Mux) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		tb.Fatal(err)
	}
	errChan := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err == nil {
			accepted, err = AcceptAnonymous(conn, peerVersion)
		}
		errChan <- err
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	dialed, err = DialAnonymous(conn, peerVersion)
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
				errChan <- err
				return
			}
			go func() {
				defer s.Close()
				if err := fn(s); err != nil {
					errChan <- err
					return
				}
			}()
		}
	}()
	return errChan
}

func TestVersionSelection(t *testing.T) {
	for _, version := range []uint8{3, 4, 5, 255} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			m1, m2 := newTestingPairWithVersion(t, version)

			serverCh := handleStreams(m2, func(s *Stream) error {
				buf := make([]byte, 100)
				n, _ := s.Read(buf)
				s.Write(buf[:n])
				return nil
			})

			s := m1.DialStream()
			msg := "hello, world!"
			buf := make([]byte, len(msg))
			if _, err := s.Write([]byte(msg)); err != nil {
				t.Fatal(err)
			} else if _, err := io.ReadFull(s, buf); err != nil {
				t.Fatal(err)
			} else if string(buf) != msg {
				t.Fatalf("bad echo: got %q, want %q", string(buf), msg)
			}
			s.Close()

			if err := m1.Close(); err != nil {
				t.Fatal(err)
			} else if err := <-serverCh; err != nil && err != ErrPeerClosedConn {
				t.Fatal(err)
			}
		})
	}
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
			m, err := Accept(conn, serverKey, 4)
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
	m, err := Dial(conn, serverKey.Public().(ed25519.PublicKey), 4)
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
			s.SetDeadline(time.Now().Add(time.Millisecond)) // too short
		}},
		{true, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Millisecond))
			s.SetReadDeadline(time.Time{}) // Write should still fail
		}},
		{true, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Millisecond))
			s.SetWriteDeadline(time.Time{}) // Read should still fail
		}},
		{false, func(s *Stream) {
			s.SetDeadline(time.Now())
			s.SetDeadline(time.Time{}) // should overwrite
		}},
		{false, func(s *Stream) {
			s.SetDeadline(time.Now().Add(time.Millisecond))
			s.SetWriteDeadline(time.Time{}) // overwrites Read
			s.SetReadDeadline(time.Time{})  // overwrites Write
		}},
	}
	for i, test := range tests {
		err := func() error {
			s := m1.DialStream()
			defer s.Close()
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
