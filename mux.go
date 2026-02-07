package mux

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	muxv3 "go.sia.tech/mux/v3"
)

// A Mux multiplexes multiple duplex Streams onto a single net.Conn.
type Mux struct {
	m3 *muxv3.Mux
}

// Close closes the underlying net.Conn.
func (m *Mux) Close() error {
	return m.m3.Close()
}

// AcceptStream waits for and returns the next peer-initiated Stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	s, err := m.m3.AcceptStream()
	return &Stream{s3: s}, err
}

// DialStream creates a new Stream.
//
// Unlike e.g. net.Dial, this does not perform any I/O; the peer will not be
// aware of the new Stream until Write is called.
func (m *Mux) DialStream() *Stream {
	return &Stream{s3: m.m3.DialStream()}
}

// Dial initiates a mux protocol handshake on the provided conn.
func Dial(conn net.Conn, theirKey ed25519.PublicKey) (*Mux, error) {
	// exchange versions
	var theirVersion [1]byte
	if _, err := conn.Write([]byte{4}); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if _, err := io.ReadFull(conn, theirVersion[:]); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if theirVersion[0] == 0 {
		return nil, errors.New("peer sent invalid version")
	}
	if theirVersion[0] < 3 {
		return nil, errors.New("versions 1 and 2 are no longer supported")
	}
	m, err := muxv3.Dial(conn, theirKey, theirVersion[0])
	return &Mux{m3: m}, err
}

// Accept reciprocates a mux protocol handshake on the provided conn.
func Accept(conn net.Conn, ourKey ed25519.PrivateKey) (*Mux, error) {
	// exchange versions
	var theirVersion [1]byte
	if _, err := io.ReadFull(conn, theirVersion[:]); err != nil {
		return nil, fmt.Errorf("could not read peer version: %w", err)
	} else if _, err := conn.Write([]byte{4}); err != nil {
		return nil, fmt.Errorf("could not write our version: %w", err)
	} else if theirVersion[0] == 0 {
		return nil, errors.New("peer sent invalid version")
	}
	if theirVersion[0] < 3 {
		return nil, errors.New("versions 1 and 2 are no longer supported")
	}
	m, err := muxv3.Accept(conn, ourKey, theirVersion[0])
	return &Mux{m3: m}, err
}

var anonPrivkey = ed25519.NewKeyFromSeed(make([]byte, 32))
var anonPubkey = anonPrivkey.Public().(ed25519.PublicKey)

// DialAnonymous initiates a mux protocol handshake to a party without a
// pre-established identity. The counterparty must reciprocate the handshake with
// AcceptAnonymous.
func DialAnonymous(conn net.Conn) (*Mux, error) { return Dial(conn, anonPubkey) }

// AcceptAnonymous reciprocates a mux protocol handshake without a
// pre-established identity. The counterparty must initiate the handshake with
// DialAnonymous.
func AcceptAnonymous(conn net.Conn) (*Mux, error) { return Accept(conn, anonPrivkey) }

// A Stream is a duplex connection multiplexed over a net.Conn. It implements
// the net.Conn interface.
type Stream struct {
	s3 *muxv3.Stream
}

// LocalAddr returns the underlying connection's LocalAddr.
func (s *Stream) LocalAddr() net.Addr {
	return s.s3.LocalAddr()
}

// RemoteAddr returns the underlying connection's RemoteAddr.
func (s *Stream) RemoteAddr() net.Addr {
	return s.s3.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the Stream. It
// is equivalent to calling both SetReadDeadline and SetWriteDeadline.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Read or Write calls, only
// future calls.
func (s *Stream) SetDeadline(t time.Time) error {
	return s.s3.SetDeadline(t)
}

// SetReadDeadline sets the read deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Read calls, only future calls.
func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.s3.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Write calls, only future
// calls.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	return s.s3.SetWriteDeadline(t)
}

// Read reads data from the Stream.
func (s *Stream) Read(p []byte) (int, error) {
	return s.s3.Read(p)
}

// Write writes data to the Stream.
func (s *Stream) Write(p []byte) (int, error) {
	return s.s3.Write(p)
}

// Close closes the Stream. The underlying connection is not closed.
func (s *Stream) Close() error {
	return s.s3.Close()
}
