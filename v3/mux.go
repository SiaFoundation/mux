package mux

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"
)

// NOTE: This package makes heavy use of sync.Cond to manage concurrent streams
// multiplexed onto a single connection. sync.Cond is rarely used (since it is
// almost never the right tool for the job), and consequently, Go programmers
// tend to be unfamiliar with its semantics. Nevertheless, it is currently the
// only way to achieve optimal throughput in a stream multiplexer, so we make
// careful use of it here. Please make sure you understand sync.Cond thoroughly
// before attempting to modify this code.

// Errors relating to stream or mux shutdown.
var (
	ErrClosedConn       = errors.New("underlying connection was closed")
	ErrClosedStream     = errors.New("stream was gracefully closed")
	ErrPeerClosedStream = errors.New("peer closed stream gracefully")
	ErrPeerClosedConn   = errors.New("peer closed underlying connection")
	ErrStreamFlood      = errors.New("too many frames received for closed stream")
	ErrUnknownStream    = errors.New("frame received for unknown stream")
	ErrInactiveConn     = errors.New("connection closed due to inactivity")
	ErrWriteBacklog     = errors.New("too many frames buffered for a peer that is not reading")
)

const (
	// closingStreamCleanupInterval is the time after which a closed stream will
	// no longer be tracked as closing. After that time, receiving a frame for
	// that stream will lead to an immediate closure of the mux.
	closingStreamCleanupInterval = time.Minute

	// maxClosedFrames is the maximum number of frames to accept for a closed
	// stream before we consider the peer to be acting maliciously and close the
	// mux.
	maxClosedFrames = 1000 // ~4MiB on default settings

	// maxQueuedCloseFrames is the number of flagLast frames that Close may
	// buffer beyond the size that bufferFrame fills a buffer to. Close closes
	// the mux with ErrWriteBacklog rather than exceed it.
	maxQueuedCloseFrames = 1 << 16 // 512KiB

	// maxKeepalives is the maximum number of consecutive keepalives to send
	// without any other traffic before closing the mux.
	maxKeepalives = 4
)

// A Mux multiplexes multiple duplex Streams onto a single net.Conn.
type Mux struct {
	conn     net.Conn
	cipher   *seqCipher
	settings connSettings

	// all subsequent fields are guarded by mu
	mu             sync.Mutex
	cond           sync.Cond
	streams        map[uint32]*Stream
	closingStreams map[uint32]closingStream // streams closed by us
	nextID         uint32
	remKeepalives  int
	err            error // sticky and fatal
	writeBuf       []byte
	covertBuf      []byte
	bufferCond     sync.Cond // separate cond for waking a single bufferFrame
}

// closingStream is used to track streams that have been closed by us until either
// - the peer acknowledges the closure by sending a frame with flagLast
// - frameCount exceeds maxClosedFrames
// - closingStreamCleanupInterval has passed
type closingStream struct {
	frameCount uint16
	closed     time.Time
}

// addClosingStream starts tracking id as closing. The caller must hold m.mu.
func (m *Mux) addClosingStream(id uint32) {
	m.closingStreams[id] = closingStream{closed: time.Now()}
}

// setErr sets the Mux error and wakes up all Mux-related goroutines. If m.err
// is already set, setErr is a no-op.
func (m *Mux) setErr(err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setErrLocked(err)
}

// setErrLocked is like setErr, but the caller must hold m.mu.
func (m *Mux) setErrLocked(err error) error {
	if m.err != nil {
		return m.err
	}

	// try to detect when the peer closed the connection
	if isConnCloseError(err) {
		err = ErrPeerClosedConn
	}

	// set sticky error, close conn, and wake everyone up
	m.err = err
	for _, s := range m.streams {
		s.cond.L.Lock()
		s.err = err
		s.readBuf = nil
		s.cond.Broadcast()
		s.cond.L.Unlock()
	}
	m.conn.Close()
	m.cond.Broadcast()
	m.bufferCond.Broadcast()
	return err
}

// writeBufFor returns the buffer that frames for a regular or covert stream are
// stored in, and the size up to which bufferFrame fills it. The caller must
// hold m.mu.
func (m *Mux) writeBufFor(covert bool) (buf *[]byte, maxBufSize int) {
	if covert {
		return &m.covertBuf, m.settings.maxPayloadSize() * 2
	}
	return &m.writeBuf, m.settings.maxPayloadSize() * 10
}

// bufferFrame blocks until it can store a frame for s in m.writeBuf (or, for
// covert streams, m.covertBuf). It returns early with an error if m.err or
// s.err is set, or if the deadline expires. Close sets s.err under m.mu, so
// re-checking s.err under m.mu guarantees that no frame can be buffered behind
// the stream's flagLast frame.
func (m *Mux) bufferFrame(s *Stream, payload []byte, deadline time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		timer := time.AfterFunc(time.Until(deadline), m.bufferCond.Broadcast) // nice
		defer timer.Stop()
	}
	// block until we can add the frame to the buffer
	buf, maxBufSize := m.writeBufFor(s.covert)
	streamErr := func() error {
		s.cond.L.Lock()
		defer s.cond.L.Unlock()
		return s.err
	}
	for len(*buf)+frameHeaderSize+len(payload) > maxBufSize && m.err == nil && streamErr() == nil && (deadline.IsZero() || time.Now().Before(deadline)) {
		m.bufferCond.Wait()
	}
	if m.err != nil {
		return m.err
	} else if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}

	// check for stream error, and set flagFirst under the same lock so that
	// concurrent Writes establish the stream exactly once
	h := frameHeader{id: s.id, length: uint16(len(payload))}
	s.cond.L.Lock()
	if err := s.err; err != nil {
		s.cond.L.Unlock()
		m.bufferCond.Signal()
		return err
	}
	if !s.established {
		h.flags = flagFirst
		s.established = true
	}
	s.cond.L.Unlock()

	// buffer our frame and wake the writeLoop
	//
	// NOTE: it is not necessary to wait for the writeLoop to flush our frame.
	// After all, a successful write() syscall doesn't mean that the peer
	// actually received the data, just that the packets are sitting in a kernel
	// buffer somewhere.
	*buf = appendFrame(*buf, h, payload)
	m.cond.Broadcast()

	if s.covert {
		// wake all other bufferFrame calls
		//
		// NOTE: this causes lots of spurious wakeups. Covert bandwidth is
		// precious, though, so it's better to take a small performance hit to
		// ensure that we're making use of whatever bandwidth is available.
		// If it becomes a problem, we can easily add a separate sync.Cond.
		m.bufferCond.Broadcast()
	} else {
		// wake at most one bufferFrame call
		//
		// NOTE: it's possible that we'll wake the "wrong" bufferFrame call, i.e.
		// one whose payload is too large to fit in the buffer. This means we won't
		// buffer any additional frames until the writeLoop flushes the buffer.
		// Calling Broadcast instead of Signal prevents this, but also incurs a
		// massive performance penalty when there are many concurrent streams. We
		// could probably get the best of both worlds with a more sophisticated
		// buffering strategy, but the current implementation is fast enough.
		m.bufferCond.Signal()
	}
	return nil
}

// writeLoop handles the actual Writes to the Mux's net.Conn. It waits for
// bufferFrame calls to fill m.writeBuf, then flushes the buffer to the
// underlying connection. It also handles keepalives.
func (m *Mux) writeLoop() {
	// wake cond whenever a keepalive is due
	//
	// NOTE: we send a keepalive when 75% of the MaxTimeout has elapsed
	keepaliveInterval := m.settings.MaxTimeout - m.settings.MaxTimeout/4
	nextKeepalive := time.Now().Add(keepaliveInterval)
	timer := time.AfterFunc(keepaliveInterval, m.cond.Broadcast)
	defer timer.Stop()

	// to avoid blocking bufferFrame while we Write, copy into a local buffer
	buf := make([]byte, m.settings.PacketSize*10)
	for {
		// wait for frames
		m.mu.Lock()
		for len(m.writeBuf) == 0 && m.err == nil && time.Now().Before(nextKeepalive) {
			m.cond.Wait()
		}
		if m.err != nil {
			m.mu.Unlock()
			return
		}

		// if we have a normal frame, use that; otherwise, send a keepalive
		//
		// NOTE: even if we were woken by the keepalive timer, there might be a
		// normal frame ready to send, in which case we don't need a keepalive
		if len(m.writeBuf) == 0 {
			if m.remKeepalives--; m.remKeepalives == 0 {
				m.mu.Unlock()
				m.setErr(ErrInactiveConn)
				return
			}
			m.writeBuf = appendFrame(m.writeBuf[:0], frameHeader{id: idKeepalive}, nil)
		} else {
			m.remKeepalives = maxKeepalives
		}
		// pad to packet boundary
		if len(m.writeBuf)%m.settings.maxFrameSize() != 0 {
			padding := m.settings.maxFrameSize() - len(m.writeBuf)%m.settings.maxFrameSize()
			m.writeBuf = append(m.writeBuf, make([]byte, padding)...)
			pad := m.writeBuf[len(m.writeBuf)-padding:]
			// replace padding with covert data, if available
			if len(m.covertBuf) > 0 && len(pad) > 1 {
				pad[0] = 0b10 // sentinel byte; see packetReader
				n := copy(pad[1:], m.covertBuf)
				m.covertBuf = append(m.covertBuf[:0], m.covertBuf[n:]...)
			}
		}
		// split into packets and encrypt
		//
		// NOTE: Close appends flagLast frames without waiting for buffer
		// space, so writeBuf can exceed the size bufferFrame allows
		if n := len(m.writeBuf) / m.settings.maxFrameSize() * m.settings.PacketSize; n > len(buf) {
			buf = make([]byte, n)
		}
		packets := encryptPackets(buf, m.writeBuf, m.settings.PacketSize, m.cipher)

		// clear writeBuf and wake at most one bufferFrame call
		m.writeBuf = m.writeBuf[:0]
		m.bufferCond.Signal()
		m.mu.Unlock()

		// reset keepalive timer
		timer.Stop()
		timer.Reset(keepaliveInterval)
		nextKeepalive = time.Now().Add(keepaliveInterval)

		// write the packet(s)
		if _, err := m.conn.Write(packets); err != nil {
			m.setErr(err)
			return
		}
	}
}

func (m *Mux) pruneClosedStreams() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, cs := range m.closingStreams {
		if time.Since(cs.closed) > closingStreamCleanupInterval {
			delete(m.closingStreams, id)
		}
	}
	if len(m.closingStreams) == 0 {
		m.closingStreams = make(map[uint32]closingStream) // free memory
	}
}

// readLoop handles the actual Reads from the Mux's net.Conn. It waits for a
// frame to arrive, then routes it to the appropriate Stream, creating a new
// Stream if none exists. It then waits for the frame to be fully consumed by
// the Stream before attempting to Read again.
func (m *Mux) readLoop() {
	pr := &packetReader{
		r:          m.conn,
		cipher:     m.cipher,
		packetSize: m.settings.PacketSize,
		buf:        make([]byte, 0, m.settings.PacketSize*10),
	}
	frameBuf := make([]byte, m.settings.maxPayloadSize())

	// prune closed streams whenever enough time has passed for streams to
	// expire
	var wg sync.WaitGroup
	defer wg.Wait()
	cleanupTicker := time.NewTicker(closingStreamCleanupInterval)
	cleanupDone := make(chan struct{})
	defer func() {
		cleanupTicker.Stop()
		close(cleanupDone)
	}()
	wg.Go(func() {
		for {
			select {
			case <-cleanupDone:
				return
			case <-cleanupTicker.C:
				m.pruneClosedStreams()
			}
		}
	})

	for {
		h, payload, covert, err := pr.nextFrame(frameBuf)
		if err != nil {
			m.setErr(err)
			return
		}
		if h.id == idKeepalive {
			continue // no action required
		} else if h.id < idLowestStream {
			m.setErr(fmt.Errorf("peer sent invalid frame ID (%v) (covert=%v, length=%v, flags=%v)", h.id, covert, h.length, h.flags))
			return
		}

		// look for matching Stream
		//
		// NOTE: this must happen under m.mu so that it agrees with Close about
		// whether we have closed the stream
		m.mu.Lock()
		m.remKeepalives = maxKeepalives
		stream := m.streams[h.id]
		if stream == nil {
			if cs, ok := m.closingStreams[h.id]; ok {
				// we are encountering a frame for a stream that has already
				// been closed. This could be a delayed frame, or it could be
				// an attempt to flood us with garbage frames. Track how many
				// frames we've seen for this closed stream, and if it exceeds
				// the threshold, close the mux
				//
				// NOTE: this applies even if the frame has flagFirst set.
				// Peers running older versions of this package can set
				// flagFirst on more than one frame when Writes race, and such
				// a frame must not reopen the stream.
				cs.frameCount++
				m.closingStreams[h.id] = cs
				if cs.frameCount >= maxClosedFrames {
					m.mu.Unlock()
					m.setErr(ErrStreamFlood)
					return
				}
				m.mu.Unlock()
				continue
			}
			if h.flags&flagFirst == 0 {
				// received a frame for a stream that we don't know at all
				m.mu.Unlock()
				m.setErr(ErrUnknownStream)
				return
			}
			// create a new stream
			const maxStreams = 1 << 20
			if len(m.streams) > maxStreams {
				m.mu.Unlock()
				m.setErr(fmt.Errorf("exceeded concurrent stream limit (%v streams)", maxStreams))
				return
			}
			// If the mux is already dying, do not register a new stream.
			if m.err != nil {
				m.mu.Unlock()
				return
			}
			stream = &Stream{
				m:           m,
				id:          h.id,
				needAccept:  true,
				cond:        sync.Cond{L: new(sync.Mutex)},
				covert:      covert,
				established: true,
			}
			m.streams[h.id] = stream
			m.cond.Broadcast() // wake (*Mux).AcceptStream
		}
		if h.flags&flagLast != 0 {
			m.peerClosedStream(stream, h, payload)
			m.mu.Unlock()
			continue
		}
		m.mu.Unlock()
		stream.consumeFrame(payload)
	}
}

// peerClosedStream handles a flagLast frame for a stream that we have not
// closed. The caller must hold m.mu.
func (m *Mux) peerClosedStream(s *Stream, h frameHeader, payload []byte) {
	err := ErrPeerClosedStream
	if h.flags&flagError != 0 {
		err = errors.New(string(payload))
	}
	s.cond.L.Lock()
	s.err = err
	s.cond.Broadcast() // wake Read
	s.cond.L.Unlock()

	delete(m.streams, s.id)
	m.bufferCond.Broadcast() // wake Write so it can observe s.err
}

// Close closes the underlying net.Conn.
func (m *Mux) Close() error {
	err := m.setErr(ErrClosedConn)
	if err == ErrClosedConn || err == ErrPeerClosedConn {
		err = nil
	}
	return err
}

// AcceptStream waits for and returns the next peer-initiated Stream.
func (m *Mux) AcceptStream() (*Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		if m.err != nil {
			return nil, m.err
		}
		for _, s := range m.streams {
			if s.needAccept {
				s.needAccept = false
				return s, nil
			}
		}
		m.cond.Wait()
	}
}

// DialStream creates a new Stream.
//
// Unlike e.g. net.Dial, this does not perform any I/O; the peer will not be
// aware of the new Stream until Write is called.
func (m *Mux) DialStream() *Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &Stream{
		m:           m,
		id:          m.nextID,
		needAccept:  false,
		cond:        sync.Cond{L: new(sync.Mutex)},
		established: false,
		err:         m.err, // stream is unusable if m.err is set
	}
	m.streams[s.id] = s
	m.nextID += 2
	// wraparound when nextID grows too large
	if m.nextID >= math.MaxUint32>>2 {
		m.nextID = idLowestStream + m.nextID&1 // preserve dial/accept bit
		// NOTE: the above assumes that idLowestStream & 1 == 0, which we enforce
		// at compile time using the following declaration:
		var _ [idLowestStream & 1]struct{} = [0]struct{}{}
	}
	return s
}

// DialCovertStream creates a new covert Stream. Covert Streams hide their
// payloads within the padding of other Streams, making them effectively
// invisible to traffic analysis.
//
// Unlike e.g. net.Dial, this does not perform any I/O; the peer will not be
// aware of the new Stream until Write is called.
func (m *Mux) DialCovertStream() *Stream {
	s := m.DialStream()
	s.covert = true
	return s
}

// DialStreamContext creates a new Stream with the provided context. When the
// context expires, the Stream will be closed and any pending calls will return
// ctx.Err(). DialStreamContext spawns a goroutine whose lifetime matches that
// of the context.
//
// Unlike e.g. net.Dial, this does not perform any I/O; the peer will not be
// aware of the new Stream until Write is called.
//
// Deprecated: To associate a Stream with a context, use a helper function as
// described here: https://github.com/SiaFoundation/mux/pull/2#issuecomment-2351171318
func (m *Mux) DialStreamContext(ctx context.Context) *Stream {
	s := m.DialStream()
	go func() {
		<-ctx.Done()
		s.cond.L.Lock()
		if ctx.Err() != nil && s.err == nil {
			s.err = ctx.Err()
			s.readBuf = nil
			s.cond.Broadcast()
		}
		s.cond.L.Unlock()

		// wake any Write blocked in bufferFrame so it can observe s.err
		m.mu.Lock()
		m.bufferCond.Broadcast()
		m.mu.Unlock()
	}()
	return s
}

// newMux initializes a Mux and spawns its readLoop and writeLoop goroutines.
func newMux(conn net.Conn, cipher *seqCipher, settings connSettings) *Mux {
	m := &Mux{
		conn:           conn,
		cipher:         cipher,
		closingStreams: make(map[uint32]closingStream),
		settings:       settings,
		streams:        make(map[uint32]*Stream),
		nextID:         idLowestStream,
		remKeepalives:  maxKeepalives,
		writeBuf:       make([]byte, 0, settings.maxFrameSize()*10),
		covertBuf:      make([]byte, 0, settings.maxPayloadSize()*2),
	}
	// both conds use the same mutex
	m.cond.L = &m.mu
	m.bufferCond.L = &m.mu
	go m.readLoop()
	go m.writeLoop()
	return m
}

// Dial initiates a mux protocol handshake on the provided conn.
func Dial(conn net.Conn, theirKey ed25519.PublicKey) (*Mux, error) {
	cipher, settings, err := initiateHandshake(conn, theirKey, defaultConnSettings)
	if err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}
	return newMux(conn, cipher, settings), nil
}

// Accept reciprocates a mux protocol handshake on the provided conn.
func Accept(conn net.Conn, ourKey ed25519.PrivateKey) (*Mux, error) {
	cipher, settings, err := acceptHandshake(conn, ourKey, defaultConnSettings)
	if err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}
	m := newMux(conn, cipher, settings)
	m.nextID++ // avoid collisions with Dialing peer
	return m, nil
}

var anonPrivkey = ed25519.NewKeyFromSeed(make([]byte, 32))
var anonPubkey = anonPrivkey.Public().(ed25519.PublicKey)

// DialAnonymous initiates a mux protocol handshake to a party without a
// pre-established identity. The counterparty must reciprocate the handshake with
// AcceptAnonymous.
func DialAnonymous(conn net.Conn) (*Mux, error) {
	return Dial(conn, anonPubkey)
}

// AcceptAnonymous reciprocates a mux protocol handshake without a
// pre-established identity. The counterparty must initiate the handshake with
// DialAnonymous.
func AcceptAnonymous(conn net.Conn, theirVersion uint8) (*Mux, error) {
	return Accept(conn, anonPrivkey)
}

// A Stream is a duplex connection multiplexed over a net.Conn. It implements
// the net.Conn interface.
type Stream struct {
	m          *Mux
	id         uint32
	covert     bool
	needAccept bool // managed by Mux

	cond        sync.Cond // guards + synchronizes subsequent fields
	established bool      // has the first frame been sent?
	err         error
	readBuf     []byte
	rd, wd      time.Time // deadlines
}

// LocalAddr returns the underlying connection's LocalAddr.
func (s *Stream) LocalAddr() net.Addr { return s.m.conn.LocalAddr() }

// RemoteAddr returns the underlying connection's RemoteAddr.
func (s *Stream) RemoteAddr() net.Addr { return s.m.conn.RemoteAddr() }

// SetDeadline sets the read and write deadlines associated with the Stream. It
// is equivalent to calling both SetReadDeadline and SetWriteDeadline.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Read or Write calls, only
// future calls.
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetReadDeadline(t)
	s.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Read calls, only future calls.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.rd = t
	return nil
}

// SetWriteDeadline sets the write deadline associated with the Stream.
//
// This implementation does not entirely conform to the net.Conn interface:
// setting a new deadline does not affect pending Write calls, only future
// calls.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	s.wd = t
	return nil
}

// consumeFrame stores a frame in s.readBuf and waits for it to be consumed by
// (*Stream).Read calls.
func (s *Stream) consumeFrame(payload []byte) {
	// set payload and wait for it to be consumed
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	if s.err != nil {
		return
	}
	s.readBuf = payload
	s.cond.Broadcast() // wake Read
	for len(s.readBuf) > 0 && s.err == nil {
		s.cond.Wait()
	}
}

// Read reads data from the Stream.
func (s *Stream) Read(p []byte) (int, error) {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	if !s.established {
		// developer error: peer doesn't know this Stream exists yet
		panic("mux: Read called before Write on newly-Dialed Stream")
	}
	if !s.rd.IsZero() {
		defer time.AfterFunc(time.Until(s.rd), s.cond.Broadcast).Stop()
	}
	for len(s.readBuf) == 0 && s.err == nil && (s.rd.IsZero() || time.Now().Before(s.rd)) {
		s.cond.Wait()
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]

	err := s.err
	if err == ErrPeerClosedStream {
		err = io.EOF
	} else if !(s.rd.IsZero() || time.Now().Before(s.rd)) {
		err = os.ErrDeadlineExceeded
	} else if err != nil {
		s.readBuf = nil // if the error is fatal, drop the rest of the buffer
	}
	if len(s.readBuf) > 0 {
		err = nil // if more data is available, silence the error
	} else {
		s.cond.Broadcast() // wake consumeFrame
	}
	return n, err
}

// Write writes data to the Stream.
func (s *Stream) Write(p []byte) (n int, err error) {
	buf := bytes.NewBuffer(p)
	for buf.Len() > 0 {
		// check for error
		s.cond.L.Lock()
		err = s.err
		deadline := s.wd
		s.cond.L.Unlock()
		if err != nil {
			return
		}
		// write next frame's worth of data
		payload := buf.Next(s.m.settings.maxPayloadSize())
		err = s.m.bufferFrame(s, payload, deadline)
		if err != nil {
			return
		}
		n += len(payload)
	}
	return
}

// Close closes the Stream. The underlying connection is not closed.
//
// Close does not block, even if the write buffer is full; the flagLast frame
// is sent after any frames already buffered for the Stream. If too many
// flagLast frames are already waiting for a peer that is not reading, Close
// closes the Mux and returns ErrWriteBacklog. If the peer has already closed
// the Stream, Close returns nil, sends nothing, and
// the Stream keeps the error the peer closed it with.
func (s *Stream) Close() error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	// only the first Close of a stream that is still open does anything; the
	// peer may already have closed it
	if s.m.streams[s.id] != s {
		return nil
	}
	delete(s.m.streams, s.id)

	s.cond.L.Lock()
	s.err = ErrClosedStream
	established := s.established
	s.readBuf = nil
	s.cond.Broadcast()
	s.cond.L.Unlock()
	s.m.bufferCond.Broadcast() // wake Write so it can observe s.err

	if !established {
		// if the stream was never established (no frames were sent to the
		// peer), don't send a flagLast frame since the peer doesn't know
		// about this stream and would treat it as an error.
		return nil
	} else if s.m.err != nil {
		return s.m.err
	}

	// buffer the flagLast frame without waiting for buffer space; it follows
	// any frames already buffered for the stream. The stream is tracked as
	// closing right away, so frames the peer sends meanwhile are discarded.
	//
	// NOTE: closing streams are pruned even while the writeLoop is blocked, so
	// without a budget, a peer that stops reading but keeps opening streams
	// for us to close could grow the buffer without bound. Dropping the
	// flagLast frame instead would leave the peer with a phantom stream.
	buf, maxBufSize := s.m.writeBufFor(s.covert)
	if len(*buf)+frameHeaderSize > maxBufSize+maxQueuedCloseFrames*frameHeaderSize {
		return s.m.setErrLocked(ErrWriteBacklog)
	}
	*buf = appendFrame(*buf, frameHeader{id: s.id, flags: flagLast}, nil)
	s.m.addClosingStream(s.id)
	s.m.cond.Broadcast() // wake writeLoop
	return nil
}

var _ net.Conn = (*Stream)(nil)
