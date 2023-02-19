package mux

import (
	"encoding/binary"
	"fmt"
	"io"
)

//
// However, multiple frames may be stored within a single packet. After a
// receiver decodes a frame, it checks for the presence of another frame within
// the packet by inspecting the next unread bit. A 1 bit indicates another
// frame. (This bit is "stolen" from the stream ID; see encodeFrameHeader.) If
// the bit is 0, the next unread bit is inspected. A 0 bit indicates padding:
// the rest of the packet is discarded. A 1 bit indicates "covert stream data:"
// the remaining 6 bits of the byte are discarded, and the remainder of the
// packet is treated as a distinct stream of raw data. This data is buffered
// until it comprises a full frame, whereupon it is decoded and processed as
// usual and the covert buffer is reset. Since this covert data is only ever
// sent in place of padding, it cannot be detected by traffic analysis.

const (
	flagFirst = 1 << iota // first frame in stream
	flagLast              // stream is being closed gracefully
	flagError             // stream is being closed due to an error
)

const (
	idKeepalive = iota // empty frame to keep connection open

	idLowestStream = 1 << 8 // IDs below this value are reserved
)

const (
	chachaPoly1305NonceSize = 12
	chachaPoly1305TagSize   = 16
)

type frameHeader struct {
	id     uint32
	length uint16
	flags  uint16
}

const frameHeaderSize = 4 + 2 + 2

func encodeFrameHeader(buf []byte, h frameHeader) {
	binary.LittleEndian.PutUint32(buf[0:], (h.id<<1)|1)
	binary.LittleEndian.PutUint16(buf[4:], h.length)
	binary.LittleEndian.PutUint16(buf[6:], h.flags)
}

func decodeFrameHeader(buf []byte) (h frameHeader) {
	h.id = binary.LittleEndian.Uint32(buf[0:]) >> 1
	h.length = binary.LittleEndian.Uint16(buf[4:])
	h.flags = binary.LittleEndian.Uint16(buf[6:])
	return
}

func appendFrame(buf []byte, h frameHeader, payload []byte) []byte {
	frame := buf[len(buf):][:frameHeaderSize+len(payload)]
	encodeFrameHeader(frame[:frameHeaderSize], h)
	copy(frame[frameHeaderSize:], payload)
	return buf[:len(buf)+len(frame)]
}

type packetReader struct {
	r          io.Reader
	cipher     *seqCipher
	packetSize int

	buf       []byte
	encrypted []byte // aliases buf
	decrypted []byte // aliases buf
	covert    []byte // separate buffer; grows until we have a full frame
}

func (pr *packetReader) Read(p []byte) (int, error) {
	// if we have decrypted data, use that; otherwise, if we have an encrypted
	// packet, decrypt it and use that; otherwise, read at least one more packet,
	// decrypt it, and use that

	if len(pr.decrypted) == 0 {
		if len(pr.encrypted) < pr.packetSize {
			pr.buf = append(pr.buf[:0], pr.encrypted...)
			n, err := io.ReadAtLeast(pr.r, pr.buf[len(pr.buf):cap(pr.buf)], pr.packetSize-len(pr.encrypted))
			if err != nil {
				return 0, err
			}
			pr.buf = pr.buf[:len(pr.buf)+n]
			pr.encrypted = pr.buf
		}
		decrypted, err := pr.cipher.decryptInPlace(pr.encrypted[:pr.packetSize])
		if err != nil {
			return 0, err
		}
		pr.decrypted = decrypted
		pr.encrypted = pr.encrypted[pr.packetSize:]
	}

	n := copy(p, pr.decrypted)
	pr.decrypted = pr.decrypted[n:]
	return n, nil
}

func (pr *packetReader) skipPadding() {
	// the first bit tells us if we have a regular frame
	if len(pr.decrypted) == 0 || pr.decrypted[0]&1 != 0 {
		return
	}
	// the second bit tells us if we have covert data or padding
	if pr.decrypted[0]&0b10 != 0 {
		pr.covert = append(pr.covert, pr.decrypted[1:]...)
	}
	pr.decrypted = pr.decrypted[len(pr.decrypted):]
}

func (pr *packetReader) covertFrame() (frameHeader, []byte, bool) {
	if len(pr.covert) < frameHeaderSize {
		return frameHeader{}, nil, false
	}
	h := decodeFrameHeader(pr.covert[:frameHeaderSize])
	if len(pr.covert[frameHeaderSize:]) < int(h.length) {
		return frameHeader{}, nil, false
	}
	payload := pr.covert[frameHeaderSize:][:h.length]
	// check for another covert frame
	if rest := pr.covert[frameHeaderSize+h.length:]; len(rest) > 0 && rest[0]&1 != 0 {
		pr.covert = rest
	} else {
		// no more covert data; skip rest of buffer
		pr.covert = pr.covert[:0]
	}
	return h, payload, true
}

func (pr *packetReader) nextFrame(buf []byte) (frameHeader, []byte, bool, error) {
	pr.skipPadding()
	// if we've buffered a full covert frame, return it
	if h, payload, ok := pr.covertFrame(); ok {
		return h, payload, true, nil
	}

	if _, err := io.ReadFull(pr, buf[:frameHeaderSize]); err != nil {
		return frameHeader{}, nil, false, fmt.Errorf("could not read frame header: %w", err)
	}
	h := decodeFrameHeader(buf[:frameHeaderSize])
	if h.length > uint16(pr.packetSize-frameHeaderSize) {
		return frameHeader{}, nil, false, fmt.Errorf("peer sent too-large frame (%v bytes)", h.length)
	} else if _, err := io.ReadFull(pr, buf[:h.length]); err != nil {
		return frameHeader{}, nil, false, fmt.Errorf("could not read frame payload: %w", err)
	}
	return h, buf[:h.length], false, nil
}

func encryptPackets(buf []byte, p []byte, packetSize int, cipher *seqCipher) []byte {
	maxFrameSize := packetSize - chachaPoly1305TagSize
	numPackets := len(p) / maxFrameSize
	for i := 0; i < numPackets; i++ {
		packet := buf[i*packetSize:][:packetSize]
		plaintext := p[i*maxFrameSize:][:maxFrameSize]
		copy(packet, plaintext)
		cipher.encryptInPlace(packet)
	}
	return buf[:numPackets*packetSize]
}
