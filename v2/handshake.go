package mux

import (
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"lukechampine.com/frand"
)

func generateX25519KeyPair() (xsk, xpk [32]byte) {
	frand.Read(xsk[:])
	curve25519.ScalarBaseMult(&xpk, &xsk)
	return
}

type seqCipher struct {
	aead       cipher.AEAD
	ourNonce   [chachaPoly1305NonceSize]byte
	theirNonce [chachaPoly1305NonceSize]byte
}

func incNonce(nonce []byte) {
	binary.LittleEndian.PutUint64(nonce, binary.LittleEndian.Uint64(nonce)+1)
}

func (c *seqCipher) encryptInPlace(buf []byte) {
	plaintext := buf[:len(buf)-chachaPoly1305TagSize]
	c.aead.Seal(plaintext[:0], c.ourNonce[:], plaintext, nil)
	incNonce(c.ourNonce[:])
}

func (c *seqCipher) decryptInPlace(buf []byte) ([]byte, error) {
	plaintext, err := c.aead.Open(buf[:0], c.theirNonce[:], buf, nil)
	incNonce(c.theirNonce[:])
	return plaintext, err
}

func deriveSharedCipher(xsk, xpk [32]byte) (*seqCipher, error) {
	// NOTE: an error is only possible here if xpk is a "low-order point."
	// Basically, if the other party chooses one of these points as their public
	// key, then the resulting "secret" can be derived by anyone who observes
	// the handshake, effectively rendering the protocol unencrypted. This would
	// be a strange thing to do; the other party can decrypt the messages
	// anyway, so if they want to make the messages public, nothing can stop
	// them from doing so. Consequently, some people (notably djb himself) will
	// tell you not to bother checking for low-order points at all. But why
	// would we want to talk to a peer that's behaving weirdly?
	secret, err := curve25519.X25519(xsk[:], xpk[:])
	if err != nil {
		return nil, err
	}
	key := blake2b.Sum256(secret)
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	// hash the key again to get the initial nonce value
	nonce := blake2b.Sum256(key[:])
	return &seqCipher{
		aead:       c,
		ourNonce:   *(*[chachaPoly1305NonceSize]byte)(nonce[:]),
		theirNonce: *(*[chachaPoly1305NonceSize]byte)(nonce[:]),
	}, err
}

type connSettings struct {
	PacketSize int
	MaxTimeout time.Duration
}

func (cs connSettings) maxFrameSize() int {
	return cs.PacketSize - chachaPoly1305TagSize
}

func (cs connSettings) maxPayloadSize() int {
	return cs.maxFrameSize() - frameHeaderSize
}

const ipv6MTU = 1440 // 1500-byte Ethernet frame - 40-byte IPv6 header - 20-byte TCP header

var defaultConnSettings = connSettings{
	PacketSize: ipv6MTU * 3, // chosen empirically via BenchmarkPackets
	MaxTimeout: 20 * time.Minute,
}

const connSettingsSize = 4 + 4

func encodeConnSettings(buf []byte, cs connSettings) {
	binary.LittleEndian.PutUint32(buf[0:], uint32(cs.PacketSize))
	binary.LittleEndian.PutUint32(buf[4:], uint32(cs.MaxTimeout.Milliseconds()))
}

func decodeConnSettings(buf []byte) (cs connSettings) {
	cs.PacketSize = int(binary.LittleEndian.Uint32(buf[0:]))
	cs.MaxTimeout = time.Millisecond * time.Duration(binary.LittleEndian.Uint32(buf[4:]))
	return
}

func mergeSettings(ours, theirs connSettings) (connSettings, error) {
	// use smaller value for all settings
	merged := ours
	if theirs.PacketSize < merged.PacketSize {
		merged.PacketSize = theirs.PacketSize
	}
	if theirs.MaxTimeout < merged.MaxTimeout {
		merged.MaxTimeout = theirs.MaxTimeout
	}
	// enforce minimums and maximums
	switch {
	case merged.PacketSize < 1220:
		return connSettings{}, fmt.Errorf("requested packet size (%v) is too small", merged.PacketSize)
	case merged.PacketSize > 32768:
		return connSettings{}, fmt.Errorf("requested packet size (%v) is too large", merged.PacketSize)
	case merged.MaxTimeout < 2*time.Minute:
		return connSettings{}, fmt.Errorf("maximum timeout (%v) is too short", merged.MaxTimeout)
	case merged.MaxTimeout > 2*time.Hour:
		return connSettings{}, fmt.Errorf("maximum timeout (%v) is too long", merged.MaxTimeout)
	}
	return merged, nil
}

func initiateHandshake(conn net.Conn, theirKey ed25519.PublicKey, ourSettings connSettings) (*seqCipher, connSettings, error) {
	xsk, xpk := generateX25519KeyPair()

	// write pubkey
	buf := make([]byte, 32+64+connSettingsSize+chachaPoly1305TagSize)
	copy(buf[:], xpk[:])
	if _, err := conn.Write(buf[:32]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not write handshake request: %w", err)
	}
	// read pubkey, signature, and settings
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not read handshake response: %w", err)
	}

	// verify signature
	var rxpk [32]byte
	copy(rxpk[:], buf[:32])
	sig := buf[32:][:64]
	sigHash := blake2b.Sum256(append(xpk[:], rxpk[:]...))
	if !ed25519.Verify(theirKey, sigHash[:], sig) {
		return nil, connSettings{}, errors.New("invalid signature")
	}

	// derive shared cipher
	cipher, err := deriveSharedCipher(xsk, rxpk)
	if err != nil {
		return nil, connSettings{}, fmt.Errorf("failed to derive shared cipher: %w", err)
	}

	// decrypt settings
	var mergedSettings connSettings
	if plaintext, err := cipher.decryptInPlace(buf[32+64:]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could1 not decrypt settings response: %w", err)
	} else if mergedSettings, err = mergeSettings(ourSettings, decodeConnSettings(plaintext)); err != nil {
		return nil, connSettings{}, fmt.Errorf("peer sent unacceptable settings: %w", err)
	}

	// encrypt + write our settings
	encodeConnSettings(buf[:], ourSettings)
	cipher.encryptInPlace(buf[:connSettingsSize+chachaPoly1305TagSize])
	if _, err := conn.Write(buf[:connSettingsSize+chachaPoly1305TagSize]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not write settings: %w", err)
	}

	return cipher, mergedSettings, nil
}

func acceptHandshake(conn net.Conn, ourKey ed25519.PrivateKey, ourSettings connSettings) (*seqCipher, connSettings, error) {
	xsk, xpk := generateX25519KeyPair()

	// read pubkey
	buf := make([]byte, 32+64+connSettingsSize+chachaPoly1305TagSize)
	if _, err := io.ReadFull(conn, buf[:32]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not read handshake request: %w", err)
	}

	// derive shared cipher
	var rxpk [32]byte
	copy(rxpk[:], buf[:32])
	cipher, err := deriveSharedCipher(xsk, rxpk)
	if err != nil {
		return nil, connSettings{}, fmt.Errorf("failed to derive shared cipher: %w", err)
	}

	// write pubkey, signature, and settings
	sigHash := blake2b.Sum256(append(rxpk[:], xpk[:]...))
	sig := ed25519.Sign(ourKey, sigHash[:])
	copy(buf[:], xpk[:])
	copy(buf[32:], sig)
	encodeConnSettings(buf[32+64:], ourSettings)
	cipher.encryptInPlace(buf[32+64:])
	if _, err := conn.Write(buf); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not write handshake response: %w", err)
	}

	// read + decrypt settings
	var settings connSettings
	if _, err := io.ReadFull(conn, buf[:connSettingsSize+chachaPoly1305TagSize]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could not read settings response: %w", err)
	} else if plaintext, err := cipher.decryptInPlace(buf[:connSettingsSize+chachaPoly1305TagSize]); err != nil {
		return nil, connSettings{}, fmt.Errorf("could2 not decrypt settings response: %w", err)
	} else if settings, err = mergeSettings(ourSettings, decodeConnSettings(plaintext)); err != nil {
		return nil, connSettings{}, fmt.Errorf("peer sent unacceptable settings: %w", err)
	}

	return cipher, settings, nil
}
