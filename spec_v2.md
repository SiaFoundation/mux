SiaMux Spec, Version 2
----------------------

In brief, v2 differs from v1 as follows:

- The MaxFrameSizePackets setting was removed
- The MaxTimeout setting is specified in milliseconds, not seconds
- The "first frame" flag was added
- The frame's payload length is a uint16, not a uint32
- The keepalive ID is 0, not 1
- The shared secret is hashed before use
- Encryption is per-packet, not per-frame
- Support for "covert frames" was added


## Full Spec

A SiaMux session is an exchange of *frames* between two peers over a shared
connection. A session is initiated by a handshake, and terminated (gracefully)
when a "final" frame is sent, or (forcibly) when the connection is closed.

The session is encrypted and authenticated: the dialer must know their peer's
Ed25519 public key, which is used to sign the handshake and thereby derive a
shared secret. This secret is then used to encrypt each frame with
ChaCha20-Poly1305.

All integers in this spec are little-endian.

### Handshake

The *dialing peer* generates an X25519 keypair and sends:

| Length | Type   | Description   |
|--------|--------|---------------|
|   0    | uint8  | Version       |
|   32   | []byte | X25519 pubkey |

The current version is 2.

The *accepting* peer derives the shared X25519 secret, hashes it for use as a
ChaCha20-Poly1305 key, and responds with:

| Length | Type   | Description        |
|--------|--------|--------------------|
|   0    | uint8  | Version            |
|   32   | []byte | X25519 pubkey      |
|   64   | []byte | Ed25519 signature  |
|   36   |        | Encrypted settings |

Finally, the dialing peer derives the shared secret and responds with its own encrypted settings.

The settings are:

| Length | Type   | Description | Valid range    |
|--------|--------|-------------|----------------|
|   4    | uint32 | Packet size | 1220-32768     |
|   4    | uint32 | Max timeout | 120000-7200000 |

Settings are encrypted in the same manner as [Packets](#packets): a 12-byte
nonce, a ciphertext (8 bytes in this case), and a 16-byte tag.

Peers agree upon settings by choosing the minimum of the two packet sizes and
the maximum of the two timeouts. The timeout is an integer number of
milliseconds.

### Frames

After completing the handshake, peers may begin exchanging frames. A frame
consists of a *frame header* followed by a payload. A header is:

| Length | Type   | Description    |
|--------|--------|----------------|
|   4    | uint32 | ID             |
|   2    | uint16 | Payload length |
|   2    | uint16 | Flags          |

The ID specifies which *stream* a frame belongs to. Streams are numbered
sequentially, starting at 256. To prevent collisions, streams initiated by the
dialing peer use even IDs, while the accepting peer uses odd IDs.

An ID of 0 indicates a keepalive frame. Keepalives contain no payload and merely
serve to keep the underlying connection open.

When encoding the ID, shift a 1 into the least-significant bit position; when
decoding, remove this bit by shifting right. (This is necessary to support
[Covert Frames](#covert-frames).)

There are three defined flags:

| Bit | Description           |
|-----|-----------------------|
|  0  | First frame in stream |
|  1  | Last frame in stream  |
|  2  | Error                 |

The "Error" flag may only be set alongside the "Last frame" flag, and indicates
that the payload contains a string describing why the stream was closed.

### Packets

Frames are sent in fixed-length, encrypted *packets*:

| Length | Type   | Description    |
|--------|--------|----------------|
|   12   | []byte | ChaCha20 nonce |
|   n    | []byte | Ciphertext     |
|   16   | []byte | Poly1305 tag   |

Where `n = packetSize - (12 + 16)`.

The decrypted ciphertext contains one or more concatenated frames, padded to `n`
with `0x00` bytes. (Any byte other than `0x00` indicates another frame.) Frames
must not be split across packet boundaries. (In other words, the maximum size of
a frame's payload is `n - (4 + 2 + 2)`.)

The nonce should be chosen randomly for each packet.

### Covert Frames

A packet's padding may contain one or more *covert frames*. Covert frame data is
present if the first byte of padding is `0x02`. After skipping this byte, the
subsequent padding contains covert frame data.

Unlike regular frames, covert frames may be split across multiple packets.
Implementations must buffer covert data until a full covert frame can be
decoded. After decoding the frame header, it becomes possible to determine how
much of the remaining padding is covert data, and how much is regular padding.
