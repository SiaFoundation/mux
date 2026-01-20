SiaMux Spec, Version 3
----------------------

In brief, v3 differs from v2 as follows:

- Support for "covert frames" was removed
- Support for v1 and v2 protocols was removed


## Full Spec

A SiaMux session is an exchange of *frames* between two peers over a shared
connection. A session is initiated by a handshake, and terminated (gracefully)
when a "final" frame is sent, or (forcibly) when the connection is closed.

The session is encrypted and authenticated: the dialer must know their peer's
Ed25519 public key, which is used to sign the handshake and thereby derive a
shared secret. This secret is then used to encrypt each frame with
ChaCha20-Poly1305, incrementing the nonce after each packet.

All integers in this spec are little-endian.

### Handshake

The *dialing peer* generates an X25519 keypair and sends:

| Length | Type   | Description   |
|--------|--------|---------------|
|   1    | uint8  | Version       |
|   32   | []byte | X25519 pubkey |

The current version is 3.

The *accepting* peer generates an X25519 keypair, derives the shared X25519
secret, and computes the ChaCha20-Poly1305 key as `BLAKE2b(secret | k1 | k2)`,
where `k1` is `k2` are the dialing and accepting X25519 pubkeys. It initializes
its nonce to `0`, and responds with:

| Length | Type   | Description        |
|--------|--------|--------------------|
|   1    | uint8  | Version            |
|   32   | []byte | X25519 pubkey      |
|   64   | []byte | Ed25519 signature  |
|   24   |        | Encrypted settings |

Finally, the dialing peer derives the same ChaCha20-Poly1305 key, initializes
its nonce to `1<<95`, and responds with its own encrypted settings.

The settings are:

| Length | Type   | Description | Valid range    |
|--------|--------|-------------|----------------|
|   4    | uint32 | Packet size | 1220-32768     |
|   4    | uint32 | Max timeout | 120000-7200000 |

Settings are encrypted in the same manner as [Packets](#packets): a ciphertext
(8 bytes in this case) followed by a 16-byte authentication tag.

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
decoding, remove this bit by shifting right.

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
|   n    | []byte | Ciphertext     |
|   16   | []byte | Poly1305 tag   |

Where `n = packetSize - 16`.

The decrypted ciphertext contains one or more concatenated frames, padded to `n`
with `0x00` bytes. (Any byte other than `0x00` indicates another frame.) Frames
must not be split across packet boundaries. (In other words, the maximum size of
a frame's payload is `n - (4 + 2 + 2)`.)

A separate nonce is tracked for both the dialing and accepting peer, incremented
after each use. The initial nonce value is `0` for the dialing peer and `1<<95`
for the accepting peer. To increment a nonce, interpret its least-significant 8
bytes as a 64-bit unsigned integer.
