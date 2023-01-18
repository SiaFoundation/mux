SiaMux Spec, Version 1
----------------------

A SiaMux session is an exchange of *frames* between two peers over a shared
connection. A session is initiated by a handshake, and terminated (gracefully)
when a "final" frame is sent, or (forcibly) when the connection is closed.

The session is encrypted and authenticated: the dialer must know their peer's
Ed25519 public key, which is used to sign the handshake and thereby derive a
shared secret. This secret is then used to encrypt each frame with
ChaCha20-Poly1305.

All integers in this spec are little-endian.

### Handshake

The *dialing peer* and *accepting peer* first exchange versions:

| Length | Type   | Description   |
|--------|--------|---------------|
|   0    | uint8  | Version       |
|   32   | []byte | X25519 pubkey |

The dialing peer then generates an X25519 keypair and sends a
[Frame](#frames) containing:

| Length | Type       | Description               |
|--------|------------|---------------------------|
|   32   | []byte     | X25519 pubkey             |
|   8    | uint64     | Length of cipher list     |
|   n    | []string   | List of supported ciphers |

The frame's ID must be 1.

The only standard cipher is ChaCha20-Poly1305, encoded as the string
"Chacha20P1305\x00\x00\x00".

The accepting peer responds with a frame containing its signed pubkey, and the
selected cipher:

| Length | Type       | Description       |
|--------|------------|-------------------|
|   32   | []byte     | X25519 pubkey     |
|   64   | []byte     | Ed25519 signature |
|   16   | []byte     | Selected cipher   |

The frame's ID must be 1.

The peers then derive the shared X25519 secret, which is used as the cipher key.
The dialing peer sends a frame containing its desired settings:

| Length | Type   | Description    | Valid range |
|--------|--------|----------------|-------------|
|   8    | uint64 | Packet size    | 1220-       |
|   8    | uint64 | Max frame size | 10-64       |
|   8    | uint64 | Max timeout    | 120-        |

The frame's ID must be 2.

Peers agree upon settings by choosing the minimum of the two packet sizes, the
minimum of the max frame size, and the maximum of the two timeouts. The frame
size is given in packets, i.e. a value of 10 means the maximum frame size is 10
packets. The timeout is an integer number of seconds.

### Frames

After completing the handshake, peers may begin exchanging frames. A frame
consists of a *frame header* followed by a payload. A header is:

| Length | Type   | Description    |
|--------|--------|----------------|
|   4    | uint32 | ID             |
|   4    | uint32 | Payload length |
|   2    | uint16 | Flags          |

The ID specifies which *stream* a frame belongs to. Streams are numbered
sequentially, starting at 256. To prevent collisions, streams initiated by the
dialing peer use even IDs, while the accepting peer uses odd IDs.

An ID of 3 indicates a keepalive frame. Keepalives contain no payload and merely
serve to keep the underlying connection open.

There are three defined flags:

| Bit | Description           |
|-----|-----------------------|
|  0  | Last frame in stream  |
|  1  | Error                 |

The "Error" flag may only be set alongside the "First frame" flag, and indicates
that the payload contains a string describing why the stream was closed.

The payload is a ChaCha20 ciphertext with the nonce prependend:

| Length | Type   | Description    |
|--------|--------|----------------|
|   12   | []byte | ChaCha20 nonce |
|   n    | []byte | Ciphertext     |
|   16   | []byte | Poly1305 tag   |

Where `n` is the payload length given in the header. Ciphertexts must be padded
such that the total length of the frame is a multiple of the packet size. This
applies even if the payload length is 0, e.g. in a keepalive frame.

The nonce should be chosen randomly for each packet.
