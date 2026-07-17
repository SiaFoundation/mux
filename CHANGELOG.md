## 1.5.3 (2026-07-17)

### Fixes

- Fix Stream.Write not getting unblocked by Stream.Close if writeBuf is full.
- Short-circuits readLoop if an error occurs before Stream creation

## 1.5.2 (2026-06-09)

### Fixes

- Fix NDFs
- Prevent Stream.Write from sending a frame on an already closed Stream.

## 1.5.1 (2026-05-13)

### Fixes

- Fix Close failing after write deadline is reached.
- Fix goroutine leak in readLoop.
- Update Go version to v1.26.0.

#### Fix Close hanging indefinitely when conn.Write is blocked due to TCP backpressure

Close no longer attempts to flush the write buffer and closes the underlying connection immediately.
