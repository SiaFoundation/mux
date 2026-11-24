---
default: patch
---

# Fix Stream.Close blocking when writeBuf is full

Close appends the flagLast frame without waiting for buffer space, so it is sent after any frames already buffered for the Stream. Close no longer returns os.ErrDeadlineExceeded. If 2^16 flagLast frames are already waiting beyond the usual buffer size, because the peer has stopped reading, Close instead closes the Mux and returns the new ErrWriteBacklog.
