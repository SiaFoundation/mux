---
default: patch
---

# Keep the peer's error in Stream.Close if the peer closed the Stream first

Close returns nil and sends no flagLast frame. Previously, an error sent by the peer was replaced with ErrClosedStream.
