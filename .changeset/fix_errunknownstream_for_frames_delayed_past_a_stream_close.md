---
default: patch
---

# Fix ErrUnknownStream for frames delayed past a stream close

Frames for a closed Stream are now discarded even if readLoop was blocked for more than a minute before reading them. Frames that peers running older versions of this package send after their flagLast frame are also discarded.
