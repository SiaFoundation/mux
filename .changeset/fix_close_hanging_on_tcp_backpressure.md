---
default: patch
---

# Fix Close hanging indefinitely when conn.Write is blocked due to TCP backpressure

Close no longer attempts to flush the write buffer and closes the underlying connectino immediately.
