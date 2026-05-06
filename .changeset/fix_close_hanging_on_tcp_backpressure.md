---
default: patch
---

# Fix Close hanging indefinitely when conn.Write is blocked due to TCP backpressure

Close now waits at most 5 seconds for pending writes to flush before tearing
down the connection.
