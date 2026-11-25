---
default: patch
---

# Fix the Mux closing when frames for a closed Stream arrive late

Frames for a closed Stream are now discarded however late they arrive and however many there are, instead of closing the Mux with ErrUnknownStream or ErrStreamFlood. Both errors have been removed, as they are no longer returned.
