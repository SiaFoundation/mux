---
default: patch
---

# Include frame details in ErrUnknownStream

ErrUnknownStream is now wrapped with the frame's ID, length, flags, and whether it was covert, so it must be compared with errors.Is.
