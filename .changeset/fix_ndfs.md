---
default: patch
---

# Fix NDFs

#43 by @chris124567

Fix `TestContext` and `TestCovertStream`

`go test ./v3 -v -race -count=50 -run="TestCovertStream"` and  `go test ./v3 -v -race -count=50 -run="TestContext"` succeed
