# [![Sia Core](https://sia.tech/banners/sia-banner-mux.png)](http://sia.tech)

[![GoDoc](https://godoc.org/go.sia.tech/mux?status.svg)](https://godoc.org/go.sia.tech/mux)

# mux

SiaMux is a high-performance stream multiplexer. It allows you
to operate many distinct bidirectional streams on top of a single underlying
connection. We built it for [Sia](https://sia.tech) because we weren't satisfied
with other multiplexers available at the time.

As a privacy-focused multiplexer, SiaMux behaves differently from other muxes.
It transparently encrypts the connection, and supports authentication via
Ed25519 public keys. To hinder metadata analysis, it always writes data in
fixed-size "packets," inserting padding as necessary. SiaMux can be used for any
application in need of a multiplexer, but its privacy features make it a
particularly good choice for p2p networks and other distributed systems.

## Usage

Dialer:

```go
conn, _ := net.Dial("tcp", addr)
defer conn.Close()
m, _ := mux.DialAnonymous(conn)
defer m.Close()
s := m.DialStream()
defer s.Close()
io.WriteString(s, "hello, world")
```

Listener:

```go
l, _ := net.Listen("tcp", addr)
conn, _ := l.Accept()
m, _ := mux.AcceptAnonymous(conn)
s, _ := m.AcceptStream()
defer s.Close()
io.Copy(os.Stdout, s)
```

For authenticated communication, use `mux.Dial`/`mux.Accept` with a
`crypto/ed25519` keypair.

## Benchmarks

SiaMux allocates very little memory (some buffers at startup, plus the `Stream`
objects), does not use channels, and spawns just two goroutines per multiplexer.
Despite encrypting the connection, in benchmarks SiaMux is competitive with
alternatives such as [yamux](github.com/hashicorp/yamux),
[muxado](https://github.com/inconshreveable/muxado), and
[smux](https://github.com/xtaci/smux).

```
BenchmarkMux/1           1221 ns/op     3517.96 MB/s      818917 frames/sec        0 allocs/op
BenchmarkMux/2           2643 ns/op     3251.42 MB/s      756858 frames/sec        0 allocs/op
BenchmarkMux/10         15646 ns/op     2745.76 MB/s      639151 frames/sec        0 allocs/op
BenchmarkMux/100       195125 ns/op     2201.66 MB/s      512501 frames/sec        0 allocs/op
BenchmarkMux/500       941216 ns/op     2282.16 MB/s      531237 frames/sec        2 allocs/op
BenchmarkMux/1000     1884418 ns/op     2279.75 MB/s      530677 frames/sec       11 allocs/op
```
