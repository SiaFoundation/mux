# [![Sia Core](https://sia.tech/banners/sia-banner-mountains.png)](http://sia.tech)

[![GoDoc](https://godoc.org/go.sia.tech/mux?status.svg)](https://godoc.org/go.sia.tech/mux)

# mux

SiaMux is a high-performance stream multiplexer. It allows you
to operate many distinct bidirectional streams on top of a single underlying
connection. We built it for [Sia](https://sia.tech) because we weren't satisfied
with other multiplexers available at the time.

As a privacy-focused multiplexer, SiaMux behaves differently from other muxes.
It transparently encrypts the connection, and supports authentication via
Ed25519 public keys. To hinder metadata analysis, It always writes data in
fixed-size "packets," inserting padding as necessary. Lastly, SiaMux implements
a unique feature known as *covert streams*. Covert streams hide their data
within the padding of other streams, making them completely undetectable to
network analysis (at the cost of greatly reduced throughput). SiaMux can be used
for any application in need of a multiplexer, but its privacy features make it a
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

To create a covert stream use `m.DialCovertStream`. The accepting peer calls
`m.AcceptStream` as usual.

## Benchmarks

SiaMux allocates very little memory (some buffers at startup, plus the `Stream`
objects), does not use channels, and spawns just two goroutines per multiplexer.
Despite encrypting the connection, in benchmarks SiaMux is competitive with
alternatives such as [yamux](github.com/hashicorp/yamux),
[muxado](https://github.com/inconshreveable/muxado), and
[smux](https://github.com/xtaci/smux).

```
BenchmarkMux/1            5156 ns/op     830.90 MB/s      193977 frames/sec        0 allocs/op
BenchmarkMux/2            9550 ns/op     897.21 MB/s      210562 frames/sec        0 allocs/op
BenchmarkMux/10          50567 ns/op     847.19 MB/s      198281 frames/sec        0 allocs/op
BenchmarkMux/100        449494 ns/op     953.07 MB/s      223966 frames/sec        0 allocs/op
BenchmarkMux/500       2184647 ns/op     980.48 MB/s      229271 frames/sec        7 allocs/op
BenchmarkMux/1000      4548476 ns/op     941.85 MB/s      221448 frames/sec       28 allocs/op
BenchmarkCovertStream    45805 ns/op      93.53 MB/s       21833 frames/sec        2 allocs/op
```