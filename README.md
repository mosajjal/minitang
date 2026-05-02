# minitang

[![ci](https://github.com/mosajjal/minitang/actions/workflows/ci.yml/badge.svg)](https://github.com/mosajjal/minitang/actions/workflows/ci.yml)
[![release](https://github.com/mosajjal/minitang/actions/workflows/release.yml/badge.svg)](https://github.com/mosajjal/minitang/actions/workflows/release.yml)

A small Go reimplementation of [Tang](https://github.com/latchset/tang) — the
network-bound encryption server used by Clevis for things like automatic LUKS
unlock. ~450 lines of Go, no external dependencies, and the binary builds
with [TinyGo](https://tinygo.org).

Wire-compatible with upstream tang: same JWK on-disk format, same `/adv` and
`/rec/<thumbprint>` endpoints, same McCallum–Relyea exchange. Existing
`tangd-keygen` keysets work unchanged.

## Why

Three reasons it exists:

- **Smaller binary**: ~6 MB statically linked vs. tang + libjose + libjansson
  + libhttp-parser + libssl shared library footprint.
- **Single static binary**: no system libraries, drop it in a container or
  a minimal image.
- **TinyGo target**: the protocol is small enough that you can build it
  with TinyGo and keep the binary tiny. There's a real twist here, see
  the [TinyGo notes](#the-tinygo-twist).

## Run modes

`minitang` has two run modes; pick whichever your supervisor prefers.

### 1. Inetd / socket-activated (default)

Reads one HTTP request from stdin, writes the response to stdout, exits.
This is the same shape as upstream tangd. **Works under both stdgo and
TinyGo builds.**

```sh
# Quick smoke test:
printf 'GET /adv HTTP/1.1\r\nHost: x\r\n\r\n' | minitang /var/db/minitang

# socat-driven listener:
socat TCP-LISTEN:8080,fork,reuseaddr EXEC:'minitang /var/db/minitang'
```

systemd socket activation is in [`contrib/systemd/`](contrib/systemd):

```sh
sudo cp contrib/systemd/minitang.socket    /etc/systemd/system/
sudo cp contrib/systemd/minitang@.service  /etc/systemd/system/
sudo systemctl enable --now minitang.socket
```

The unit ships with `DynamicUser=yes`, `ProtectSystem=strict`, and a
read-only bind on `/var/db/minitang`, so the per-connection process has
no write access anywhere by default.

### 2. Standalone HTTP server (`-listen`)

```sh
minitang -listen :8080 /var/db/minitang
```

This requires `net.Listen`, which works with the **stdgo build but not
TinyGo** — TinyGo's net package has no host-syscall backend, it expects a
`netdev` driver to be registered. If you want a long-lived listener under
TinyGo, front it with socat or systemd as above.

## Install

### Pre-built binaries

Grab from the [latest release](https://github.com/mosajjal/minitang/releases/latest):

- `minitang-linux-amd64`, `minitang-linux-arm64`, `minitang-linux-arm`
- `minitang-darwin-amd64`, `minitang-darwin-arm64`
- `minitang-freebsd-amd64`, `minitang-windows-amd64.exe`
- `minitang-tiny-linux-amd64` (TinyGo build, smaller)

Each ships with a `.sha256` next to it.

### Container

```sh
docker run --rm -p 8080:8080 -v /var/db/minitang:/var/db/minitang \
    ghcr.io/mosajjal/minitang:latest
```

The image is alpine + socat + the TinyGo binary. socat fronts a fork loop;
each connection spawns a fresh `minitang`. Dockerfile is in the repo root.

### From source

```sh
go install github.com/mosajjal/minitang@latest
```

Or with TinyGo:

```sh
git clone https://github.com/mosajjal/minitang
cd minitang
tinygo build -opt=z -no-debug -o minitang .
```

## Generate a keyset

`minitang` reads JWK files from a directory. Files prefixed with `.` are
treated as rotated keys — still usable for recovery, not advertised.

You need one signing key (alg `ES256`/`ES384`/`ES512`, key_ops
`sign`/`verify`) and one exchange key (alg `ECMR`, key_ops `deriveKey`).
The simplest tool is upstream's `tangd-keygen` script, or the included
[`contrib/keygen.sh`](contrib/keygen.sh) which uses
[`jose`](https://github.com/latchset/jose):

```sh
contrib/keygen.sh /var/db/minitang
```

## Layout

```
main.go      request dispatch (CGI mode + -listen mode)
keys.go      keyset loader
jwk.go       JWK type, RFC 7638 thumbprint, base64url helpers
jose.go      JWS flat signing (ES256/384/512) + ECMR scalar-mult recovery
contrib/     systemd units, keygen.sh
Dockerfile   alpine + socat + TinyGo binary
```

## The TinyGo twist

TinyGo's `net` package is built for embedded targets — it requires a
`netdever` driver to be registered before `Listen`/`Dial` will work,
because there's no host-syscall backend. The native `linux/amd64` target
gives you `Netdev not set` if you call `http.ListenAndServe`.

`minitang` sidesteps that by being CGI-style by default: it never opens a
socket. The binary uses `http.ReadRequest` on `os.Stdin` and writes the
response by hand to `os.Stdout`. Networking is the supervisor's problem
— exactly upstream tang's design, and a clean fit for both stdgo and
TinyGo.

Other TinyGo-driven choices:

- `crypto/elliptic.ScalarMult` (deprecated in stdgo, still present in
  TinyGo) for the recovery operation. `crypto/ecdh` only exposes the X
  coordinate of the shared point; Tang needs both X and Y.
- Hand-built JSON for the JWS protected header and the RFC 7638
  thumbprint canonicalization, so we don't depend on TinyGo's
  `encoding/json` map-key emission ordering matching stdgo's.
- One request, one process — no long-lived state, no SIGHUP, no
  goroutines.

Verified end-to-end against upstream tang's own test JWK fixtures with
TinyGo 0.41.1 on Linux: both `/adv` (JWS verifies under its advertised
P-521 key) and `/rec` (returns an on-curve point for a fresh client
ephemeral) work.

## Differences from upstream tang

- No SIGHUP-driven keyset reload. Restart the process (or, since each
  connection spawns a fresh process under socket activation, every
  request already picks up the latest keys on disk).
- No bundled `tangd-keygen` / `tangd-rotate-keys`. Use upstream's
  scripts or `contrib/keygen.sh`.
- Standalone `-listen` mode is provided, but the recommended deployment
  is still socket activation — it's how the original was designed and
  it's also the only way the TinyGo build can take TCP traffic.

## License

MIT — see [LICENSE](LICENSE). Tang itself is GPL-2.0+; this is a clean
reimplementation that talks the same wire protocol but shares no code.
