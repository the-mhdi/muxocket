# muxocket

Go package that multiplexes many bidirectional byte streams ("channels") over
one connection: TCP, Unix sockets, UDP or any `net.Conn`. It has per-channel
and per-session flow control, optional reliability (ARQ) for lossy
transports, keepalive, graceful close and session resumption across
reconnects or IP changes.

## Protocol

### Framing
Every frame has a fixed 17-byte big-endian header, followed by `length`
payload bytes for DATA frames only:

```
 0        4    5        9                 17
 +--------+----+--------+-----------------+----------------+
 | length |flag|  chID  |     offset      | payload ...    |
 |  u32   | u8 |  u32   |      u64        | (DATA only)    |
 +--------+----+--------+-----------------+----------------+
```

| flag | name   | meaning |
|------|--------|---------|
| 1 | DATA   | `length` payload bytes; `offset` = stream position of the first byte |
| 2 | NOOP   | ignored |
| 3 | FIN    | sender finished writing; `offset` = final stream length |
| 4 | PING   | keepalive probe |
| 5 | PONG   | keepalive reply |
| 6 | UPD    | window update: grant `length` bytes of credit (`chID` 0 = session window) |
| 7 | ACK    | reliability only: cumulative ACK, everything below `offset` received |
| 8 | GOAWAY | last frame of a graceful close; peer closes immediately instead of waiting to resume |
- Payloads are at most `MaxFrameDataSize` (default 32 KiB). Larger writes are
  split into several frames.
- On stream transports, frames are written back-to-back. On datagram
  transports, one or more whole frames go in each datagram, which must fit
  the MTU.
- The writer batches queued frames into a single `writev` call.

### Handshake

The dialer speaks first. Each message is prefixed by a 2-byte length and
signed with Ed25519.

1. **Initiator → responder:** protocol version, session ID (zero for a new
   session), nonce (0 for a new session), 32 random bytes, the initiator's
   public key and a signature.
2. **Responder → initiator:** version, the assigned 32-byte session ID,
   nonce, and the session parameters: stream window, session window, update
   ratio, max frame size, reliability on/off and resumption on/off. Then the
   responder's public key, and a signature over these fields plus a hash of
   the initiator's request. That binding means a recorded response can't be
   replayed against a different handshake.

The **listener decides** window sizes, frame size and reliability; the
dialer adopts them. Resumption is used only if both sides allow it.

**Resumption:** if the transport drops, the session stays suspended for
`ConnectionResumeTimeout`. The dialer reconnects and sends a new handshake
with the existing session ID and a nonce higher than the last one,
signed with the same key. The listener checks the key and nonce, the dialer
checks the responder's key is unchanged, and the session carries on over
the new connection. Channels and stream offsets survive. Without
reliability, frames in flight during the drop can be lost.

> **Security note:** the handshake detects tampering and prevents replays
> and session hijacking, but keys are generated per session and **traffic is
> not encrypted**. Unless you pin keys yourself, this doesn't authenticate
> who the peer is. Run it over TLS, WireGuard or similar when you need
> confidentiality or peer identity.

### Channels

- A channel is identified by a **label** of 1–6 characters `[A-Za-z0-9]`,
  case-insensitive. It's encoded into the 32-bit `chID` (ID 0 is reserved
  for session-level frames).
- **Labels are not case-sensitive.** Upper- and lowercase letters encode to
  the same value, so `"Web"`, `"WEB"` and `"web"` are one channel:
  - a peer that opens `"Web"` is connected to a peer that opens `"web"`;
  - on one session, once `"web"` is open, `OpenChannel("WEB")` fails with
    "channel with this label and ID already exists";
  - `Channel.Label()` is decoded from the ID, so it always returns lowercase
    (`"web"`), whatever spelling was passed to `OpenChannel`.

  This is a size limit, not an oversight. With 36 symbols, every label of
  up to 6 characters fits in 32 bits (about 2.24 billion IDs). With 62
  case-sensitive symbols, 6-character labels would need about 57.7 billion.
- There is **no open frame.** Both peers call `OpenChannel` with the same
  label. Data that arrives before the local `OpenChannel` is held briefly
  (a small per-session buffer, about 5 s) and delivered when the channel
  opens. Data for labels that are never opened is dropped. Repeated drops
  for unknown channels (`MaxUnknownChannelErrors`) close the session.
- **Flow control:** credit-based, per channel (`InitialStreamWindow`,
  2 MiB) and per session (`InitialSessionWindow`, 4 MiB). Receivers return
  credit with UPD frames as the application reads, so a slow reader slows
  its sender instead of buffering without limit.
- **Half-close:** `CloseWrite` sends FIN, after which the peer's `Read`
  returns `io.EOF`. `Close` closes both directions. The channel is freed once
  both sides are done and, with reliability, everything is acknowledged.
- **Reliability** (`Config.Reliability`, chosen by the listener): offsets,
  cumulative ACKs, retransmission with exponential backoff, and in-order
  reassembly. Use it on UDP or other lossy transports. TCP doesn't need it,
  except to keep unacknowledged data across a resumption.

## API

| | |
|---|---|
| `Listen(ln net.Listener, cfg *Config) (*Listener, error)` | stream listener (TCP, Unix) |
| `ListenPacket(pc net.PacketConn, mtu int, cfg ...*Config) (*Listener, error)` | datagram listener (UDP) |
| `(*Listener).Accept() (*Session, error)` / `Close()` / `Addr()` | |
| `Dial(conn)`, `DialConfig(conn, cfg)`, `(&Dialer{...}).Dial(conn)` | client handshake over an existing `net.Conn` |
| `Dialer{Config, PrivateKey, HandshakeTimeout, Redial}` | `Redial` enables automatic resumption |
| `(*Session).Resume(conn net.Conn) error` | manual resumption on a new connection |
| `(*Session).OpenChannel(label string) (*Channel, error)` | |
| `(*Session).Close()` / `Done()` / `IsClosed()` / `ID()` / `RemoteAddr()` | |
| `*Channel`: `Read`, `Write`, `CloseWrite`, `Close`, `Done`, `Label` | `io.ReadWriteCloser` |
| `*Channel`: `ReadFrom`, `WriteTo` | used by `io.Copy` to avoid extra copies |
| `NewSession(conn io.ReadWriteCloser, cfg *Config) *Session` | raw session with no handshake (tests, custom transports) |
| `DefaultConfig() *Config` | |

`Channel` is safe for one reader and one writer at a time.

## Examples
### Server

```go
tcpLn, err := net.Listen("tcp", ":9000")
if err != nil {
	log.Fatal(err)
}
ln, err := muxocket.Listen(tcpLn, muxocket.DefaultConfig())
if err != nil {
	log.Fatal(err)
}
defer ln.Close()

for {
	sess, err := ln.Accept()
	if err != nil {
		return
	}
	go func(s *muxocket.Session) {
		defer s.Close()
		ch, err := s.OpenChannel("echo") // the client opens "echo" too
		if err != nil {
			return
		}
		io.Copy(ch, ch) // echo until the client half-closes
		ch.CloseWrite()
		<-ch.Done()
	}(sess)
}
```

### Client

```go
conn, err := net.Dial("tcp", "server:9000")
if err != nil {
	log.Fatal(err)
}
sess, err := muxocket.Dial(conn)
if err != nil {
	log.Fatal(err)
}
defer sess.Close()

ch, err := sess.OpenChannel("echo")
if err != nil {
	log.Fatal(err)
}
ch.Write([]byte("hello"))
ch.CloseWrite()                // FIN: the server's io.Copy ends
reply, _ := io.ReadAll(ch)     // "hello", then EOF
fmt.Println(string(reply))
```

### Tunnel / proxy pattern

`io.Copy` uses `ReadFrom` and `WriteTo` automatically, so data moves between
a TCP connection and a channel without an extra copy through `io.Copy`'s
buffer:

```go
func pipe(ch *muxocket.Channel, c net.Conn) {
	go func() {
		io.Copy(ch, c)   // local -> tunnel
		ch.CloseWrite()
	}()
	io.Copy(c, ch)       // tunnel -> local
	c.Close()
	ch.Close()
}
```

### UDP with reliability and automatic resumption

```go
// server
pc, _ := net.ListenPacket("udp", ":9000")
cfg := muxocket.DefaultConfig()
cfg.Reliability = true // the listener decides; clients adopt it
ln, _ := muxocket.ListenPacket(pc, 1400, cfg)

// client
d := &muxocket.Dialer{
	Redial: func() (net.Conn, error) { return net.Dial("udp", "server:9000") },
}
conn, _ := net.Dial("udp", "server:9000")
sess, _ := d.Dial(conn) // on a transport failure the session redials and resumes
```

## Configuration

`DefaultConfig()` values:

| field | default | notes |
|---|---|---|
| `MaxFrameDataSize` | 32 KiB | max payload per frame (listener decides) |
| `InitialStreamWindow` / `InitialSessionWindow` | 2 MiB / 4 MiB | flow-control credit (listener decides) |
| `MaxWriteBufferSize` | 32 | write queue depth, in frames |
| `KeepAlive`, `KeepAliveInterval`, `KeepAliveTimeout` | on, 10 s, 30 s | PING/PONG; dead transports are detected |
| `MaxUnknownChannelErrors` | 128 | session closes after this many frames for unknown channels |
| `Reliability` | off | ARQ (listener decides) |
| `RetransmitTimeout`, `MaxRetransmit`, `AckInterval` | 150 ms, 8, 10 ms | ARQ tuning; backoff is exponential (capped at 64× RTO) |
| `AllowConnectionResumption`, `ConnectionResumeTimeout` | on, 5 s | how long a dropped session waits to be resumed |
| `MaxPendingChannels` | 32 | max channels with buffered early data (data for a label not opened locally yet); beyond this, frames are dropped |
| `MaxPendingEarlyFramesPerSession` | 16 | early-data budget per session, in full frames (16 × `MaxFrameDataSize` = 512 KiB by default); beyond this, frames are dropped |
| `PendingFramesTTL` | 5 s | how long early data waits for a local `OpenChannel` before it's discarded |
| `ClosedChannelFrameLingerTTL` | 5 s | reliability only: how long late retransmits for a closed channel are dropped instead of buffered |