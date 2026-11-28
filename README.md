# Bifrost – home lab relay

Remote access to a home lab without opening ports at home. One binary with three roles:
**heimdall** (relay on a VPS), **asgard** (agent in the home lab) and **hlidskjalf**
(web UI next to the agent). Design: the "Home Lab Relay: Architecture" document, variant v2.

- **iPhone → VPS:** mTLS on TCP 443; the VPS checks an allowlist of public keys.
- **Home lab ↔ VPS:** WireGuard, entirely in-process (wireguard-go with the gVisor netstack).
  No network interface, no root privileges, no port forwarding at home. Through the tunnel,
  only the web app's single stream port in the home lab is reachable, not the home network.
- **iPhone ↔ home lab:** end-to-end with Noise (`Noise_IK`, `Noise_IKpsk2` for pairing).
  The VPS only ever sees ciphertext.

> Not independently audited. Shipped as signed `.deb` releases and in daily use on a
> single home lab, but review it yourself before you rely on it.

## What's inside

| Package | Contents |
| --- | --- |
| `cmd/bifrost` | The single binary: `heimdall`, `asgard`, `hlidskjalf`, `pair`/`devices`/`revoke`, `client`, `upgrade`, `version` |
| `internal/relay` | TLS for devices, key allowlist, per-IP rate limit, one WireGuard peer per agent, control channel, one TCP connection through the tunnel per device connection |
| `internal/agent` | In-process WireGuard with keepalive, control channel with backoff, Noise responder, per-device service rights, pairing, revocation, admin API |
| `internal/service` | The boundary between transport and services: `Channel`, `Service`, type registry |
| `internal/services/tcp` | Passthrough service: a channel becomes a TCP connection to a fixed target |
| `internal/services/mqtt` | MQTT service: JSON messages from the device, MQTT to the broker, topic allowlist, sender identity |
| `internal/mqttgw` | Config and topic rules of the MQTT service (broker login, allowlists, sender identity) |
| `internal/mqttc` | Small MQTT 3.1.1 client used by the MQTT service |
| `internal/update` | `bifrost upgrade`: fetch the latest release, verify the minisign signature, install with apt, health check, rollback |
| `internal/web` | Hlidskjalf: web UI for devices and pairing (login, QR codes, revoke) |
| `internal/wg` | In-process WireGuard tunnel (wireguard-go, netstack) |
| `internal/client` | The app's tunnel core: pairing, channels, local port forwarding (CLI) |
| `mobile` | gomobile binding of the tunnel core for iOS (`Bifrost.xcframework`) |
| `internal/wire` | Framing, Noise handshake, `SecureConn`, TLS pinning |
| `internal/keys` | Ed25519 (TLS), X25519 (Noise and WireGuard), fingerprints |
| `internal/e2e` | End-to-end test including attack scenarios |

Not yet included: push (APNs/FCM/ntfy), metrics, P-256 keys in the Secure Enclave.

## Install

Releases contain `.deb` packages with hardened systemd units, binaries for
linux/darwin and a signed `SHA256SUMS`. See [docs/install.md](docs/install.md);
how releases are made is in [docs/release.md](docs/release.md).
`bifrost version` prints the installed version; `sudo bifrost upgrade` installs the
latest signed release (optionally daily via `bifrost-upgrade.timer`).

| Unit | Host | Purpose |
| --- | --- | --- |
| `bifrost-heimdall.service` | VPS | relay |
| `bifrost-asgard.service` | home lab | agent |
| `bifrost-hlidskjalf.service` | home lab | web UI |
| `bifrost-check.timer` | home lab | optional end-to-end check every 5 minutes (see below) |
| `bifrost-upgrade.timer` | both | optional daily self-update (04:00 plus up to one hour) |

No unit is enabled on install. Configs live in `/etc/bifrost/*.json`; the package never
writes or replaces them. On every install or upgrade the package restarts the services that
are running and starts the two timers again if they are enabled but have failed.

Debian has an unrelated package that is also called `bifrost`. From v0.3.1 on, this
package has epoch 1 (`1:0.3.1`) and installs an apt pin (`/etc/apt/preferences.d/bifrost`)
so `unattended-upgrades` cannot replace it with Debian's. Details in
[docs/install.md](docs/install.md).

## Build and test

```sh
go build -o bifrost ./cmd/bifrost     # Go 1.23 or newer
go test -race ./...
```

The test brings up relay and agent with real WireGuard over UDP on localhost and checks:
pairing, 3 MB through the tunnel, rejection of services that are not allowed, single-use tokens,
a simulated compromised relay (knows the token hash, not the token),
that only the agent's stream port is reachable through the tunnel, and that revocation
closes active connections immediately.

## Setup

Install the package on both hosts first ([docs/install.md](docs/install.md)); the example
configs are in `/usr/share/doc/bifrost/examples/` (and in `examples/` here).

1. On the VPS: copy `heimdall.json` to `/etc/bifrost/heimdall.json`, adjust it and run
   `systemctl enable --now bifrost-heimdall`. The log (`journalctl -u bifrost-heimdall`) shows
   the **relay pin** and the **relay WireGuard key**. Both go into `asgard.json`.
2. In the home lab: copy `asgard.json` to `/etc/bifrost/asgard.json`, adjust it and run
   `systemctl enable --now bifrost-asgard`. The log shows the **agent WireGuard key**. It goes
   into `heimdall.json` under `agents.homelab.wg_pub`; then restart `bifrost-heimdall`.
3. Open on the VPS: TCP 443 (devices) and UDP 51820 (WireGuard). At home: nothing.
4. Pair a device: `bifrost pair -name iphone -services mqtt` shows a QR code and `bifrost1:…`
   (valid for 5 minutes, single use). Add `-user alice` to bind the code to an app user
   (see [User and device name](#user-and-device-name)).
5. Pair the "app": `bifrost client pair -state phone -code bifrost1:… [-user alice] [-device-name "Alice's iPhone"]`.
6. Open a tunnel: `bifrost client forward -state phone -L mqtt=127.0.0.1:11883`,
   then e.g. `mosquitto_sub -h 127.0.0.1 -p 11883 -t 'home/#'`.
7. List and revoke devices: `bifrost devices`, `bifrost revoke -name iphone`.

Bind the agent's admin API (`admin`) to `127.0.0.1` or the LAN only.

Without the package, the same works by hand: `bifrost heimdall -config heimdall.json` and
`bifrost asgard -config asgard.json`.

### End-to-end check

`bifrost-check` (with `bifrost-check.timer`, every 5 minutes) tests the whole path
home lab → VPS → WireGuard → agent → MQTT broker: it opens a forward with a paired
monitor device, publishes to the broker and reports the result to a push monitor
(`PING_URL`, `/fail` appended on failure). Pair a device for the `bifrost-mon` user, then
put `MQTT_PASS` and `PING_URL` into `/etc/bifrost-monitor.env` (mode 0600); the optional
variables are listed at the top of `packaging/scripts/bifrost-check`.

## User and device name

During pairing the app may send two optional labels in its first encrypted message,
next to the relay key:

```json
{"relay_id": "…", "user": "alice", "device_name": "Alice's iPhone"}
```

The agent stores them on the device record (`user`, `device_name`) and shows them in
`bifrost devices`. They are trimmed, stripped of control characters and limited to 64
characters. The name given with `bifrost pair -name` stays the primary key: revocation,
logs and the service allowlist all use it.

Backward compatible in both directions: old apps that send only `relay_id` still pair
(the labels stay empty), and old agents ignore the new fields.

Security:

- `user` and `device_name` are **self-asserted** by the app. Whoever holds the pairing
  code can claim any user. Without a binding they are informational only; do not base
  authorization on them.
- `bifrost pair -name iphone -services mqtt -user alice` binds the code to a user: the app
  must send exactly `alice`, otherwise the agent rejects the pairing and **burns the
  token** (a second try with the same code fails), so the user name cannot be guessed
  with one code. The device record then has `"user_bound": true`. This protects against a
  leaked QR code being used by someone who does not know the user name, but it is not
  authentication of the user: the user name is not a secret.
- Like the rest of the pairing confirmation, the labels travel inside Noise
  (`Noise_IKpsk2`); the relay never sees them.

## Services

bifrost itself is only the transport: relay, Noise, pairing and which device may open
which service. Everything a message means belongs to a **service** in the agent and to the
app on the other end. The core packages (`agent`, `client`, `relay`, `wire`, `mobile`)
import no service; a test checks that. Service types register themselves with
`internal/service`, and the binary imports them via `internal/services/all`.

Every connection from a device starts, inside Noise, with the service marker

```json
{"open": "midgard", "mode": "msg"}
```

The agent checks that the device was paired for `midgard`, that the service supports the
mode, and answers `{"ok": true, "mode": "msg"}`. Two modes exist:

| Mode | On the wire | Used for |
| --- | --- | --- |
| `stream` (default, all clients before v0.4.0) | A byte stream cut into Noise messages; boundaries mean nothing | Passthrough to a TCP target |
| `msg` | Each Noise message is one message (at most 65 519 bytes); boundaries are kept | Message services such as MQTT |

Services in `asgard.json`:

```json
"services": {
  "ha":      {"type": "tcp", "target": "192.168.10.20:8123"},
  "mqtt":    "127.0.0.1:1883",
  "midgard": {
    "type": "mqtt",
    "broker": "127.0.0.1:1883",
    "username": "midgard",
    "password_file": "${CREDENTIALS_DIRECTORY}/bifrost-mqtt-midgard",
    "publish": ["midgard/+/command"],
    "subscribe": ["midgard/#"]
  }
}
```

A plain `"host:port"` string is short for a `tcp` service. The section `mqtt_gateways`
from earlier versions still works: each entry there is an `mqtt` service. Service names
are what you pair: `bifrost pair -name iphone -services midgard,ha`.

### tcp

Stream mode only. Each channel becomes one TCP connection to `target`; bytes pass through
unchanged. Use it for web UIs or for devices that speak a protocol themselves.

### mqtt

The agent logs in to the broker with its own credentials (`username` and the password from
`password_file`); the device has no broker password and needs no MQTT library.

The service only has message mode: one JSON object per message. Device to agent:

```json
{"op":"sub",   "id":1, "filter":"midgard/#", "qos":1}
{"op":"unsub", "id":2, "filter":"midgard/#"}
{"op":"pub",   "id":3, "topic":"midgard/tg/command", "payload":{"action":"open"}, "qos":1, "retain":false}
{"op":"ping",  "id":4}
```

A `pub` carries one of `payload` (any JSON value, sent as its JSON text), `payload_text`
(sent as is) or `payload_b64`. With an `id`, every op is answered with
`{"op":"ack","id":n}` or `{"op":"error","id":n,"error":"..."}`; a denied op does not end
the channel. Agent to device:

```json
{"op":"msg", "topic":"midgard/tg/state", "payload":{"state":"open"}, "retain":true}
```

with `payload` if the MQTT payload is JSON, else `payload_text` or `payload_b64`. If the
broker connection ends, the device gets `{"op":"error","error":"broker connection lost"}`
and the channel closes.

The stream mode, in which apps before v0.4.0 spoke MQTT themselves through the channel, was
removed in v0.5.0; such apps get "service does not support mode" and need an update.

Every PUBLISH must match a filter in `publish` and every SUBSCRIBE must lie
within a filter in `subscribe` (`+` and `#` allowed). **Sender identity:** every published
JSON object gets a field set by the agent from the pairing, e.g.
`"bifrost": {"device": "michael-iphone", "user": "michael", "user_bound": true}`. A
`bifrost` field sent by the device is overwritten, so the receiver can trust it. Turn it off
per service with `"identity": false`. The agent log shows every publish with device, user
and topic.

The pairing is the only credential the device holds: revoking the device in bifrost ends
its MQTT access immediately, and the broker password never leaves the home lab. Keep the
password root-only and let systemd pass it in (the shipped unit has `ImportCredential=bifrost-*`):

```sh
install -d -m 700 /etc/credstore
install -m 600 /dev/stdin /etc/credstore/bifrost-mqtt-midgard   # type the password, then Ctrl-D
systemctl restart bifrost-asgard
```

`password_file` expands environment variables; outside systemd any readable path works.

### From the command line

`bifrost client channel` opens a channel in message mode and connects it to stdin and
stdout, one message per line:

```sh
echo '{"op":"pub","id":1,"topic":"midgard/tg/command","payload":{"action":"open"}}' |
  bifrost client channel -state phone -service midgard
```

`bifrost client forward` still forwards a local port to a stream service. Any process on
the machine can use that port with the device's identity, so use it only on a machine you
alone use.

## Mobile (iOS) binding

Package `mobile` wraps the tunnel core for [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile).
It does not depend on wireguard-go or gVisor (checked by a test and by the build script),
so the framework stays small.

Apps can use it through Swift Package Manager: add `https://github.com/MichaelBMF/bifrost`
as a package dependency and link the `Bifrost` library. Each release attaches the prebuilt
`Bifrost.xcframework.zip`, and `Package.swift` pins its checksum (see [docs/release.md](docs/release.md)).

To build the framework yourself (needs Xcode and Go; installs gomobile/gobind in the version pinned in `go.mod`):

```sh
scripts/build-ios.sh <output-dir>       # -> <output-dir>/Bifrost.xcframework (ios + iossimulator)
```

`IOS_MIN` (default `16.0`) sets the deployment target. Add the xcframework to the app target
("Embed & Sign" is not needed, it is a static framework) and `import Bifrost`.

The Go API, with the generated Swift signatures:

| Go | Swift |
| --- | --- |
| `NewClient(stateDir string) (*Client, error)` | `MobileNewClient(_ stateDir: String?, _ error: NSErrorPointer) -> MobileClient?` |
| `(*Client) IsPaired() bool` | `func isPaired() -> Bool` |
| `(*Client) Info() string` | `func info() -> String` (JSON) |
| `(*Client) Pair(code, user, deviceName string) (string, error)` | `func pair(_ code: String?, user: String?, deviceName: String?, error: NSErrorPointer) -> String` (JSON) |
| `(*Client) OpenChannel(service string, h MessageHandler) (*Channel, error)` | `func openChannel(_ service: String?, h: MobileMessageHandlerProtocol?) throws -> MobileChannel` |
| `(*Channel) Send(msg []byte) error` | `func send(_ msg: Data?) throws` |
| `(*Channel) Close()` / `IsOpen() bool` | `func close()` / `func isOpen() -> Bool` |
| `MessageHandler.OnMessage(msg []byte)` / `OnClose(err string)` | `func onMessage(_ msg: Data?)` / `func onClose(_ err: String?)` |
| `(*Client) StopAll()` | `func stopAll()` |
| `(*Client) Probe(service string) error` | `func probe(_ service: String?) throws` |
| `(*Client) Unpair() error` | `func unpair() throws` |

```swift
import Bifrost

let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("bifrost").path
var err: NSError?
guard let tunnel = MobileNewClient(dir, &err) else { throw err! }

if !tunnel.isPaired() {
    var perr: NSError?
    let result = tunnel.pair(scannedCode, user: "alice", deviceName: UIDevice.current.name, error: &perr)
    if let perr { throw perr }
    print(result)   // {"name":"iphone","services":["mqtt"],"user":"alice",...}
}

final class Handler: NSObject, MobileMessageHandlerProtocol {
    func onMessage(_ msg: Data?) { /* one message of the service, e.g. JSON */ }
    func onClose(_ err: String?) { /* "" after close(), else why it ended */ }
}

let channel = try tunnel.openChannel("midgard", h: Handler())
try channel.send(Data(#"{"op":"sub","id":1,"filter":"midgard/#","qos":1}"#.utf8))
```

On Android the same API comes from the AAR (`mobile.Mobile.newClient`, `client.openChannel`,
a class implementing `mobile.MessageHandler`).

Notes for the app:

- `stateDir` holds `bifrost.key` (device keys, mode 0600) and `bifrost.json` (pairing state).
  Exclude it from iCloud backup if the identity should not move to another device.
- `Info()` returns `{"paired", "relay", "agent_id", "services", "name", "user", "device_name",
  "device_fp", "agent_fp", "paired_at"}`. `device_fp` exists
  before pairing, so it can be shown for comparison with the agent log.
- A channel opens no port: its messages stay inside the app's process, so no other app
  on the device can use the tunnel. Each channel is its own end-to-end connection. iOS
  suspends the app in the background; call `stopAll()` there (it closes all channels) and open the channel again when the app becomes active.
- There is no local port forward in the binding any more (`StartForward` was removed in
  v0.5.0). Port forwards are only for the CLI (`bifrost client forward`, tcp services).
- `Probe("mqtt")` checks the whole path (relay, pin, device allowed, Noise, service reachable)
  with a 20 s timeout.
- `Unpair()` deletes the pairing state and replaces the keys, but does not notify the agent;
  revoke the device there with `bifrost revoke -name …`.
- `Pair` fails if the client is already paired; call `Unpair()` first.

## Web UI (Hlidskjalf)

`bifrost hlidskjalf` is a small web UI that runs next to the agent: list devices,
pair a new one (QR code to scan with the app, valid 5 minutes, single use) and revoke
devices. It talks to the agent's admin API on localhost and only exposes its own pages,
never the admin API.

- **Login:** users with bcrypt password hashes in the config (`bifrost hlidskjalf -hash`).
  Sessions are HttpOnly, SameSite=Strict cookies; every form carries a CSRF token; failed
  logins are rate limited per IP.
- **TLS:** by default a self-signed certificate is created in `state_dir`; its SHA-256
  fingerprint is logged so the browser warning can be checked once. `tls.mode` can also be
  `files` (own certificate) or `off` (only behind a TLS reverse proxy).
- **Protected devices:** devices listed in `protected` are marked and cannot be revoked from
  the UI. Revoking any other device requires typing its name.
- **User binding:** the optional user field is passed to the agent as `user`; agents with
  user support then reject a pairing from a different username.

Setup next to asgard (see `examples/hlidskjalf.json`; the unit
`packaging/systemd/bifrost-hlidskjalf.service` comes with the package):

```sh
bifrost hlidskjalf -hash                      # prints a bcrypt hash; put it into the config
install -m 600 hlidskjalf.json /etc/bifrost/hlidskjalf.json
systemctl enable --now bifrost-hlidskjalf
journalctl -u bifrost-hlidskjalf | grep SHA-256   # certificate fingerprint
```

## How it works

1. Agent → VPS: WireGuard handshake (UDP), then the control channel `10.8.0.1:7000` inside the tunnel
   with `Hello{role: agent}`. The VPS identifies the agent by its tunnel address, which
   WireGuard only allows for the configured key.
2. iPhone → VPS: TLS 1.3 with a client certificate, then `Hello{role: dial|pair}`.
3. VPS → agent: a new TCP connection to `10.8.0.2:9000` inside the tunnel, `StreamHeader{kind, relay_id}`,
   after that bytes are just passed through.
4. iPhone ↔ agent: Noise_IK. The agent checks that the Noise key and the relay key belong
   to the same device, then reads the service marker `{"open":"midgard","mode":"msg"}` and
   hands the channel to that service; what a service may reach comes only from `asgard.json`.
5. Pairing: `Noise_IKpsk2` with the token from the QR code as PSK. The device is stored only after
   the app's first encrypted message `{"relay_id", "user"?, "device_name"?}`.

All messages are `[2-byte length][data]`.

## License

MIT, see [LICENSE](LICENSE).
