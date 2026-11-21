# Bifrost – home lab relay (prototype, v2)

Prototype for the "Home Lab Relay: Architecture" design, variant **v2**:

- **iPhone → VPS:** mTLS on TCP 443; the VPS checks an allowlist of public keys.
- **Home lab ↔ VPS:** WireGuard, entirely in-process (wireguard-go with the gVisor netstack).
  No network interface, no root privileges, no port forwarding at home. Through the tunnel,
  only the web app's single stream port in the home lab is reachable, not the home network.
- **iPhone ↔ home lab:** end-to-end with Noise (`Noise_IK`, `Noise_IKpsk2` for pairing).
  The VPS only ever sees ciphertext.

> Prototype: not audited, not meant for production.

## What's inside

| Package | Contents |
| --- | --- |
| `internal/relay` | TLS for devices, key allowlist, per-IP rate limit, one WireGuard peer per agent, control channel, one TCP connection through the tunnel per device connection |
| `internal/agent` | In-process WireGuard with keepalive, control channel with backoff, Noise responder, per-device services, pairing, revocation, admin API |
| `internal/web` | Hlidskjalf: web UI for devices and pairing (login, QR codes, revoke) |
| `internal/wg` | In-process WireGuard tunnel (wireguard-go, netstack) |
| `internal/client` | The app's tunnel core: pairing and local port forwarding |
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

1. Copy `heimdall.json` from `examples/` to the VPS and start `bifrost heimdall -config heimdall.json`.
   The log shows the **relay pin** and the **relay WireGuard key**. Both go into `asgard.json`.
2. Adjust `asgard.json` in the home lab and start `bifrost asgard -config asgard.json`.
   The log shows the **agent WireGuard key**. It goes into `heimdall.json` under `agents.homelab.wg_pub`.
   Restart the relay.
3. Open on the VPS: TCP 443 (devices) and UDP 51820 (WireGuard). At home: nothing.
4. Pair a device: `bifrost pair -name iphone -services mqtt` shows a QR code and `bifrost1:…`
   (valid for 5 minutes, single use). Add `-user alice` to bind the code to an app user
   (see [User and device name](#user-and-device-name)).
5. Pair the "app": `bifrost client pair -state phone -code bifrost1:… [-user alice] [-device-name "Alice's iPhone"]`.
6. Open a tunnel: `bifrost client forward -state phone -L mqtt=127.0.0.1:11883`,
   then e.g. `mosquitto_sub -h 127.0.0.1 -p 11883 -t 'home/#'`.
7. List and revoke devices: `bifrost devices`, `bifrost revoke -name iphone`.

Bind the agent's admin API (`admin`) to `127.0.0.1` or the LAN only.

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
| `(*Client) StartForward(service string, port int) (int, error)` | `func startForward(_ service: String?, port: Int, ret0_: UnsafeMutablePointer<Int>?) throws` |
| `(*Client) ForwardPort(service string) int` | `func forwardPort(_ service: String?) -> Int` |
| `(*Client) StopForward(service string)` | `func stopForward(_ service: String?)` |
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

var port = 0
try tunnel.startForward("mqtt", port: 0, ret0_: &port)   // 0 = pick a free port
// connect the MQTT client to 127.0.0.1:port
```

Notes for the app:

- `stateDir` holds `bifrost.key` (device keys, mode 0600) and `bifrost.json` (pairing state).
  Exclude it from iCloud backup if the identity should not move to another device.
- `Info()` returns `{"paired", "relay", "agent_id", "services", "name", "user", "device_name",
  "device_fp", "agent_fp", "paired_at", "forwards": {"mqtt": 54321}}`. `device_fp` exists
  before pairing, so it can be shown for comparison with the agent log.
- Every connection to the local port opens its own end-to-end tunnel. iOS suspends the app
  in the background; call `stopAll()` there and `startForward` again when it becomes active
  (with `port: 0` this may return a different port).
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
journalctl -u bifrost-hlidskjalf | grep fingerprint
```

## How it works

1. Agent → VPS: WireGuard handshake (UDP), then the control channel `10.8.0.1:7000` inside the tunnel
   with `Hello{role: agent}`. The VPS identifies the agent by its tunnel address, which
   WireGuard only allows for the configured key.
2. iPhone → VPS: TLS 1.3 with a client certificate, then `Hello{role: dial|pair}`.
3. VPS → agent: a new TCP connection to `10.8.0.2:9000` inside the tunnel, `StreamHeader{kind, relay_id}`,
   after that bytes are just passed through.
4. iPhone ↔ agent: Noise_IK. The agent checks that the Noise key and the relay key belong
   to the same device, then `{"open":"mqtt"}`; the target comes only from `asgard.json`.
5. Pairing: `Noise_IKpsk2` with the token from the QR code as PSK. The device is stored only after
   the app's first encrypted message `{"relay_id", "user"?, "device_name"?}`.

All messages are `[2-byte length][data]`.

## License

MIT, see [LICENSE](LICENSE).
