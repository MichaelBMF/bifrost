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
| `internal/agent` | In-process WireGuard with keepalive, control channel with backoff, Noise responder, per-device services, pairing, revocation, admin API |
| `internal/mqttgw` | MQTT gateway: broker credentials stay with the agent, per-service topic allowlist |
| `internal/update` | `bifrost upgrade`: fetch the latest release, verify the minisign signature, install with apt, health check, rollback |
| `internal/web` | Hlidskjalf: web UI for devices and pairing (login, QR codes, revoke) |
| `internal/wg` | In-process WireGuard tunnel (wireguard-go, netstack) |
| `internal/client` | The app's tunnel core: pairing, service streams, local port forwarding for the CLI |
| `internal/mqttc` | Small MQTT 3.1.1 client that runs inside the app over a service stream (QoS 0/1) |
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
writes or replaces them.

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
6. Use MQTT through the tunnel, without any local port:
   `bifrost client mqtt sub -state phone -service mqtt -t 'home/#'` and
   `bifrost client mqtt pub -state phone -service mqtt -t home/test -m hello [-q 1] [-r]`.
   For a plain MQTT service pass `-username` and put the password into the environment
   variable `BIFROST_MQTT_PASSWORD`; an [MQTT gateway](#mqtt-gateway) needs neither.
   `sub` also takes `-C <count>` and `-W <seconds>` for scripts.
7. For other tools, forward a service to a local TCP port:
   `bifrost client forward -state phone -L ha=127.0.0.1:18123`. It prints a warning: the port
   accepts connections from **every process on the computer**, which then reach the service
   with this device's identity, so use it only for tests and admin work on a machine you
   trust. Apps use the [mobile binding](#mobile-ios-binding), which opens no port.
8. List and revoke devices: `bifrost devices`, `bifrost revoke -name iphone`.

Bind the agent's admin API (`admin`) to `127.0.0.1` or the LAN only.

Without the package, the same works by hand: `bifrost heimdall -config heimdall.json` and
`bifrost asgard -config asgard.json`.

### End-to-end check

`bifrost-check` (with `bifrost-check.timer`, every 5 minutes) tests the whole path
home lab → VPS → WireGuard → agent → MQTT broker: it publishes to the broker with
`bifrost client mqtt pub` as a paired monitor device (no local port) and reports the result to a push monitor
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

## MQTT gateway

A service can be an **MQTT gateway** instead of a plain TCP forward. The device then
speaks MQTT through its tunnel **without any broker credentials**; the agent decides:

- It replaces the credentials in the device's CONNECT with its own (`username` and the
  password from `password_file`) and prefixes the client ID with the device name, so the
  broker log shows which device is connected.
- Every PUBLISH must match a filter in `publish`, every SUBSCRIBE must lie within a filter
  in `subscribe` (`+` and `#` allowed). Anything else ends the session before it reaches
  the broker. A will message is kept only if its topic is allowed.
- **Sender identity:** every published JSON object gets a field set by the agent from the
  pairing, e.g. `"bifrost": {"device": "michael-iphone", "user": "michael", "user_bound": true}`.
  A `bifrost` field sent by the device is overwritten, so the receiver can trust it. Other
  payloads pass unchanged. Turn it off per gateway with `"identity": false`.
- The agent log shows every publish with device, user and topic.
- Only MQTT 3.1.1 is supported.

The pairing is the only credential the device holds: revoking the device in bifrost ends
its MQTT access immediately, and the broker password never leaves the home lab.

```json
"mqtt_gateways": {
  "midgard": {
    "broker": "127.0.0.1:1883",
    "username": "midgard",
    "password_file": "${CREDENTIALS_DIRECTORY}/bifrost-mqtt-midgard",
    "publish": ["midgard/+/command"],
    "subscribe": ["midgard/#"]
  }
}
```

Gateway names share the namespace with `services` and are paired the same way
(`bifrost pair -name iphone -services midgard`). A plain `mqtt` service can stay next to
the gateway for devices that log in to the broker themselves. Keep the password root-only and let systemd
pass it in (the shipped unit has `ImportCredential=bifrost-*`):

```sh
install -d -m 700 /etc/credstore
install -m 600 /dev/stdin /etc/credstore/bifrost-mqtt-midgard   # type the password, then Ctrl-D
systemctl restart bifrost-asgard
```

`password_file` expands environment variables; outside systemd any readable path works.

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
| `(*Client) ConnectMQTT(service, clientID string, keepAlive int, h MessageHandler) (*MQTTSession, error)` | `func connectMQTT(_ service: String?, clientID: String?, keepAlive: Int, handler: MobileMessageHandlerProtocol?) throws -> MobileMQTTSession` |
| `(*MQTTSession) Subscribe(filter string, qos int) error` | `func subscribe(_ filter: String?, qos: Int) throws` |
| `(*MQTTSession) Unsubscribe(filter string) error` | `func unsubscribe(_ filter: String?) throws` |
| `(*MQTTSession) Publish(topic string, payload []byte, qos int, retain bool) error` | `func publish(_ topic: String?, payload: Data?, qos: Int, retain: Bool) throws` |
| `(*MQTTSession) IsConnected() bool` | `func isConnected() -> Bool` |
| `(*MQTTSession) Close()` | `func close()` |
| `(*Client) StopAll()` | `func stopAll()` |
| `MessageHandler.OnMessage(topic string, payload []byte, retained bool)` | `func onMessage(_ topic: String?, payload: Data?, retained: Bool)` |
| `MessageHandler.OnClose(reason string)` | `func onClose(_ reason: String?)` |
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
    func onMessage(_ topic: String?, payload: Data?, retained: Bool) {
        DispatchQueue.main.async { /* update state */ }
    }
    func onClose(_ reason: String?) {
        // empty reason: closed by the app; otherwise reconnect and subscribe again
    }
}

let mqtt = try tunnel.connectMQTT("midgard", clientID: "app", keepAlive: 30, handler: Handler())
try mqtt.subscribe("midgard/#", qos: 1)
try mqtt.publish("midgard/tg/command", payload: Data(#"{"action":"open"}"#.utf8), qos: 1, retain: false)
```

Notes for the app:

- `stateDir` holds `bifrost.key` (device keys, mode 0600) and `bifrost.json` (pairing state).
  Exclude it from iCloud backup if the identity should not move to another device.
- `Info()` returns `{"paired", "relay", "agent_id", "services", "name", "user", "device_name",
  "device_fp", "agent_fp", "paired_at"}`. `device_fp` exists
  before pairing, so it can be shown for comparison with the agent log.
- MQTT runs inside the app: `connectMQTT` opens one end-to-end tunnel to an
  [MQTT gateway](#mqtt-gateway) and speaks MQTT 3.1.1 over it (clean session, QoS 0 and 1,
  retained messages, keep-alive). The binding opens **no local port**, so other apps on the
  device cannot use the tunnel or the device's identity. The app needs no broker password.
- Handler calls arrive one at a time on a background thread. The handler may call
  `publish`/`subscribe` itself. `onClose` is called exactly once per session.
- iOS suspends the app in the background; call `stopAll()` there and `connectMQTT` plus the
  subscriptions again when it becomes active. Do the same after `onClose` with a non-empty
  reason (connection lost, or the gateway refused a topic).
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
   to the same device, then `{"open":"mqtt"}`; the target comes only from `asgard.json`.
5. Pairing: `Noise_IKpsk2` with the token from the QR code as PSK. The device is stored only after
   the app's first encrypted message `{"relay_id", "user"?, "device_name"?}`.

All messages are `[2-byte length][data]`.

## License

MIT, see [LICENSE](LICENSE).
