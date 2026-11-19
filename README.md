# Bifrost – home lab relay (prototype, v2)

Prototype for the "Home Lab Relay: Architecture" design, variant **v2**:

- **iPhone → VPS:** mTLS on TCP 443; the VPS checks an allowlist of public keys.
- **Home lab ↔ VPS:** WireGuard, entirely in-process (wireguard-go with the gVisor netstack).
  No network interface, no root privileges, no port forwarding at home. Through the tunnel,
  only the web app's single stream port in the home lab is reachable, not the home network.
- **iPhone ↔ home lab:** end-to-end with Noise (`Noise_IK`, `Noise_IKpsk2` for pairing).
  The VPS only ever sees ciphertext.

> Prototype: not audited, not meant for production. The binary is called `hlr` for now.

## What's inside

| Package | Contents |
| --- | --- |
| `internal/relay` | TLS for devices, key allowlist, per-IP rate limit, one WireGuard peer per agent, control channel, one TCP connection through the tunnel per device connection |
| `internal/agent` | In-process WireGuard with keepalive, control channel with backoff, Noise responder, per-device services, pairing, revocation, admin API |
| `internal/wg` | In-process WireGuard tunnel (wireguard-go, netstack) |
| `internal/client` | The app's tunnel core: pairing and local port forwarding |
| `internal/wire` | Framing, Noise handshake, `SecureConn`, TLS pinning |
| `internal/keys` | Ed25519 (TLS), X25519 (Noise and WireGuard), fingerprints |
| `internal/e2e` | End-to-end test including attack scenarios |

Not yet included: push (APNs/FCM/ntfy), a real mobile app, metrics, P-256 keys in the Secure Enclave.

## Build and test

```sh
go build -o hlr ./cmd/hlr      # Go 1.23 or newer
go test -race ./...
```

The test brings up relay and agent with real WireGuard over UDP on localhost and checks:
pairing, 3 MB through the tunnel, rejection of services that are not allowed, single-use tokens,
a simulated compromised relay (knows the token hash, not the token),
that only the agent's stream port is reachable through the tunnel, and that revocation
closes active connections immediately.

## Setup

1. Copy `relay.json` from `examples/` to the VPS and start `hlr relay -config relay.json`.
   The log shows the **relay pin** and the **relay WireGuard key**. Both go into `agent.json`.
2. Adjust `agent.json` in the home lab and start `hlr agent -config agent.json`.
   The log shows the **agent WireGuard key**. It goes into `relay.json` under `agents.homelab.wg_pub`.
   Restart the relay.
3. Open on the VPS: TCP 443 (devices) and UDP 51820 (WireGuard). At home: nothing.
4. Pair a device: `hlr pair -name iphone -services mqtt` shows a QR code and `hlr1:…`
   (valid for 5 minutes, single use).
5. Pair the "app": `hlr client pair -state phone -code hlr1:…`.
6. Open a tunnel: `hlr client forward -state phone -L mqtt=127.0.0.1:11883`,
   then e.g. `mosquitto_sub -h 127.0.0.1 -p 11883 -t 'home/#'`.
7. List and revoke devices: `hlr devices`, `hlr revoke -name iphone`.

Bind the agent's admin API (`admin`) to `127.0.0.1` or the LAN only.

## How it works

1. Agent → VPS: WireGuard handshake (UDP), then the control channel `10.8.0.1:7000` inside the tunnel
   with `Hello{role: agent}`. The VPS identifies the agent by its tunnel address, which
   WireGuard only allows for the configured key.
2. iPhone → VPS: TLS 1.3 with a client certificate, then `Hello{role: dial|pair}`.
3. VPS → agent: a new TCP connection to `10.8.0.2:9000` inside the tunnel, `StreamHeader{kind, relay_id}`,
   after that bytes are just passed through.
4. iPhone ↔ agent: Noise_IK. The agent checks that the Noise key and the relay key belong
   to the same device, then `{"open":"mqtt"}`; the target comes only from `agent.json`.
5. Pairing: `Noise_IKpsk2` with the token from the QR code as PSK. The device is stored only after
   the app's first encrypted message.

All messages are `[2-byte length][data]`.

## License

MIT, see [LICENSE](LICENSE).
