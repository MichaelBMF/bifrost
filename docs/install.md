# Installing and updating bifrost

Releases ship a Debian package per architecture (`bifrost_<version>_amd64.deb`,
`bifrost_<version>_arm64.deb`), plain tarballs, the iOS framework and a
`SHA256SUMS` file signed with [minisign](https://jedisct1.github.io/minisign/).
The public key is `packaging/minisign.pub` in this repository and is attached
to every release.

## What the package contains

| Path | Purpose |
| --- | --- |
| `/usr/bin/bifrost` | the binary (all roles) |
| `/usr/lib/systemd/system/bifrost-heimdall.service` | relay on the VPS |
| `/usr/lib/systemd/system/bifrost-asgard.service` | agent in the home lab |
| `/usr/lib/systemd/system/bifrost-hlidskjalf.service` | web UI next to the agent |
| `/usr/bin/bifrost-check`, `bifrost-check.{service,timer}` | optional end-to-end check |
| `/usr/lib/sysusers.d/bifrost.conf`, `/usr/lib/tmpfiles.d/bifrost.conf` | `bifrost-mon` user and its state directory for the check |
| `/usr/share/doc/bifrost/examples/` | example configs |
| `/etc/bifrost/` | empty; configs are yours |

The package never writes configs, keys or passwords. They stay in
`/etc/bifrost/*.json`, `/etc/bifrost-monitor.env` and `/var/lib/private/bifrost*`,
and an upgrade leaves them alone.

No unit is enabled on install, because every host runs a different role. On an
upgrade the package restarts the bifrost services that are running.

## Download and verify

```sh
VERSION=v0.2.0
ARCH=$(dpkg --print-architecture)       # amd64 or arm64
BASE=https://github.com/MichaelBMF/bifrost/releases/download/$VERSION
cd "$(mktemp -d)"
curl -fsSL -O "$BASE/SHA256SUMS" -O "$BASE/SHA256SUMS.minisig" \
     -O "$BASE/bifrost_${VERSION#v}_${ARCH}.deb"
minisign -Vm SHA256SUMS -p /etc/bifrost/minisign.pub
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install "./bifrost_${VERSION#v}_${ARCH}.deb"
```

Copy `packaging/minisign.pub` from this repository to `/etc/bifrost/minisign.pub`
once (`apt install minisign` for the tool). Do not take the key from the release
you are verifying, otherwise the signature proves nothing.

## First install

VPS (relay):

```sh
sudo install -m 0644 /usr/share/doc/bifrost/examples/heimdall.json /etc/bifrost/heimdall.json
sudoedit /etc/bifrost/heimdall.json
sudo systemctl enable --now bifrost-heimdall
```

Home lab container (agent, web UI, check):

```sh
install -m 0644 /usr/share/doc/bifrost/examples/asgard.json /etc/bifrost/asgard.json
systemctl enable --now bifrost-asgard
install -m 0600 /usr/share/doc/bifrost/examples/hlidskjalf.json /etc/bifrost/hlidskjalf.json
systemctl enable --now bifrost-hlidskjalf
# end-to-end check: pair a device for bifrost-mon, write /etc/bifrost-monitor.env (0600)
systemctl enable --now bifrost-check.timer
```

## Moving a manual install to the package

Hand-written units in `/etc/systemd/system/` take precedence over the packaged
ones, and `/usr/local/bin` comes before `/usr/bin` in `PATH`. Remove them once,
after installing the package (configs and keys are not touched):

```sh
sudo apt install ./bifrost_<version>_<arch>.deb
sudo rm -f /etc/systemd/system/bifrost-heimdall.service \
           /etc/systemd/system/bifrost-asgard.service \
           /etc/systemd/system/bifrost-hlidskjalf.service \
           /etc/systemd/system/bifrost-check.service \
           /etc/systemd/system/bifrost-check.timer \
           /usr/local/bin/bifrost /usr/local/bin/bifrost.prev /usr/local/bin/bifrost-check
sudo systemctl daemon-reload
sudo systemctl reenable bifrost-heimdall        # VPS
# in the container: systemctl reenable bifrost-asgard bifrost-hlidskjalf bifrost-check.timer
sudo systemctl restart bifrost-heimdall          # or the units of the container
```

The package prints a warning on install for every such file it finds.

## Updating

Install the newer `.deb` the same way (`apt install ./bifrost_<new>_<arch>.deb`);
running services are restarted. To go back, install the previous `.deb`.
Keep relay and agent on the same version.
