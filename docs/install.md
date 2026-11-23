# Installing and updating bifrost

Releases ship a Debian package per architecture (`bifrost_<version>_amd64.deb`,
`bifrost_<version>_arm64.deb`), plain tarballs, the iOS framework and a
`SHA256SUMS` file signed with [minisign](https://jedisct1.github.io/minisign/).
The public key is `packaging/minisign.pub` in this repository and is attached
to every release.


> **Debian has an unrelated package that is also called `bifrost`** (version 1.3.x).
> Up to v0.3.0, `unattended-upgrades` could replace this project's package with it,
> which removes `/usr/bin/bifrost`. From v0.3.1 on, the package has epoch 1
> (`1:0.3.1`, always newer for apt) and installs `/etc/apt/preferences.d/bifrost`,
> which blocks Debian's package. If `dpkg-query -W bifrost` shows `1.3.1-1`, install
> the release `.deb` again by hand as below.

## What the package contains

| Path | Purpose |
| --- | --- |
| `/usr/bin/bifrost` | the binary (all roles) |
| `/usr/lib/systemd/system/bifrost-heimdall.service` | relay on the VPS |
| `/usr/lib/systemd/system/bifrost-asgard.service` | agent in the home lab |
| `/usr/lib/systemd/system/bifrost-hlidskjalf.service` | web UI next to the agent |
| `/usr/bin/bifrost-check`, `bifrost-check.{service,timer}` | optional end-to-end check |
| `bifrost-upgrade.{service,timer}` | optional daily self-update (`bifrost upgrade`) |
| `/usr/share/bifrost/minisign.pub` | release signing key used by `bifrost upgrade` |
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
VERSION=v0.3.1
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

From v0.2.0 on, the package can update itself:

```sh
sudo bifrost upgrade -check      # is there a newer release?
sudo bifrost upgrade             # install it
sudo bifrost upgrade -to v0.2.0  # install a specific version, also an older one
```

`bifrost upgrade` asks GitHub for the latest release, verifies `SHA256SUMS`
against `/usr/share/bifrost/minisign.pub` (the signature's trusted comment must
name exactly that release, so an old signed file cannot be replayed), checks the
package against it and installs it with `apt-get`. The package restarts the
bifrost services that were running. If one of them is not active
20 seconds later, or systemd had to restart it, the previous version is
installed again and the command fails.

To update automatically once a day (04:00 plus up to one hour of random delay,
so relay and agent do not restart at the same moment):

```sh
sudo systemctl enable --now bifrost-upgrade.timer
journalctl -u bifrost-upgrade        # what happened
```

Relay and agent may then run different versions for up to an hour. For a
release that changes the relay/agent protocol, stop the timer on both hosts
and update them by hand.

Without the timer, install a newer `.deb` by hand as described above; running
services are restarted.
