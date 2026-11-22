package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/MichaelBMF/bifrost/internal/update"
)

// Services the package may run; after an upgrade every one that was active
// before must be active again, or the previous version is reinstalled.
var upgradeUnits = []string{"bifrost-heimdall.service", "bifrost-asgard.service", "bifrost-hlidskjalf.service"}

// upgrade implements "bifrost upgrade": install the newest signed release of
// the .deb, check the services and roll back if one does not come up.
func upgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	check := fs.Bool("check", false, "only report whether a newer release exists")
	to := fs.String("to", "", "install this version (e.g. v0.2.0) instead of the latest, also a lower one")
	pubkey := fs.String("pubkey", "/usr/share/bifrost/minisign.pub", "minisign public key of the releases")
	repo := fs.String("repo", "MichaelBMF/bifrost", "GitHub repository with the releases")
	settle := fs.Duration("settle", 20*time.Second, "how long services must stay up after the upgrade")
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	installed, err := installedVersion()
	if err != nil {
		return err
	}
	key, err := update.PublicKeyFromFile(*pubkey)
	if err != nil {
		return fmt.Errorf("release key: %w", err)
	}
	src := &update.Source{Repo: *repo, PublicKey: key}

	target := *to
	if target == "" {
		if target, err = src.Latest(ctx); err != nil {
			return err
		}
		if !update.Newer(target, installed) {
			log.Printf("up to date (%s)", installed)
			return nil
		}
	} else if target, err = update.ParseTag(target); err != nil {
		return err
	} else if target == installed {
		log.Printf("%s is already installed", installed)
		return nil
	}
	if *check {
		fmt.Printf("%s -> %s available\n", installed, target)
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("installing needs root (sudo bifrost upgrade)")
	}

	active := activeUnits(upgradeUnits)
	log.Printf("upgrading %s -> %s (running: %s)", installed, target, strings.Join(active, " "))
	if err := installRelease(ctx, src, target); err != nil {
		return err
	}
	bad := waitHealthy(active, *settle)
	if len(bad) == 0 {
		log.Printf("upgraded to %s", target)
		return nil
	}
	log.Printf("not healthy after upgrade: %s; rolling back to %s", strings.Join(bad, " "), installed)
	if err := installRelease(ctx, src, installed); err != nil {
		return fmt.Errorf("rollback to %s failed: %w", installed, err)
	}
	for _, u := range bad {
		exec.Command("systemctl", "restart", u).Run()
	}
	if still := waitHealthy(active, *settle); len(still) > 0 {
		return fmt.Errorf("rolled back to %s, but still not healthy: %s", installed, strings.Join(still, " "))
	}
	return fmt.Errorf("upgrade to %s failed (%s), rolled back to %s", target, strings.Join(bad, " "), installed)
}

// installedVersion returns the tag of the installed bifrost package.
func installedVersion() (string, error) {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Status}|${Version}", "bifrost").Output()
	if err != nil || !strings.HasPrefix(string(out), "install ok installed|") {
		return "", errors.New("bifrost is not installed from the .deb package (see docs/install.md)")
	}
	v := strings.SplitN(string(out), "|", 2)[1]
	tag, err := update.ParseTag(debVersionToTag(v))
	if err != nil {
		return "", fmt.Errorf("the installed package \"bifrost\" (version %s) is not this project's; "+
			"reinstall the release .deb (see docs/install.md)", strings.TrimSpace(v))
	}
	return tag, nil
}

// debVersionToTag strips the Debian epoch ("1:0.3.1" -> "0.3.1"). Packages from
// v0.3.1 on carry epoch 1 so they stay newer than Debian's unrelated "bifrost".
func debVersionToTag(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	return strings.TrimSpace(v)
}

func debArch() string {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return runtime.GOARCH
	}
	return ""
}

func installRelease(ctx context.Context, src *update.Source, tag string) error {
	arch := debArch()
	if arch == "" {
		return fmt.Errorf("no package for %s", runtime.GOARCH)
	}
	dir, err := os.MkdirTemp("", "bifrost-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	deb, err := src.FetchDeb(ctx, tag, arch, dir)
	if err != nil {
		return err
	}
	// apt waits for a running unattended-upgrades instead of failing on the lock.
	// The package's postinst restarts the bifrost services that are running.
	cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "--allow-downgrades",
		"-o", "DPkg::Lock::Timeout=600", deb)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apt-get install %s: %w", tag, err)
	}
	return nil
}

func activeUnits(units []string) []string {
	var out []string
	for _, u := range units {
		if exec.Command("systemctl", "is-active", "-q", u).Run() == nil {
			out = append(out, u)
		}
	}
	return out
}

// unitState returns ActiveState and NRestarts (restarts by systemd's Restart=).
func unitState(u string) (string, int) {
	out, _ := exec.Command("systemctl", "show", "-p", "ActiveState", "-p", "NRestarts", u).Output()
	state, restarts := "", -1
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ActiveState":
			state = v
		case "NRestarts":
			fmt.Sscan(v, &restarts)
		}
	}
	return state, restarts
}

// waitHealthy waits settle and returns the units that are not active, or that
// systemd restarted in the meantime (crash loop).
func waitHealthy(units []string, settle time.Duration) []string {
	if len(units) == 0 {
		return nil
	}
	before := map[string]int{}
	for _, u := range units {
		_, before[u] = unitState(u)
	}
	time.Sleep(settle)
	var bad []string
	for _, u := range units {
		state, n := unitState(u)
		if state != "active" || n < 0 || n > before[u] {
			bad = append(bad, u)
		}
	}
	return bad
}
