// Package wg runs WireGuard entirely in-process (wireguard-go with the gVisor netstack).
// No network interface is created on the host and no root privileges are needed.
// Only what the program itself serves on the netstack is reachable through the tunnel.
package wg

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Peer struct {
	PublicKey []byte
	Endpoint  string // host:port, empty = peer connects to us (server side)
	AllowedIP netip.Addr
	Keepalive int // seconds, 0 = off
}

type Config struct {
	PrivateKey []byte
	Address    netip.Addr
	ListenPort int // 0 = random port (client side)
	Peers      []Peer
}

type Tunnel struct {
	*netstack.Net
	dev *device.Device
}

func (t *Tunnel) Close() { t.dev.Close() }

func Up(c Config) (*Tunnel, error) {
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{c.Address}, nil, 1420)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(c.PrivateKey))
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey))
		if p.Endpoint != "" {
			ua, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				dev.Close()
				return nil, fmt.Errorf("endpoint %s: %w", p.Endpoint, err)
			}
			ap := ua.AddrPort()
			// Use IPv4 as a plain IPv4 address, not the ::ffff: form (otherwise WireGuard picks the IPv6 socket).
			ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			fmt.Fprintf(&b, "endpoint=%s\n", ap)
		}
		fmt.Fprintf(&b, "allowed_ip=%s/32\n", p.AllowedIP)
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
	}
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &Tunnel{Net: tnet, dev: dev}, nil
}
