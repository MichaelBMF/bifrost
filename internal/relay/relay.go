// Package relay is the broker on the VPS (v2).
//
// iPhone -> relay: mTLS on TCP 443 with a key allowlist.
// Relay <-> home lab: in-process WireGuard (UDP), carrying one TCP connection per iPhone connection
// plus a persistent control channel. The relay can neither read nor modify the Noise payload.
package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/MichaelBMF/bifrost/internal/keys"
	"github.com/MichaelBMF/bifrost/internal/wg"
	"github.com/MichaelBMF/bifrost/internal/wire"
	"golang.org/x/time/rate"
)

type AgentConfig struct {
	WGPub      string `json:"wg_pub"`      // agent's WireGuard public key (base64)
	TunnelIP   string `json:"tunnel_ip"`   // e.g. 10.8.0.2
	StreamPort int    `json:"stream_port"` // web app port inside the tunnel, e.g. 9000
}

type Config struct {
	Listen      string                 `json:"listen"`       // TLS for iPhones, e.g. ":443"
	KeyFile     string                 `json:"key_file"`     // created on first start
	WGPort      int                    `json:"wg_port"`      // UDP, e.g. 51820
	TunnelIP    string                 `json:"tunnel_ip"`    // own tunnel address, e.g. 10.8.0.1
	ControlPort int                    `json:"control_port"` // control channel inside the tunnel, e.g. 7000
	Agents      map[string]AgentConfig `json:"agents"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	return &c, json.Unmarshal(b, &c)
}

type agentSession struct {
	id      string
	ctrl    net.Conn
	stream  netip.AddrPort
	devices map[string]bool      // allowed device TLS IDs
	pairs   map[string]time.Time // token hash -> expiry
	conns   map[string]map[net.Conn]bool
}

type Relay struct {
	cfg      *Config
	tun      *wg.Tunnel
	mu       sync.Mutex
	agents   map[string]*agentSession
	limiters map[string]*rate.Limiter
	ready    chan struct{}
}

func New(cfg *Config) *Relay {
	return &Relay{cfg: cfg, agents: map[string]*agentSession{}, limiters: map[string]*rate.Limiter{},
		ready: make(chan struct{})}
}

// allowedAtTLS rejects unknown keys during the TLS handshake. Exception: while a
// pairing window is open, a new key may get as far as the Hello message.
func (r *Relay) allowedAtTLS(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for _, s := range r.agents {
		if s.devices[id] {
			return true
		}
		for _, exp := range s.pairs {
			if now.Before(exp) {
				return true
			}
		}
	}
	return false
}

func (r *Relay) limiter(ip string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.limiters[ip]
	if !ok {
		l = rate.NewLimiter(rate.Every(6*time.Second), 10) // 10 handshakes per minute
		r.limiters[ip] = l
	}
	return l
}

func (r *Relay) Run() error {
	id, created, err := keys.LoadOrCreate(r.cfg.KeyFile)
	if err != nil {
		return err
	}
	if created {
		log.Printf("created new relay key in %s", r.cfg.KeyFile)
	}
	log.Printf("relay pin (for asgard.json, relay_pin): %s", id.TLSID())
	log.Printf("relay WireGuard key (for asgard.json, relay_wg_pub): %s", id.WGPublic())

	// In-process WireGuard: each agent is a peer with exactly one allowed address.
	self, err := netip.ParseAddr(r.cfg.TunnelIP)
	if err != nil {
		return err
	}
	wcfg := wg.Config{PrivateKey: id.WG.Private, Address: self, ListenPort: r.cfg.WGPort}
	for name, a := range r.cfg.Agents {
		pub, err := keys.ParseWGKey(a.WGPub)
		if err != nil {
			return errors.New("agent " + name + ": " + err.Error())
		}
		ip, err := netip.ParseAddr(a.TunnelIP)
		if err != nil {
			return err
		}
		wcfg.Peers = append(wcfg.Peers, wg.Peer{PublicKey: pub, AllowedIP: ip})
	}
	if r.tun, err = wg.Up(wcfg); err != nil {
		return err
	}
	log.Printf("WireGuard on UDP %d, tunnel address %s", r.cfg.WGPort, self)
	ctl, err := r.tun.ListenTCPAddrPort(netip.AddrPortFrom(self, uint16(r.cfg.ControlPort)))
	if err != nil {
		return err
	}
	go r.acceptControl(ctl)

	cert, err := id.Certificate()
	if err != nil {
		return err
	}
	tcfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if !r.allowedAtTLS(keys.CertID(c)) {
				return errors.New("unknown key")
			}
			return nil
		},
	}
	ln, err := net.Listen("tcp", r.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("relay listening on %s (TLS for devices)", r.cfg.Listen)
	close(r.ready)
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		ip, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
		if !r.limiter(ip).Allow() {
			raw.Close()
			continue
		}
		go r.handle(tls.Server(raw, tcfg))
	}
}

// Tunnel exposes the WireGuard netstack (for tests).
func (r *Relay) Tunnel() *wg.Tunnel { return r.tun }

// Ready is closed once the relay accepts connections (for tests).
func (r *Relay) Ready() <-chan struct{} { return r.ready }

func (r *Relay) acceptControl(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("control channel: %v", err)
			return
		}
		go r.serveAgent(c)
	}
}

// serveAgent: the agent's identity is already established, because WireGuard only accepts
// packets from the configured key with its tunnel address. Here it is only mapped.
func (r *Relay) serveAgent(c net.Conn) {
	src, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		c.Close()
		return
	}
	var h wire.Hello
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := wire.ReadJSON(c, &h); err != nil || h.Role != "agent" {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	ac, ok := r.cfg.Agents[h.AgentID]
	if !ok || ac.TunnelIP != src.Addr().String() {
		log.Printf("rejected control channel from %s for %q", src.Addr(), h.AgentID)
		c.Close()
		return
	}
	ip, _ := netip.ParseAddr(ac.TunnelIP)
	a := &agentSession{id: h.AgentID, ctrl: c, stream: netip.AddrPortFrom(ip, uint16(ac.StreamPort)),
		devices: map[string]bool{}, pairs: map[string]time.Time{}, conns: map[string]map[net.Conn]bool{}}
	r.mu.Lock()
	if old := r.agents[h.AgentID]; old != nil {
		old.ctrl.Close()
	}
	r.agents[h.AgentID] = a
	r.mu.Unlock()
	log.Printf("agent %s connected (WireGuard %s)", h.AgentID, src.Addr())

	for {
		var m wire.Control
		if err := wire.ReadJSON(c, &m); err != nil {
			break
		}
		r.mu.Lock()
		switch m.Op {
		case "sync_devices":
			next := map[string]bool{}
			for _, k := range m.Keys {
				next[k] = true
			}
			for k := range a.devices {
				if !next[k] { // revoked: close open connections immediately
					for conn := range a.conns[k] {
						conn.Close()
					}
					delete(a.conns, k)
				}
			}
			a.devices = next
			log.Printf("agent %s: %d devices allowed", h.AgentID, len(next))
		case "pair_open":
			a.pairs[m.Hash] = time.Now().Add(time.Duration(m.TTL) * time.Second)
		case "pair_close":
			delete(a.pairs, m.Hash)
		}
		r.mu.Unlock()
	}
	r.mu.Lock()
	if r.agents[h.AgentID] == a {
		delete(r.agents, h.AgentID)
	}
	r.mu.Unlock()
	c.Close()
	log.Printf("agent %s disconnected", h.AgentID)
}

func (r *Relay) handle(c *tls.Conn) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err != nil {
		c.Close()
		return
	}
	peerID := keys.CertID(c.ConnectionState().PeerCertificates[0])
	var h wire.Hello
	if err := wire.ReadJSON(c, &h); err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	if h.Role != "dial" && h.Role != "pair" {
		c.Close()
		return
	}
	r.serveClient(c, peerID, h)
}

func (r *Relay) serveClient(c net.Conn, peerID string, h wire.Hello) {
	fail := func(msg string) {
		_ = wire.WriteJSON(c, wire.Status{Error: msg})
		c.Close()
	}
	r.mu.Lock()
	a := r.agents[h.AgentID]
	ok := false
	if a != nil {
		switch h.Role {
		case "dial":
			ok = a.devices[peerID]
		case "pair":
			exp, found := a.pairs[h.TokenHash]
			ok = found && time.Now().Before(exp)
		}
	}
	r.mu.Unlock()
	if !ok {
		fail("not allowed or agent offline")
		return
	}
	// One dedicated TCP connection through the WireGuard tunnel per iPhone connection.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	st, err := r.tun.DialContextTCPAddrPort(ctx, a.stream)
	cancel()
	if err != nil {
		fail("agent unreachable")
		return
	}
	if err := wire.WriteJSON(st, wire.StreamHeader{Kind: h.Role, RelayID: peerID, TokenHash: h.TokenHash}); err != nil {
		st.Close()
		fail("agent unreachable")
		return
	}
	if err := wire.WriteJSON(c, wire.Status{OK: true}); err != nil {
		st.Close()
		c.Close()
		return
	}
	r.track(a, peerID, c, true)
	wire.Pipe(c, st) // from here on only Noise ciphertext
	r.track(a, peerID, c, false)
}

func (r *Relay) track(a *agentSession, id string, c net.Conn, add bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if add {
		if a.conns[id] == nil {
			a.conns[id] = map[net.Conn]bool{}
		}
		a.conns[id][c] = true
	} else if a.conns[id] != nil {
		delete(a.conns[id], c)
	}
}
