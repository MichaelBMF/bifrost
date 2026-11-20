// Package agent runs in the home lab, connects outbound to the relay, terminates Noise
// and forwards connections only to services listed in its own config.
package agent

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/MichaelBMF/bifrost/internal/keys"
	"github.com/MichaelBMF/bifrost/internal/wg"
	"github.com/MichaelBMF/bifrost/internal/wire"
	"github.com/mdp/qrterminal/v3"
)

type Config struct {
	Relay    string `json:"relay"`     // relay TLS address for iPhones, host:443 (goes into the QR code)
	RelayPin string `json:"relay_pin"` // relay SPKI hash
	// WireGuard to the relay (v2): runs in-process, no interface on the host.
	RelayWGEndpoint string            `json:"relay_wg_endpoint"` // host:51820
	RelayWGPub      string            `json:"relay_wg_pub"`      // base64
	RelayTunnelIP   string            `json:"relay_tunnel_ip"`   // e.g. 10.8.0.1
	ControlPort     int               `json:"control_port"`      // relay control channel, e.g. 7000
	TunnelIP        string            `json:"tunnel_ip"`         // own tunnel address, e.g. 10.8.0.2
	StreamPort      int               `json:"stream_port"`       // agent accepts connections here, e.g. 9000
	AgentID         string            `json:"agent_id"`
	KeyFile         string            `json:"key_file"`
	StateFile       string            `json:"state_file"` // device list
	Admin           string            `json:"admin"`      // LAN/localhost only, e.g. 127.0.0.1:7070
	Services        map[string]string `json:"services"`   // name -> target host:port
}

type Device struct {
	NoisePub string   `json:"noise_pub"`
	RelayID  string   `json:"relay_id"`
	Services []string `json:"services"`
	Added    string   `json:"added"`
}

type pending struct {
	token    []byte
	name     string
	services []string
	expires  time.Time
}

// PairingCode is the content of the QR code.
type PairingCode struct {
	Relay    string `json:"r"`
	RelayPin string `json:"p"`
	AgentID  string `json:"a"`
	AgentPub string `json:"k"`
	Token    string `json:"t"`
}

func (p PairingCode) String() string {
	b, _ := json.Marshal(p)
	return "bifrost1:" + base64.RawURLEncoding.EncodeToString(b)
}

func ParsePairingCode(s string) (PairingCode, error) {
	var p PairingCode
	if !strings.HasPrefix(s, "bifrost1:") {
		return p, errors.New("not a bifrost1 code")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "bifrost1:"))
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal(b, &p)
}

type Agent struct {
	cfg     *Config
	id      *keys.Identity
	mu      sync.Mutex
	devices map[string]*Device
	pending map[string]*pending // token hash -> pairing
	ctrl    net.Conn
	active  map[string]map[net.Conn]bool // device name -> open connections
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	return &c, json.Unmarshal(b, &c)
}

func New(cfg *Config) (*Agent, error) {
	id, created, err := keys.LoadOrCreate(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	if created {
		log.Printf("created new agent key in %s", cfg.KeyFile)
	}
	a := &Agent{cfg: cfg, id: id, devices: map[string]*Device{}, pending: map[string]*pending{},
		active: map[string]map[net.Conn]bool{}}
	if b, err := os.ReadFile(cfg.StateFile); err == nil {
		if err := json.Unmarshal(b, &a.devices); err != nil {
			return nil, err
		}
	}
	log.Printf("agent WireGuard key (for relay.json under agents.<id>.wg_pub): %s", id.WGPublic())
	log.Printf("agent fingerprint: %s", keys.Fingerprint(id.Noise.Public))
	return a, nil
}

func (a *Agent) saveLocked() error {
	b, _ := json.MarshalIndent(a.devices, "", "  ")
	return os.WriteFile(a.cfg.StateFile, b, 0o600)
}

func (a *Agent) sendCtrl(m wire.Control) {
	a.mu.Lock()
	c := a.ctrl
	a.mu.Unlock()
	if c != nil {
		_ = wire.WriteJSON(c, m)
	}
}

func (a *Agent) syncDevices() {
	a.mu.Lock()
	var ks []string
	for _, d := range a.devices {
		ks = append(ks, d.RelayID)
	}
	a.mu.Unlock()
	a.sendCtrl(wire.Control{Op: "sync_devices", Keys: ks})
}

// Run starts in-process WireGuard, accepts connections from the relay inside the tunnel
// and keeps the control channel to the relay up with exponential backoff.
func (a *Agent) Run() error {
	if a.cfg.Admin != "" {
		go a.serveAdmin()
	}
	relayPub, err := keys.ParseWGKey(a.cfg.RelayWGPub)
	if err != nil {
		return err
	}
	self, err1 := netip.ParseAddr(a.cfg.TunnelIP)
	relayIP, err2 := netip.ParseAddr(a.cfg.RelayTunnelIP)
	if err1 != nil || err2 != nil {
		return errors.New("invalid tunnel_ip or relay_tunnel_ip")
	}
	// The home lab initiates the tunnel (endpoint + keepalive), no port forwarding needed.
	tun, err := wg.Up(wg.Config{PrivateKey: a.id.WG.Private, Address: self,
		Peers: []wg.Peer{{PublicKey: relayPub, Endpoint: a.cfg.RelayWGEndpoint, AllowedIP: relayIP, Keepalive: 25}}})
	if err != nil {
		return err
	}
	defer tun.Close()
	// Only this single port is reachable through the tunnel, not the home network.
	ln, err := tun.ListenTCPAddrPort(netip.AddrPortFrom(self, uint16(a.cfg.StreamPort)))
	if err != nil {
		return err
	}
	go func() {
		for {
			st, err := ln.Accept()
			if err != nil {
				log.Printf("tunnel listener: %v", err)
				return
			}
			src, err := netip.ParseAddrPort(st.RemoteAddr().String())
			if err != nil || src.Addr() != relayIP {
				st.Close()
				continue
			}
			go a.handleStream(st)
		}
	}()
	log.Printf("WireGuard to %s, tunnel address %s, streams on port %d", a.cfg.RelayWGEndpoint, self, a.cfg.StreamPort)

	ctrlAddr := netip.AddrPortFrom(relayIP, uint16(a.cfg.ControlPort))
	backoff := time.Second
	for {
		start := time.Now()
		err := a.controlOnce(tun, ctrlAddr)
		log.Printf("control channel to relay closed: %v", err)
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, time.Minute)
	}
}

func (a *Agent) controlOnce(tun *wg.Tunnel, addr netip.AddrPort) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	c, err := tun.DialContextTCPAddrPort(ctx, addr)
	cancel()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := wire.WriteJSON(c, wire.Hello{Role: "agent", AgentID: a.cfg.AgentID}); err != nil {
		return err
	}
	a.mu.Lock()
	a.ctrl = c
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.ctrl = nil; a.mu.Unlock() }()
	a.syncDevices()
	log.Printf("control channel to relay established")
	// The relay sends nothing on the control channel; reading only detects disconnects.
	_, err = io.Copy(io.Discard, c)
	if err == nil {
		err = io.EOF
	}
	return err
}

func (a *Agent) handleStream(st net.Conn) {
	var h wire.StreamHeader
	if err := wire.ReadJSON(st, &h); err != nil {
		st.Close()
		return
	}
	var err error
	switch h.Kind {
	case "dial":
		err = a.handleDial(st, h)
	case "pair":
		err = a.handlePair(st, h)
	default:
		err = errors.New("unknown stream kind")
	}
	if err != nil {
		log.Printf("stream rejected: %v", err)
		st.Close()
	}
}

func (a *Agent) deviceByNoise(pub []byte) (string, *Device) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hp := hex.EncodeToString(pub)
	for n, d := range a.devices {
		if subtle.ConstantTimeCompare([]byte(d.NoisePub), []byte(hp)) == 1 {
			return n, d
		}
	}
	return "", nil
}

func (a *Agent) handleDial(st net.Conn, h wire.StreamHeader) error {
	var name string
	var dev *Device
	sc, _, err := wire.ServerHandshake(st, a.id.Noise, false, nil, wire.Prologue(a.cfg.AgentID),
		func(peer []byte) error {
			name, dev = a.deviceByNoise(peer)
			if dev == nil {
				return errors.New("unknown device")
			}
			// Bind both layers: the Noise key and the relay key must belong to the same device.
			if dev.RelayID != h.RelayID {
				return errors.New("relay key does not match device")
			}
			return nil
		})
	if err != nil {
		return err
	}
	var req struct {
		Open string `json:"open"`
	}
	if err := sc.ReadJSON(&req); err != nil {
		return err
	}
	target, ok := a.cfg.Services[req.Open]
	if !ok || !slices.Contains(dev.Services, req.Open) {
		_ = sc.WriteJSON(wire.Status{Error: "service not allowed"})
		return fmt.Errorf("%s: service %q not allowed", name, req.Open)
	}
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_ = sc.WriteJSON(wire.Status{Error: "service unreachable"})
		return err
	}
	if err := sc.WriteJSON(wire.Status{OK: true}); err != nil {
		up.Close()
		return err
	}
	log.Printf("%s -> %s (%s)", name, req.Open, target)
	a.track(name, sc, true)
	wire.Pipe(sc, up)
	a.track(name, sc, false)
	return nil
}

func (a *Agent) handlePair(st net.Conn, h wire.StreamHeader) error {
	a.mu.Lock()
	p := a.pending[h.TokenHash]
	a.mu.Unlock()
	if p == nil || time.Now().After(p.expires) {
		return errors.New("pairing token unknown or expired")
	}
	sc, peer, err := wire.ServerHandshake(st, a.id.Noise, true, p.token, wire.Prologue(a.cfg.AgentID),
		func([]byte) error { return nil })
	if err != nil {
		return err
	}
	// With IKpsk2, only the first transport message proves that the app knows the token.
	// Nothing is stored before that, so even a compromised relay that knows the
	// token hash cannot slip in a device.
	var req struct {
		RelayID string `json:"relay_id"`
	}
	if err := sc.ReadJSON(&req); err != nil {
		return fmt.Errorf("invalid pairing confirmation (wrong token?): %w", err)
	}
	if req.RelayID != h.RelayID {
		return errors.New("relay key in pairing does not match connection")
	}
	a.mu.Lock()
	if a.pending[h.TokenHash] != p { // already used
		a.mu.Unlock()
		return errors.New("token already used")
	}
	delete(a.pending, h.TokenHash) // single-use token
	a.devices[p.name] = &Device{NoisePub: hex.EncodeToString(peer), RelayID: req.RelayID,
		Services: p.services, Added: time.Now().Format(time.RFC3339)}
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		return err
	}
	a.sendCtrl(wire.Control{Op: "pair_close", Hash: h.TokenHash})
	a.syncDevices()
	log.Printf("paired device %q, fingerprint %s, services %v", p.name, keys.Fingerprint(peer), p.services)
	_ = sc.WriteJSON(map[string]any{"ok": true, "name": p.name, "services": p.services,
		"device_fp": keys.Fingerprint(peer), "agent_fp": keys.Fingerprint(a.id.Noise.Public)})
	sc.Close()
	return nil
}

func (a *Agent) track(name string, c net.Conn, add bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if add {
		if a.active[name] == nil {
			a.active[name] = map[net.Conn]bool{}
		}
		a.active[name][c] = true
	} else if a.active[name] != nil {
		delete(a.active[name], c)
	}
}

// StartPairing creates a single-use token (5 minutes) and returns the QR content.
func (a *Agent) StartPairing(name string, services []string) (string, error) {
	for _, s := range services {
		if _, ok := a.cfg.Services[s]; !ok {
			return "", fmt.Errorf("service %q is not configured", s)
		}
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	th := wire.TokenHash(token)
	ttl := 5 * time.Minute
	a.mu.Lock()
	if a.ctrl == nil {
		a.mu.Unlock()
		return "", errors.New("not connected to relay")
	}
	a.pending[th] = &pending{token: token, name: name, services: services, expires: time.Now().Add(ttl)}
	a.mu.Unlock()
	a.sendCtrl(wire.Control{Op: "pair_open", Hash: th, TTL: int(ttl.Seconds())})
	code := PairingCode{Relay: a.cfg.Relay, RelayPin: a.cfg.RelayPin, AgentID: a.cfg.AgentID,
		AgentPub: hex.EncodeToString(a.id.Noise.Public), Token: hex.EncodeToString(token)}.String()
	return code, nil
}

func (a *Agent) Revoke(name string) error {
	a.mu.Lock()
	if _, ok := a.devices[name]; !ok {
		a.mu.Unlock()
		return fmt.Errorf("unknown device %q", name)
	}
	delete(a.devices, name)
	for c := range a.active[name] {
		c.Close()
	}
	delete(a.active, name)
	err := a.saveLocked()
	a.mu.Unlock()
	a.syncDevices()
	log.Printf("revoked device %q", name)
	return err
}

// serveAdmin serves a small HTTP API; bind it to localhost/LAN only.
func (a *Agent) serveAdmin() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pair", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		svcs := strings.Split(r.URL.Query().Get("services"), ",")
		if name == "" {
			http.Error(w, "name missing", 400)
			return
		}
		code, err := a.StartPairing(name, svcs)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		fmt.Fprintln(os.Stderr, "pairing QR for", name)
		qrterminal.GenerateHalfBlock(code, qrterminal.L, os.Stderr)
		json.NewEncoder(w).Encode(map[string]string{"code": code})
	})
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Revoke(r.URL.Query().Get("name")); err != nil {
			http.Error(w, err.Error(), 404)
		}
	})
	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		out := map[string]any{}
		for n, d := range a.devices {
			pub, _ := hex.DecodeString(d.NoisePub)
			out[n] = map[string]any{"fingerprint": keys.Fingerprint(pub), "services": d.Services, "added": d.Added}
		}
		json.NewEncoder(w).Encode(out)
	})
	log.Printf("admin API on %s", a.cfg.Admin)
	log.Fatal(http.ListenAndServe(a.cfg.Admin, mux))
}
