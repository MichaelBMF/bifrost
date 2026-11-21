// Package client is the app's tunnel core: pairing and local port forwarding.
// It is embedded in the iOS app through the gomobile binding in package mobile,
// and used by the `bifrost client` command. It must not import the agent or relay
// packages (they pull in wireguard-go and the gVisor netstack).
package client

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/MichaelBMF/bifrost/internal/keys"
	"github.com/MichaelBMF/bifrost/internal/wire"
)

// setupTimeout bounds the relay connection, Noise handshake and service open.
const setupTimeout = 20 * time.Second

// State is the pairing state stored next to the keys.
type State struct {
	Relay    string   `json:"relay"`
	RelayPin string   `json:"relay_pin"`
	AgentID  string   `json:"agent_id"`
	AgentPub string   `json:"agent_pub"`
	Services []string `json:"services"`
	// Filled since the user/device name extension; empty in older state files.
	Name       string `json:"name,omitempty"` // agent-assigned device name
	User       string `json:"user,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	DeviceFP   string `json:"device_fp,omitempty"`
	AgentFP    string `json:"agent_fp,omitempty"`
	Paired     string `json:"paired,omitempty"` // RFC 3339
}

// PairOptions are optional labels sent to the agent during pairing.
type PairOptions struct {
	User       string // app user name; must match if the admin bound one with `bifrost pair -user`
	DeviceName string // human-readable device name, e.g. "Michael's iPhone"
}

// PairResult is what the agent confirmed after a successful pairing.
type PairResult struct {
	Name       string   `json:"name"` // agent-assigned device name
	Services   []string `json:"services"`
	User       string   `json:"user,omitempty"`
	DeviceName string   `json:"device_name,omitempty"`
	DeviceFP   string   `json:"device_fp"`
	AgentFP    string   `json:"agent_fp"`
}

type Client struct {
	// Logf receives diagnostic messages (forwarding errors). Defaults to log.Printf;
	// set it to nil to silence them.
	Logf func(format string, args ...any)

	keyPath   string
	statePath string
	mu        sync.RWMutex
	id        *keys.Identity
	state     State
}

// Open loads the keys (<base>.key) and pairing state (<base>.json), creating keys if needed.
func Open(base string) (*Client, error) {
	id, _, err := keys.LoadOrCreate(base + ".key")
	if err != nil {
		return nil, err
	}
	c := &Client{Logf: log.Printf, id: id, keyPath: base + ".key", statePath: base + ".json"}
	if b, err := os.ReadFile(c.statePath); err == nil {
		if err := json.Unmarshal(b, &c.state); err != nil {
			return nil, fmt.Errorf("%s: %w", c.statePath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return c, nil
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// State returns a copy of the pairing state.
func (c *Client) State() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.state
	s.Services = append([]string(nil), s.Services...)
	return s
}

// Paired reports whether a pairing state is present.
func (c *Client) Paired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state.AgentID != ""
}

// DeviceFingerprint is the fingerprint of this device's Noise key, as the agent shows it.
func (c *Client) DeviceFingerprint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return keys.Fingerprint(c.id.Noise.Public)
}

// Reset forgets the pairing and replaces the device keys, so a later pairing starts
// with a fresh identity. The agent is not notified; revoke the device there.
func (c *Client) Reset() error {
	id, err := keys.Generate()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Remove(c.statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := id.Save(c.keyPath); err != nil {
		return err
	}
	c.id, c.state = id, State{}
	return nil
}

func (c *Client) dialRelay(ctx context.Context, id *keys.Identity, relay, pin string, h wire.Hello) (net.Conn, error) {
	cert, err := id.Certificate()
	if err != nil {
		return nil, err
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		Config: wire.PinnedTLSConfig(cert, pin)}
	conn, err := d.DialContext(ctx, "tcp", relay)
	if err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(setupTimeout))
	if err := wire.WriteJSON(conn, h); err != nil {
		conn.Close()
		return nil, err
	}
	var st wire.Status
	if err := wire.ReadJSON(conn, &st); err != nil || !st.OK {
		conn.Close()
		if err == nil {
			err = errors.New(st.Error)
		}
		return nil, fmt.Errorf("relay: %w", err)
	}
	return conn, nil
}

// closeOnCancel closes conn if ctx ends before stop is called.
func closeOnCancel(ctx context.Context, conn net.Conn) (stop func() bool) {
	return context.AfterFunc(ctx, func() { conn.Close() })
}

// Pair pairs this device with an agent using a bifrost1: code.
func (c *Client) Pair(code string, opt PairOptions) (*PairResult, error) {
	return c.PairContext(context.Background(), code, opt)
}

func (c *Client) PairContext(ctx context.Context, code string, opt PairOptions) (*PairResult, error) {
	p, err := wire.ParsePairingCode(code)
	if err != nil {
		return nil, err
	}
	token, err1 := hex.DecodeString(p.Token)
	agentPub, err2 := hex.DecodeString(p.AgentPub)
	if err1 != nil || err2 != nil || len(token) != 32 || len(agentPub) != 32 {
		return nil, errors.New("corrupt pairing code")
	}
	user, devName := wire.CleanLabel(opt.User), wire.CleanLabel(opt.DeviceName)
	c.mu.RLock()
	id := c.id
	c.mu.RUnlock()

	conn, err := c.dialRelay(ctx, id, p.Relay, p.RelayPin, wire.Hello{Role: "pair", AgentID: p.AgentID, TokenHash: wire.TokenHash(token)})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer closeOnCancel(ctx, conn)()
	sc, err := wire.ClientHandshake(conn, id.Noise, agentPub, token, wire.Prologue(p.AgentID))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(setupTimeout))
	if err := sc.WriteJSON(wire.PairRequest{RelayID: id.TLSID(), User: user, DeviceName: devName}); err != nil {
		return nil, err
	}
	var resp wire.PairResponse
	if err := sc.ReadJSON(&resp); err != nil {
		return nil, fmt.Errorf("pairing rejected (code expired, already used or wrong?): %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("pairing rejected: %s", resp.Error)
	}
	res := &PairResult{Name: resp.Name, Services: resp.Services, User: resp.User, DeviceName: resp.DeviceName,
		DeviceFP: resp.DeviceFP, AgentFP: resp.AgentFP}
	st := State{Relay: p.Relay, RelayPin: p.RelayPin, AgentID: p.AgentID, AgentPub: p.AgentPub,
		Services: resp.Services, Name: resp.Name, User: resp.User, DeviceName: resp.DeviceName,
		DeviceFP: resp.DeviceFP, AgentFP: resp.AgentFP, Paired: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.MarshalIndent(st, "", "  ")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.id != id {
		return nil, errors.New("keys were reset during pairing")
	}
	if err := os.WriteFile(c.statePath, b, 0o600); err != nil {
		return nil, err
	}
	c.state = st
	return res, nil
}

// DialService opens an end-to-end encrypted connection to a service.
func (c *Client) DialService(name string) (net.Conn, error) {
	return c.DialServiceContext(context.Background(), name)
}

func (c *Client) DialServiceContext(ctx context.Context, name string) (net.Conn, error) {
	c.mu.RLock()
	id, st := c.id, c.state
	c.mu.RUnlock()
	if st.AgentID == "" {
		return nil, errors.New("not paired yet")
	}
	agentPub, err := hex.DecodeString(st.AgentPub)
	if err != nil {
		return nil, errors.New("corrupt state: agent key")
	}
	conn, err := c.dialRelay(ctx, id, st.Relay, st.RelayPin, wire.Hello{Role: "dial", AgentID: st.AgentID})
	if err != nil {
		return nil, err
	}
	stop := closeOnCancel(ctx, conn)
	fail := func(err error) (net.Conn, error) {
		stop()
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	sc, err := wire.ClientHandshake(conn, id.Noise, agentPub, nil, wire.Prologue(st.AgentID))
	if err != nil {
		return fail(err)
	}
	_ = conn.SetDeadline(time.Now().Add(setupTimeout))
	if err := sc.WriteJSON(map[string]string{"open": name}); err != nil {
		return fail(err)
	}
	var s wire.Status
	if err := sc.ReadJSON(&s); err != nil || !s.OK {
		if err == nil {
			err = fmt.Errorf("service %q: %s", name, s.Error)
		} else {
			err = fmt.Errorf("service %q: rejected by agent (revoked or not allowed?): %w", name, err)
		}
		return fail(err)
	}
	if !stop() { // ctx ended in the meantime and the connection is already closed
		return fail(ctx.Err())
	}
	_ = conn.SetDeadline(time.Time{})
	return sc, nil
}

// Forwarder accepts local connections and tunnels each one to a service.
type Forwarder struct {
	c       *Client
	service string
	ln      net.Listener
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
	mu      sync.Mutex
	conns   map[net.Conn]bool
	wg      sync.WaitGroup
}

// Listen opens a local listener (e.g. "127.0.0.1:0") and forwards every accepted
// connection to service through its own end-to-end encrypted tunnel.
func (c *Client) Listen(service, addr string) (*Forwarder, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{c: c, service: service, ln: ln, ctx: ctx, cancel: cancel,
		done: make(chan struct{}), conns: map[net.Conn]bool{}}
	go f.serve()
	return f, nil
}

// Forward listens on addr and blocks until the listener fails.
func (c *Client) Forward(service, addr string) error {
	f, err := c.Listen(service, addr)
	if err != nil {
		return err
	}
	c.logf("%s -> service %q", f.Addr(), service)
	<-f.Done()
	return f.Err()
}

func (f *Forwarder) Addr() net.Addr        { return f.ln.Addr() }
func (f *Forwarder) Service() string       { return f.service }
func (f *Forwarder) Done() <-chan struct{} { return f.done }

// Err returns why the forwarder stopped (nil after Close).
func (f *Forwarder) Err() error {
	<-f.done
	return f.err
}

// Close stops listening and closes all forwarded connections.
func (f *Forwarder) Close() error {
	f.cancel()
	err := f.ln.Close()
	f.mu.Lock()
	for c := range f.conns {
		c.Close()
	}
	f.mu.Unlock()
	<-f.done
	f.wg.Wait()
	return err
}

func (f *Forwarder) track(c net.Conn, add bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !add {
		delete(f.conns, c)
		return true
	}
	if f.ctx.Err() != nil {
		return false
	}
	f.conns[c] = true
	return true
}

func (f *Forwarder) serve() {
	defer close(f.done)
	for {
		local, err := f.ln.Accept()
		if err != nil {
			if f.ctx.Err() == nil {
				f.err = err
			}
			return
		}
		if !f.track(local, true) {
			local.Close()
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer f.track(local, false)
			remote, err := f.c.DialServiceContext(f.ctx, f.service)
			if err != nil {
				if f.ctx.Err() == nil {
					f.c.logf("%s: %v", f.service, err)
				}
				local.Close()
				return
			}
			if !f.track(remote, true) {
				local.Close()
				remote.Close()
				return
			}
			defer f.track(remote, false)
			wire.Pipe(local, remote)
		}()
	}
}
