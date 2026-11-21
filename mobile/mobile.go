// Package mobile is the gomobile binding of the bifrost app tunnel core for iOS
// (and Android). Build it with scripts/build-ios.sh; in Swift the types carry the
// prefix "Mobile" (MobileClient, MobileNewClient).
//
// Only gomobile-compatible types appear in the exported API: string, int, bool,
// error and *Client. Structured results are returned as JSON strings.
//
// Typical use from the app:
//
//	c := NewClient(<Application Support>/bifrost)
//	if !c.IsPaired() { c.Pair(code, user, deviceName) }
//	port := c.StartForward("mqtt", 0)   // MQTT client connects to 127.0.0.1:port
//	...
//	c.StopAll()                          // when the app goes to the background
//
// This package must not import internal/agent, internal/relay or internal/wg
// (wireguard-go, gVisor); see TestNoServerDependencies.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/MichaelBMF/bifrost/internal/client"
)

// ProbeTimeout bounds Probe (relay connection, handshake and service open), in seconds.
const ProbeTimeout = 20

// Client is the app's handle on one bifrost identity and pairing. All methods are
// safe for concurrent use.
type Client struct {
	c   *client.Client
	dir string

	mu  sync.Mutex
	fwd map[string]*client.Forwarder // service -> active forwarder
}

// NewClient opens (or creates) the device keys and pairing state in stateDir, e.g. a
// subdirectory of the app's Application Support directory. The directory is created
// with mode 0700 if it does not exist. Keys live in bifrost.key, state in bifrost.json.
func NewClient(stateDir string) (*Client, error) {
	if stateDir == "" {
		return nil, errors.New("stateDir is empty")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	c, err := client.Open(filepath.Join(stateDir, "bifrost"))
	if err != nil {
		return nil, err
	}
	return &Client{c: c, dir: stateDir, fwd: map[string]*client.Forwarder{}}, nil
}

// IsPaired reports whether this device has been paired with an agent.
func (m *Client) IsPaired() bool { return m.c.Paired() }

type info struct {
	Paired     bool           `json:"paired"`
	Relay      string         `json:"relay,omitempty"`
	AgentID    string         `json:"agent_id,omitempty"`
	Services   []string       `json:"services"`
	Name       string         `json:"name,omitempty"`
	User       string         `json:"user,omitempty"`
	DeviceName string         `json:"device_name,omitempty"`
	DeviceFP   string         `json:"device_fp"`
	AgentFP    string         `json:"agent_fp,omitempty"`
	PairedAt   string         `json:"paired_at,omitempty"`
	Forwards   map[string]int `json:"forwards"`
}

// Info returns the pairing state as JSON:
//
//	{"paired":true,"relay":"vps.example.org:443","agent_id":"homelab","services":["mqtt"],
//	 "name":"iphone","user":"alice","device_name":"Alice's iPhone",
//	 "device_fp":"ABCD-EFGH-IJKL-MNOP","agent_fp":"...","paired_at":"2026-11-21T12:00:00Z",
//	 "forwards":{"mqtt":54321}}
//
// "name" is the name the admin gave the device with `bifrost pair -name`.
// "device_fp" is always set (the key exists before pairing), so it can be shown
// while waiting for the admin to scan or compare it.
func (m *Client) Info() string {
	st := m.c.State()
	in := info{Paired: st.AgentID != "", Relay: st.Relay, AgentID: st.AgentID, Services: st.Services,
		Name: st.Name, User: st.User, DeviceName: st.DeviceName, DeviceFP: m.c.DeviceFingerprint(),
		AgentFP: st.AgentFP, PairedAt: st.Paired, Forwards: m.forwards()}
	if in.Services == nil {
		in.Services = []string{}
	}
	b, _ := json.Marshal(in)
	return string(b)
}

// Pair pairs this device using a bifrost1: code (from the QR code). user and
// deviceName are optional labels stored by the agent; if the admin created the code
// with `bifrost pair -user X`, user must be exactly X. Returns the result as JSON:
//
//	{"name":"iphone","services":["mqtt"],"user":"alice","device_name":"Alice's iPhone",
//	 "device_fp":"...","agent_fp":"..."}
//
// Fails if the device is already paired; call Unpair first.
func (m *Client) Pair(code, user, deviceName string) (string, error) {
	if m.c.Paired() {
		return "", errors.New("already paired; unpair first")
	}
	res, err := m.c.Pair(code, client.PairOptions{User: user, DeviceName: deviceName})
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(res)
	return string(b), nil
}

// StartForward listens on 127.0.0.1:port (port 0 picks a free port) and tunnels
// every connection to service. It returns the bound port. If service is already
// forwarded, the existing port is returned when port is 0 or equal to it;
// otherwise the old forward is stopped first.
func (m *Client) StartForward(service string, port int) (int, error) {
	st := m.c.State()
	if st.AgentID == "" {
		return 0, errors.New("not paired yet")
	}
	if !slices.Contains(st.Services, service) {
		return 0, fmt.Errorf("service %q is not allowed for this device (allowed: %v)", service, st.Services)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port %d", port)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if f := m.fwd[service]; f != nil {
		select {
		case <-f.Done(): // listener died
		default:
			if cur := f.Addr().(*net.TCPAddr).Port; port == 0 || port == cur {
				return cur, nil
			}
		}
		f.Close()
		delete(m.fwd, service)
	}
	f, err := m.c.Listen(service, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	m.fwd[service] = f
	return f.Addr().(*net.TCPAddr).Port, nil
}

// ForwardPort returns the local port of an active forward for service, or 0.
func (m *Client) ForwardPort(service string) int {
	return m.forwards()[service]
}

func (m *Client) forwards() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for s, f := range m.fwd {
		select {
		case <-f.Done():
		default:
			out[s] = f.Addr().(*net.TCPAddr).Port
		}
	}
	return out
}

// StopForward closes the listener for service and all its tunneled connections.
func (m *Client) StopForward(service string) {
	m.mu.Lock()
	f := m.fwd[service]
	delete(m.fwd, service)
	m.mu.Unlock()
	if f != nil {
		f.Close()
	}
}

// StopAll stops every forward.
func (m *Client) StopAll() {
	m.mu.Lock()
	fs := m.fwd
	m.fwd = map[string]*client.Forwarder{}
	m.mu.Unlock()
	for _, f := range fs {
		f.Close()
	}
}

// Probe opens one end-to-end connection to service and closes it again. It checks
// the whole path: relay reachable, relay pin, device allowed at the relay, Noise
// handshake with the agent, service allowed and reachable in the home lab.
func (m *Client) Probe(service string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout*time.Second)
	defer cancel()
	c, err := m.c.DialServiceContext(ctx, service)
	if err != nil {
		return err
	}
	return c.Close()
}

// Unpair stops all forwards, deletes the pairing state and replaces the device
// keys. The agent is not notified: the admin should also run `bifrost revoke`.
func (m *Client) Unpair() error {
	m.StopAll()
	return m.c.Reset()
}
