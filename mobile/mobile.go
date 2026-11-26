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
//	s := c.ConnectMQTT("midgard", "app", 30, handler)
//	s.Subscribe("midgard/#", 1)
//	s.Publish("midgard/tg/command", payload, 1, false)
//	...
//	c.StopAll()                          // when the app goes to the background
//
// The binding deliberately opens no local listener: a port on 127.0.0.1 could be used
// by any other app or process on the device to reach the home lab with this device's
// identity. Local port forwarding exists only in the CLI (bifrost client forward).
//
// This package must not import internal/agent, internal/relay or internal/wg
// (wireguard-go, gVisor); see TestNoServerDependencies.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/MichaelBMF/bifrost/internal/client"
	"github.com/MichaelBMF/bifrost/internal/mqttc"
)

// ProbeTimeout bounds Probe (relay connection, handshake and service open), in seconds.
const ProbeTimeout = 20

// Client is the app's handle on one bifrost identity and pairing. All methods are
// safe for concurrent use.
type Client struct {
	c   *client.Client
	dir string

	mu       sync.Mutex
	sessions map[*MQTTSession]bool
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
	return &Client{c: c, dir: stateDir, sessions: map[*MQTTSession]bool{}}, nil
}

// IsPaired reports whether this device has been paired with an agent.
func (m *Client) IsPaired() bool { return m.c.Paired() }

type info struct {
	Paired     bool     `json:"paired"`
	Relay      string   `json:"relay,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`
	Services   []string `json:"services"`
	Name       string   `json:"name,omitempty"`
	User       string   `json:"user,omitempty"`
	DeviceName string   `json:"device_name,omitempty"`
	DeviceFP   string   `json:"device_fp"`
	AgentFP    string   `json:"agent_fp,omitempty"`
	PairedAt   string   `json:"paired_at,omitempty"`
}

// Info returns the pairing state as JSON:
//
//	{"paired":true,"relay":"vps.example.org:443","agent_id":"homelab","services":["mqtt"],
//	 "name":"iphone","user":"alice","device_name":"Alice's iPhone",
//	 "device_fp":"ABCD-EFGH-IJKL-MNOP","agent_fp":"...","paired_at":"2026-11-21T12:00:00Z"}
//
// "name" is the name the admin gave the device with `bifrost pair -name`.
// "device_fp" is always set (the key exists before pairing), so it can be shown
// while waiting for the admin to scan or compare it.
func (m *Client) Info() string {
	st := m.c.State()
	in := info{Paired: st.AgentID != "", Relay: st.Relay, AgentID: st.AgentID, Services: st.Services,
		Name: st.Name, User: st.User, DeviceName: st.DeviceName, DeviceFP: m.c.DeviceFingerprint(),
		AgentFP: st.AgentFP, PairedAt: st.Paired}
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

// MessageHandler receives the messages and the end of an MQTTSession. In Swift it is
// the protocol MobileMessageHandlerProtocol. Calls come one at a time, in order, on a
// background thread; dispatch to the main thread for UI work.
type MessageHandler interface {
	// OnMessage is called for every message the broker delivers for a subscription.
	OnMessage(topic string, payload []byte, retained bool)
	// OnClose is called once when the session ends. reason is empty after Close or
	// StopAll, otherwise it says why the connection was lost; the app should then
	// connect again and repeat its subscriptions.
	OnClose(reason string)
}

// MQTTSession is an MQTT 3.1.1 session through the tunnel to an MQTT gateway of the
// agent. It runs entirely inside the app: no local port is opened, so other apps and
// processes on the device cannot use the tunnel.
type MQTTSession struct {
	m *Client
	s *mqttc.Session
}

// ConnectMQTT opens a tunnel to service (an MQTT gateway in the agent's config,
// e.g. "midgard") and starts an MQTT session over it. clientID is optional; the
// gateway prefixes it with the device name and adds the broker credentials, so the
// app needs none. keepAlive is in seconds (0 = 30). handler may be nil if the app
// only publishes.
func (m *Client) ConnectMQTT(service, clientID string, keepAlive int, handler MessageHandler) (*MQTTSession, error) {
	st := m.c.State()
	if st.AgentID == "" {
		return nil, errors.New("not paired yet")
	}
	if !slices.Contains(st.Services, service) {
		return nil, fmt.Errorf("service %q is not allowed for this device (allowed: %v)", service, st.Services)
	}
	if keepAlive < 0 || keepAlive > 65535 {
		return nil, fmt.Errorf("invalid keepAlive %d", keepAlive)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout*time.Second)
	defer cancel()
	conn, err := m.c.DialServiceContext(ctx, service)
	if err != nil {
		return nil, err
	}
	sess := &MQTTSession{m: m}
	opts := mqttc.Options{
		ClientID:  clientID,
		KeepAlive: time.Duration(keepAlive) * time.Second,
		OnClose: func(err error) {
			m.forget(sess)
			if handler != nil {
				reason := ""
				if err != nil {
					reason = err.Error()
				}
				handler.OnClose(reason)
			}
		},
	}
	if handler != nil {
		opts.OnMessage = func(msg mqttc.Message) { handler.OnMessage(msg.Topic, msg.Payload, msg.Retained) }
	}
	s, err := mqttc.Connect(conn, opts)
	if err != nil {
		return nil, err
	}
	sess.s = s
	m.mu.Lock()
	m.sessions[sess] = true
	m.mu.Unlock()
	return sess, nil
}

func (m *Client) forget(s *MQTTSession) {
	m.mu.Lock()
	delete(m.sessions, s)
	m.mu.Unlock()
}

// Publish sends payload to topic. qos is 0 or 1; with 1 it returns after the broker
// confirmed the message. A gateway ends the session on topics outside its allowlist.
func (s *MQTTSession) Publish(topic string, payload []byte, qos int, retain bool) error {
	return s.s.Publish(topic, payload, qos, retain)
}

// Subscribe subscribes to a topic filter ("+" and "#" allowed) with QoS 0 or 1 and
// returns after the broker confirmed it. A gateway ends the session on filters
// outside its allowlist.
func (s *MQTTSession) Subscribe(filter string, qos int) error {
	return s.s.Subscribe(filter, qos)
}

// Unsubscribe removes a subscription.
func (s *MQTTSession) Unsubscribe(filter string) error {
	return s.s.Unsubscribe(filter)
}

// IsConnected reports whether the session is still running.
func (s *MQTTSession) IsConnected() bool {
	select {
	case <-s.s.Done():
		return false
	default:
		return true
	}
}

// Close ends the session and its tunnel. The handler gets OnClose("").
func (s *MQTTSession) Close() {
	s.s.Close()
}

// StopAll closes every MQTT session, e.g. when the app goes to the background.
func (m *Client) StopAll() {
	m.mu.Lock()
	all := m.sessions
	m.sessions = map[*MQTTSession]bool{}
	m.mu.Unlock()
	for s := range all {
		s.s.Close()
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

// Unpair closes all sessions, deletes the pairing state and replaces the device
// keys. The agent is not notified: the admin should also run `bifrost revoke`.
func (m *Client) Unpair() error {
	m.StopAll()
	return m.c.Reset()
}
