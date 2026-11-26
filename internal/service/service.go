// Package service is the boundary between the bifrost transport and the services
// behind it.
//
// The transport (relay, Noise, pairing, device rights) ends in the agent with a
// Channel to one service. The first message on it names the service and the mode
// (wire.Open). From there on the transport only moves bytes or messages; what they
// mean is up to the service. Services live in their own packages (internal/services/...)
// and register a type here; the agent never imports them.
package service

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"
	"sync"
)

// Mode is how a channel carries data: wire.ModeStream or wire.ModeMsg.
type Mode = string

// Peer is the paired device behind a channel. The values come from the pairing in
// the agent, not from the app, so a service can trust them.
type Peer struct {
	Device    string `json:"device"`               // name from `bifrost pair -name`
	User      string `json:"user,omitempty"`       // user from the pairing
	UserBound bool   `json:"user_bound,omitempty"` // true if the admin bound the user
}

// Channel is one end-to-end encrypted connection from a device. In stream mode a
// service uses Read and Write; in message mode ReadMsg and WriteMsg, where each call
// is exactly one message. WriteMsg may be called from several goroutines. Deadlines
// apply to the underlying connection.
type Channel interface {
	net.Conn
	ReadMsg() ([]byte, error)
	WriteMsg([]byte) error
}

// Service handles channels for one configured service name.
type Service interface {
	// Modes lists the channel modes the service accepts.
	Modes() []Mode
	// Serve runs one channel until it ends. It must call accept exactly once when it
	// is ready (e.g. after reaching its backend) and before it uses ch; accept tells
	// the device that the channel is open. If Serve returns before calling accept,
	// the device is told that the service is unavailable. Serve closes ch.
	Serve(p Peer, mode Mode, ch Channel, accept func() error) error
	// String describes the service for the log, e.g. "tcp 127.0.0.1:1883".
	String() string
}

// Factory builds a service from its JSON config (the whole object, "type" included).
type Factory func(config json.RawMessage) (Service, error)

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register makes a service type available to the agent config. It is meant to be
// called from the init function of a service package.
func Register(typ string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[typ]; dup {
		panic("service type registered twice: " + typ)
	}
	registry[typ] = f
}

// Types returns the registered service types, sorted.
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// New builds a service of type typ from config.
func New(typ string, config json.RawMessage) (Service, error) {
	mu.RLock()
	f := registry[typ]
	mu.RUnlock()
	if f == nil {
		return nil, fmt.Errorf("unknown service type %q (known: %v)", typ, Types())
	}
	return f(config)
}

// Supports reports whether s accepts mode.
func Supports(s Service, mode Mode) bool { return slices.Contains(s.Modes(), mode) }
