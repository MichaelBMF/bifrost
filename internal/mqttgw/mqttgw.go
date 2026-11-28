// Package mqttgw holds the config and the topic rules of the mqtt service
// (internal/services/mqtt): broker, credentials, publish and subscribe allowlists and
// the sender identity added to published JSON objects.
//
// Until bifrost v0.5.0 it was also an MQTT 3.1.1 proxy for apps that spoke MQTT
// through the tunnel (stream mode). That is gone; devices use the message mode.
package mqttgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// Config is one mqtt service as configured in asgard.json.
type Config struct {
	Broker   string `json:"broker"`   // host:port of the MQTT broker
	Username string `json:"username"` // broker user of the gateway
	// PasswordFile holds the broker password. Environment variables are expanded, so
	// "${CREDENTIALS_DIRECTORY}/mqtt-midgard" works with systemd LoadCredential=.
	PasswordFile string `json:"password_file"`
	// Publish and Subscribe are MQTT topic filters ("+" and "#" allowed). A device may
	// publish to topics matched by Publish and subscribe to filters within Subscribe.
	Publish   []string `json:"publish"`
	Subscribe []string `json:"subscribe"`
	// Identity adds the sender to every JSON-object payload the device publishes, as
	// "bifrost": {"device": ..., "user": ..., "user_bound": ...}. These values come from
	// the pairing, not from the app, so the receiver (e.g. Home Assistant) can trust
	// them. Any "bifrost" field sent by the device is replaced. Default: on.
	Identity *bool `json:"identity,omitempty"`

	password string
}

// Peer is the paired device behind a channel.
type Peer struct {
	Device    string `json:"device"`               // name from `bifrost pair -name`
	User      string `json:"user,omitempty"`       // user from the pairing
	UserBound bool   `json:"user_bound,omitempty"` // true if the admin bound the user (`-user`)
}

func (c *Config) identity() bool { return c.Identity == nil || *c.Identity }

// Load validates the config and reads the password file.
func (c *Config) Load() error {
	if c.Broker == "" {
		return errors.New("broker missing")
	}
	if _, _, err := net.SplitHostPort(c.Broker); err != nil {
		return fmt.Errorf("broker: %w", err)
	}
	if c.PasswordFile != "" {
		b, err := os.ReadFile(os.ExpandEnv(c.PasswordFile))
		if err != nil {
			return fmt.Errorf("password_file: %w", err)
		}
		c.password = strings.TrimRight(string(b), "\r\n")
	}
	for _, f := range append(append([]string{}, c.Publish...), c.Subscribe...) {
		if !validFilter(f) {
			return fmt.Errorf("invalid topic filter %q", f)
		}
	}
	return nil
}

// maxPayload bounds a stamped payload (the broker connection of the message mode
// accepts at most this much in one PUBLISH).
const maxPayload = 256 << 10

// ErrDenied is the error for a publish or subscribe outside the allowlists.
var ErrDenied = errors.New("denied by gateway")

// stamp sets payload["bifrost"] = peer if the payload is a JSON object.
func stamp(payload []byte, peer Peer) ([]byte, bool) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, false
	}
	id, err := json.Marshal(peer)
	if err != nil {
		return nil, false
	}
	obj["bifrost"] = id
	out, err := json.Marshal(obj)
	if err != nil || len(out) > maxPayload-1024 {
		return nil, false
	}
	return out, true
}

// MARK: topic filters

func validFilter(f string) bool {
	if f == "" {
		return false
	}
	levels := strings.Split(f, "/")
	for i, l := range levels {
		if strings.Contains(l, "#") && (l != "#" || i != len(levels)-1) {
			return false
		}
		if strings.Contains(l, "+") && l != "+" {
			return false
		}
	}
	return true
}

// match reports whether topic (no wildcards) matches filter.
func match(filter, topic string) bool {
	if topic == "" || strings.ContainsAny(topic, "+#") || strings.HasPrefix(topic, "$") {
		return false
	}
	f, t := strings.Split(filter, "/"), strings.Split(topic, "/")
	for i, l := range f {
		if l == "#" {
			return true
		}
		if i >= len(t) || (l != "+" && l != t[i]) {
			return false
		}
	}
	return len(f) == len(t)
}

func matchAny(filters []string, topic string) bool {
	for _, f := range filters {
		if match(f, topic) {
			return true
		}
	}
	return false
}

// covered reports whether every topic matched by sub is also matched by allowed.
func covered(allowed, sub string) bool {
	if !validFilter(sub) || strings.HasPrefix(sub, "$") {
		return false
	}
	a, s := strings.Split(allowed, "/"), strings.Split(sub, "/")
	for i, l := range a {
		if l == "#" {
			return true
		}
		if i >= len(s) {
			return false
		}
		switch {
		case s[i] == "#":
			return false
		case l == "+":
			continue
		case s[i] == "+" || s[i] != l:
			return false
		}
	}
	return len(a) == len(s)
}

func coveredByAny(allowed []string, sub string) bool {
	for _, a := range allowed {
		if covered(a, sub) {
			return true
		}
	}
	return false
}

// MARK: used by the message mode of the mqtt service

// MayPublish reports whether a device may publish to topic.
func (c *Config) MayPublish(topic string) bool { return matchAny(c.Publish, topic) }

// MaySubscribe reports whether a device may subscribe to filter.
func (c *Config) MaySubscribe(filter string) bool { return coveredByAny(c.Subscribe, filter) }

// AddsIdentity reports whether published JSON objects get the "bifrost" field.
func (c *Config) AddsIdentity() bool { return c.identity() }

// Password returns the broker password read by Load.
func (c *Config) Password() string { return c.password }

// Stamp sets payload["bifrost"] = peer if payload is a JSON object.
func Stamp(payload []byte, peer Peer) ([]byte, bool) { return stamp(payload, peer) }

// ValidTopic reports whether topic is a valid topic name to publish to.
func ValidTopic(topic string) bool {
	return topic != "" && !strings.ContainsAny(topic, "+#") && !strings.HasPrefix(topic, "$")
}
