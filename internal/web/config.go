// Package web is Hlidskjalf, a small web UI for managing bifrost devices.
//
// It runs next to the agent (bifrost asgard), talks to the agent's admin API on
// localhost and exposes only its own, login-protected pages to the LAN. The admin
// API itself is never proxied.
package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

type User struct {
	Name string `json:"name"`
	// PasswordHash is a bcrypt hash, created with `bifrost hlidskjalf -hash`.
	PasswordHash string `json:"password_hash"`
}

type TLSConfig struct {
	// Mode is "self-signed" (default: a certificate is created in StateDir),
	// "files" (Cert and Key) or "off" (plain HTTP, only behind a TLS proxy).
	Mode string `json:"mode"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type Config struct {
	Listen string `json:"listen"` // e.g. "0.0.0.0:8443"
	Admin  string `json:"admin"`  // the agent's admin API, e.g. "127.0.0.1:7070"
	Users  []User `json:"users"`
	// Protected devices are shown with a lock and cannot be revoked from the UI.
	Protected []string `json:"protected"`
	// Services offered in the pairing form (must exist in asgard.json).
	Services []string  `json:"services"`
	TLS      TLSConfig `json:"tls"`
	StateDir string    `json:"state_dir"` // for the self-signed certificate
	// SessionHours is the session lifetime (default 12).
	SessionHours int `json:"session_hours"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, c.normalize()
}

func (c *Config) normalize() error {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8443"
	}
	if c.Admin == "" {
		c.Admin = "127.0.0.1:7070"
	}
	if len(c.Services) == 0 {
		c.Services = []string{"mqtt"}
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = "self-signed"
	}
	if c.SessionHours <= 0 {
		c.SessionHours = 12
	}
	switch c.TLS.Mode {
	case "self-signed":
		if c.StateDir == "" {
			return errors.New("state_dir is required for tls.mode self-signed")
		}
	case "files":
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return errors.New("tls.cert and tls.key are required for tls.mode files")
		}
	case "off":
	default:
		return fmt.Errorf("unknown tls.mode %q", c.TLS.Mode)
	}
	if len(c.Users) == 0 {
		return errors.New("no users configured (create a hash with `bifrost hlidskjalf -hash`)")
	}
	for _, u := range c.Users {
		if u.Name == "" || !strings.HasPrefix(u.PasswordHash, "$2") {
			return fmt.Errorf("user %q needs a name and a bcrypt password_hash", u.Name)
		}
	}
	return nil
}

func (c *Config) isProtected(name string) bool { return slices.Contains(c.Protected, name) }
