// Package tcp is the passthrough service: every channel becomes one TCP connection
// to a fixed target, and bytes flow through unchanged.
package tcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/MichaelBMF/bifrost/internal/service"
	"github.com/MichaelBMF/bifrost/internal/wire"
)

// Config is a tcp service in asgard.json:
//
//	"ha": {"type": "tcp", "target": "192.168.10.20:8123"}
//
// The short form "ha": "192.168.10.20:8123" means the same.
type Config struct {
	Target string `json:"target"`
}

func init() {
	service.Register("tcp", func(raw json.RawMessage) (service.Service, error) {
		var c Config
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return New(c.Target)
	})
}

// New returns a passthrough service to target (host:port).
func New(target string) (service.Service, error) {
	if target == "" {
		return nil, errors.New("target missing")
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	return &svc{target: target}, nil
}

type svc struct{ target string }

func (s *svc) Modes() []service.Mode { return []service.Mode{wire.ModeStream} }
func (s *svc) String() string        { return "tcp " + s.target }

func (s *svc) Serve(_ service.Peer, _ service.Mode, ch service.Channel, accept func() error) error {
	up, err := net.DialTimeout("tcp", s.target, 5*time.Second)
	if err != nil {
		ch.Close()
		return err
	}
	if err := accept(); err != nil {
		up.Close()
		ch.Close()
		return err
	}
	wire.Pipe(ch, up)
	return nil
}
