// Package client simulates the app's tunnel core: pairing and local port forwarding.
// The same code could be embedded in an iOS or Android app via gomobile.
package client

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/MichaelBMF/bifrost/internal/agent"
	"github.com/MichaelBMF/bifrost/internal/keys"
	"github.com/MichaelBMF/bifrost/internal/wire"
)

type State struct {
	Relay    string   `json:"relay"`
	RelayPin string   `json:"relay_pin"`
	AgentID  string   `json:"agent_id"`
	AgentPub string   `json:"agent_pub"`
	Services []string `json:"services"`
}

type Client struct {
	id    *keys.Identity
	state State
	path  string
}

// Open loads the keys (<base>.key) and pairing state (<base>.json).
func Open(base string) (*Client, error) {
	id, _, err := keys.LoadOrCreate(base + ".key")
	if err != nil {
		return nil, err
	}
	c := &Client{id: id, path: base + ".json"}
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, &c.state)
	}
	return c, nil
}

func (c *Client) dialRelay(relay, pin string, h wire.Hello) (net.Conn, error) {
	cert, err := c.id.Certificate()
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial("tcp", relay, wire.PinnedTLSConfig(cert, pin))
	if err != nil {
		return nil, err
	}
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

func (c *Client) Pair(code string) error {
	p, err := agent.ParsePairingCode(code)
	if err != nil {
		return err
	}
	token, err1 := hex.DecodeString(p.Token)
	agentPub, err2 := hex.DecodeString(p.AgentPub)
	if err1 != nil || err2 != nil {
		return errors.New("corrupt pairing code")
	}
	conn, err := c.dialRelay(p.Relay, p.RelayPin, wire.Hello{Role: "pair", AgentID: p.AgentID, TokenHash: wire.TokenHash(token)})
	if err != nil {
		return err
	}
	defer conn.Close()
	sc, err := wire.ClientHandshake(conn, c.id.Noise, agentPub, token, wire.Prologue(p.AgentID))
	if err != nil {
		return err
	}
	if err := sc.WriteJSON(map[string]string{"relay_id": c.id.TLSID()}); err != nil {
		return err
	}
	var resp struct {
		OK       bool     `json:"ok"`
		Name     string   `json:"name"`
		Services []string `json:"services"`
		DeviceFP string   `json:"device_fp"`
		AgentFP  string   `json:"agent_fp"`
	}
	if err := sc.ReadJSON(&resp); err != nil || !resp.OK {
		return fmt.Errorf("pairing rejected: %v", err)
	}
	c.state = State{Relay: p.Relay, RelayPin: p.RelayPin, AgentID: p.AgentID, AgentPub: p.AgentPub, Services: resp.Services}
	b, _ := json.MarshalIndent(c.state, "", "  ")
	if err := os.WriteFile(c.path, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("Paired as %q. Services: %v\nDevice fingerprint: %s\nAgent fingerprint: %s\n",
		resp.Name, resp.Services, resp.DeviceFP, resp.AgentFP)
	return nil
}

// DialService opens an end-to-end encrypted connection to a service.
func (c *Client) DialService(name string) (net.Conn, error) {
	if c.state.AgentID == "" {
		return nil, errors.New("not paired yet")
	}
	agentPub, _ := hex.DecodeString(c.state.AgentPub)
	conn, err := c.dialRelay(c.state.Relay, c.state.RelayPin, wire.Hello{Role: "dial", AgentID: c.state.AgentID})
	if err != nil {
		return nil, err
	}
	sc, err := wire.ClientHandshake(conn, c.id.Noise, agentPub, nil, wire.Prologue(c.state.AgentID))
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := sc.WriteJSON(map[string]string{"open": name}); err != nil {
		sc.Close()
		return nil, err
	}
	var st wire.Status
	if err := sc.ReadJSON(&st); err != nil || !st.OK {
		sc.Close()
		if err == nil {
			err = errors.New(st.Error)
		}
		return nil, err
	}
	return sc, nil
}

// Forward opens a local port; each connection becomes its own tunnel.
func (c *Client) Forward(service, listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("%s -> service %q", listen, service)
	for {
		local, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			remote, err := c.DialService(service)
			if err != nil {
				log.Printf("%s: %v", service, err)
				local.Close()
				return
			}
			wire.Pipe(local, remote)
		}()
	}
}
