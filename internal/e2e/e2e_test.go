package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MichaelBMF/bifrost/internal/agent"
	"github.com/MichaelBMF/bifrost/internal/client"
	"github.com/MichaelBMF/bifrost/internal/keys"
	"github.com/MichaelBMF/bifrost/internal/mqttc/mqtttest"
	"github.com/MichaelBMF/bifrost/internal/mqttgw"
	"github.com/MichaelBMF/bifrost/internal/relay"
	"github.com/MichaelBMF/bifrost/internal/wire"
)

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func echoServer(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

type env struct {
	relay    *relay.Relay
	agent    *agent.Agent
	relayPin string
	dir      string
	broker   *mqtttest.Broker // behind the "midgard" MQTT gateway
}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func setup(t *testing.T) *env {
	dir := t.TempDir()
	relayAddr := freePort(t)
	wgPort := freeUDPPort(t)
	broker := mqtttest.Start(t)
	midgard := &mqttgw.Config{Broker: broker.Addr(), Username: "midgard",
		Publish: []string{"midgard/+/command"}, Subscribe: []string{"midgard/#"}}
	if err := midgard.Load(); err != nil {
		t.Fatal(err)
	}
	rid, _, _ := keys.LoadOrCreate(filepath.Join(dir, "relay.key"))
	aid, _, _ := keys.LoadOrCreate(filepath.Join(dir, "agent.key"))
	r := relay.New(&relay.Config{Listen: relayAddr, KeyFile: filepath.Join(dir, "relay.key"),
		WGPort: wgPort, TunnelIP: "10.8.0.1", ControlPort: 7000,
		Agents: map[string]relay.AgentConfig{"homelab": {WGPub: aid.WGPublic(), TunnelIP: "10.8.0.2", StreamPort: 9000}}})
	go func() { t.Log(r.Run()) }()
	<-r.Ready()
	a, err := agent.New(&agent.Config{Relay: relayAddr, RelayPin: rid.TLSID(), AgentID: "homelab",
		RelayWGEndpoint: fmt.Sprintf("127.0.0.1:%d", wgPort), RelayWGPub: rid.WGPublic(),
		RelayTunnelIP: "10.8.0.1", ControlPort: 7000, TunnelIP: "10.8.0.2", StreamPort: 9000,
		KeyFile: filepath.Join(dir, "agent.key"), StateFile: filepath.Join(dir, "devices.json"),
		Services:     map[string]string{"mqtt": echoServer(t), "ha": echoServer(t)},
		MQTTGateways: map[string]*mqttgw.Config{"mqttgw": gatewayConfig(t), "midgard": midgard}})
	if err != nil {
		t.Fatal(err)
	}
	go a.Run()
	return &env{relay: r, agent: a, relayPin: rid.TLSID(), dir: dir, broker: broker}
}

func (e *env) pairCode(t *testing.T, name string, svcs ...string) string {
	deadline := time.Now().Add(20 * time.Second)
	for {
		code, err := e.agent.StartPairing(name, svcs)
		if err == nil {
			e.waitPairingOpen(t, code)
			return code
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitPairingOpen waits until pair_open has reached the relay over the control channel.
func (e *env) waitPairingOpen(t *testing.T, code string) {
	t.Helper()
	p, err := agent.ParsePairingCode(code)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := hex.DecodeString(p.Token)
	deadline := time.Now().Add(20 * time.Second)
	for !e.relay.PairingOpen(p.AgentID, wire.TokenHash(token)) {
		if time.Now().After(deadline) {
			t.Fatal("pairing window did not open at the relay")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func roundTrip(c net.Conn, n int) error {
	msg := make([]byte, n)
	rand.Read(msg)
	go c.Write(msg)
	got := make([]byte, n)
	c.SetReadDeadline(time.Now().Add(30 * time.Second)) // generous: 3 MB through userspace WireGuard is slow under -race
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestEndToEnd(t *testing.T) {
	e := setup(t)
	phone, _ := client.Open(filepath.Join(e.dir, "phone"))
	code := e.pairCode(t, "iphone", "mqtt")
	if _, err := phone.Pair(code, client.PairOptions{}); err != nil {
		t.Fatalf("pairing: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	t.Run("allowed service, 3 MB", func(t *testing.T) {
		c, err := phone.DialService("mqtt")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := roundTrip(c, 3<<20); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("service not allowed", func(t *testing.T) {
		if _, err := phone.DialService("ha"); err == nil {
			t.Fatal("ha should have been rejected")
		}
	})
	t.Run("token is single use", func(t *testing.T) {
		other, _ := client.Open(filepath.Join(e.dir, "other"))
		if _, err := other.Pair(code, client.PairOptions{}); err == nil {
			t.Fatal("second pairing with the same code should have failed")
		}
	})
	t.Run("compromised relay knows the token hash but not the token", func(t *testing.T) {
		code2 := e.pairCode(t, "evil", "mqtt", "ha")
		p, _ := agent.ParsePairingCode(code2)
		realToken, _ := hex.DecodeString(p.Token)
		agentPub, _ := hex.DecodeString(p.AgentPub)
		evil, _ := keys.Generate()
		cert, _ := evil.Certificate()
		conn, err := tls.Dial("tcp", p.Relay, wire.PinnedTLSConfig(cert, p.RelayPin))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		wire.WriteJSON(conn, wire.Hello{Role: "pair", AgentID: p.AgentID, TokenHash: wire.TokenHash(realToken)})
		var st wire.Status
		wire.ReadJSON(conn, &st)
		wrong := make([]byte, 32)
		if sc, err := wire.ClientHandshake(conn, evil.Noise, agentPub, wrong, wire.Prologue(p.AgentID)); err == nil {
			sc.WriteJSON(map[string]string{"relay_id": evil.TLSID()})
			sc.ReadJSON(&st)
		}
		time.Sleep(100 * time.Millisecond)
		b, _ := os.ReadFile(filepath.Join(e.dir, "devices.json"))
		if strings.Contains(string(b), "evil") {
			t.Fatal("device registered without knowing the token")
		}
	})
	t.Run("only the agent stream port is reachable through the tunnel", func(t *testing.T) {
		for _, port := range []uint16{22, 1883, 7070, 8123} {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			c, err := e.relay.Tunnel().DialContextTCPAddrPort(ctx, netip.AddrPortFrom(netip.MustParseAddr("10.8.0.2"), port))
			cancel()
			if err == nil {
				c.Close()
				t.Fatalf("home lab port %d reachable through the tunnel", port)
			}
		}
	})
	t.Run("revocation closes active connection", func(t *testing.T) {
		c, err := phone.DialService("mqtt")
		if err != nil {
			t.Fatal(err)
		}
		if err := roundTrip(c, 1000); err != nil {
			t.Fatal(err)
		}
		if err := e.agent.Revoke("iphone"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if err := roundTrip(c, 1000); err == nil {
			t.Fatal("connection kept running after revocation")
		}
		if _, err := phone.DialService("mqtt"); err == nil {
			t.Fatal("new connection possible after revocation")
		}
	})
}
