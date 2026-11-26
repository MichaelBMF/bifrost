package e2e

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MichaelBMF/bifrost/internal/agent"
	"github.com/MichaelBMF/bifrost/internal/client"
	"github.com/MichaelBMF/bifrost/internal/keys"
	"github.com/MichaelBMF/bifrost/internal/wire"
	"github.com/MichaelBMF/bifrost/mobile"
)

func (e *env) devices(t *testing.T) map[string]agent.Device {
	b, err := os.ReadFile(filepath.Join(e.dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]agent.Device
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// eventually retries f until it succeeds; the relay learns new devices asynchronously.
func eventually(t *testing.T, f func() error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := f()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestMobileBinding(t *testing.T) {
	e := setup(t)
	dir := filepath.Join(e.dir, "app")
	app, err := mobile.NewClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	code := e.pairCode(t, "iphone", "mqtt", "midgard")
	out, err := app.Pair(code, "alice", "Alice's iPhone\n")
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	var res client.PairResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if res.Name != "iphone" || res.User != "alice" || res.DeviceName != "Alice's iPhone" || len(res.Services) != 2 {
		t.Fatalf("unexpected pair result: %s", out)
	}
	d := e.devices(t)["iphone"]
	if d.User != "alice" || d.DeviceName != "Alice's iPhone" || d.UserBound {
		t.Fatalf("agent stored %+v", d)
	}
	if _, err := app.Pair(e.pairCode(t, "again", "mqtt"), "", ""); err == nil {
		t.Fatal("second Pair on a paired client must fail")
	}

	var info map[string]any
	json.Unmarshal([]byte(app.Info()), &info)
	if info["paired"] != true || info["user"] != "alice" || info["name"] != "iphone" || info["agent_id"] != "homelab" {
		t.Fatalf("unexpected info: %v", info)
	}

	eventually(t, func() error { return app.Probe("mqtt") })
	if err := app.Probe("ha"); err == nil {
		t.Fatal("probe of a service that is not allowed must fail")
	}
	if _, err := app.ConnectMQTT("ha", "app", 0, nil); err == nil {
		t.Fatal("MQTT to a service that is not allowed must fail")
	}
	app.StopAll()

	// State survives a restart of the app.
	app2, err := mobile.NewClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !app2.IsPaired() {
		t.Fatal("pairing lost after reopening")
	}
	eventually(t, func() error { return app2.Probe("mqtt") })

	if err := app2.Unpair(); err != nil {
		t.Fatal(err)
	}
	if app2.IsPaired() || app2.Probe("mqtt") == nil {
		t.Fatal("still paired after Unpair")
	}
}

func TestUserBoundPairing(t *testing.T) {
	e := setup(t)
	pairCode := func(name, user string) string {
		var code string
		eventually(t, func() (err error) {
			code, err = e.agent.StartPairingForUser(name, user, []string{"mqtt"})
			return err
		})
		e.waitPairingOpen(t, code)
		return code
	}

	code := pairCode("bound", "alice")
	bob, _ := client.Open(filepath.Join(e.dir, "bob"))
	if _, err := bob.Pair(code, client.PairOptions{User: "bob"}); err == nil || !strings.Contains(err.Error(), "user does not match") {
		t.Fatalf("pairing with the wrong user must fail, got %v", err)
	}
	alice, _ := client.Open(filepath.Join(e.dir, "alice"))
	if _, err := alice.Pair(code, client.PairOptions{User: "alice"}); err == nil {
		t.Fatal("token must be burned after a user mismatch")
	}
	if _, err := alice.Pair(pairCode("bound2", "alice"), client.PairOptions{}); err == nil || !strings.Contains(err.Error(), "user does not match") {
		t.Fatalf("pairing without user must fail when a user is bound, got %v", err)
	}
	res, err := alice.Pair(pairCode("bound3", "alice"), client.PairOptions{User: "alice", DeviceName: "iPad"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "bound3" || res.User != "alice" {
		t.Fatalf("unexpected result %+v", res)
	}
	devs := e.devices(t)
	if len(devs) != 1 || !devs["bound3"].UserBound || devs["bound3"].DeviceName != "iPad" {
		t.Fatalf("unexpected devices %+v", devs)
	}
	if _, err := e.agent.StartPairingForUser("x", "bad\nuser", []string{"mqtt"}); err == nil {
		t.Fatal("control characters in a bound user must be rejected")
	}
}

// An old client sends only {"relay_id": ...} and must still be able to pair.
func TestLegacyPairRequest(t *testing.T) {
	e := setup(t)
	code := e.pairCode(t, "legacy", "mqtt")
	p, _ := wire.ParsePairingCode(code)
	token, _ := hex.DecodeString(p.Token)
	agentPub, _ := hex.DecodeString(p.AgentPub)
	id, _ := keys.Generate()
	cert, _ := id.Certificate()
	conn, err := tls.Dial("tcp", p.Relay, wire.PinnedTLSConfig(cert, p.RelayPin))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wire.WriteJSON(conn, wire.Hello{Role: "pair", AgentID: p.AgentID, TokenHash: wire.TokenHash(token)})
	var st wire.Status
	if err := wire.ReadJSON(conn, &st); err != nil || !st.OK {
		t.Fatalf("relay: %v %+v", err, st)
	}
	sc, err := wire.ClientHandshake(conn, id.Noise, agentPub, token, wire.Prologue(p.AgentID))
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.WriteJSON(map[string]string{"relay_id": id.TLSID()}); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := sc.ReadJSON(&resp); err != nil || resp["ok"] != true || resp["name"] != "legacy" {
		t.Fatalf("legacy pairing: %v %v", err, resp)
	}
	if d := e.devices(t)["legacy"]; d.User != "" || d.DeviceName != "" || d.RelayID != id.TLSID() {
		t.Fatalf("unexpected device %+v", d)
	}
}

type handler struct {
	msgs   chan [3]string // topic, payload, retained
	closed chan string
}

func newHandler() *handler {
	return &handler{msgs: make(chan [3]string, 16), closed: make(chan string, 1)}
}

func (h *handler) OnMessage(topic string, payload []byte, retained bool) {
	h.msgs <- [3]string{topic, string(payload), fmt.Sprint(retained)}
}

func (h *handler) OnClose(reason string) { h.closed <- reason }

func (h *handler) next(t *testing.T) [3]string {
	t.Helper()
	select {
	case m := <-h.msgs:
		return m
	case <-time.After(20 * time.Second):
		t.Fatal("no message")
	}
	return [3]string{}
}

func (h *handler) waitClosed(t *testing.T) string {
	t.Helper()
	select {
	case r := <-h.closed:
		return r
	case <-time.After(20 * time.Second):
		t.Fatal("OnClose not called")
	}
	return ""
}

// The app speaks MQTT inside its own process through the gateway: no local port,
// broker credentials only in the agent, sender identity stamped by the gateway.
func TestMobileMQTT(t *testing.T) {
	e := setup(t)
	app, err := mobile.NewClient(filepath.Join(e.dir, "mqtt-app"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Pair(e.pairCode(t, "iphone", "midgard"), "alice", "Alice's iPhone"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ConnectMQTT("mqtt", "app", 0, nil); err == nil {
		t.Fatal("ConnectMQTT to a service that is not allowed must fail")
	}
	e.broker.Publish("midgard/tg/state", []byte(`{"state":"closed"}`), true)

	h := newHandler()
	var s *mobile.MQTTSession
	eventually(t, func() (err error) {
		s, err = app.ConnectMQTT("midgard", "app", 30, h)
		return err
	})
	if !s.IsConnected() {
		t.Fatal("not connected")
	}
	if err := s.Subscribe("midgard/#", 1); err != nil {
		t.Fatal(err)
	}
	if m := h.next(t); m != [3]string{"midgard/tg/state", `{"state":"closed"}`, "true"} {
		t.Fatalf("retained state: %v", m)
	}
	if err := s.Publish("midgard/tg/command", []byte(`{"action":"open"}`), 1, false); err != nil {
		t.Fatal(err)
	}
	m := h.next(t)
	var got map[string]any
	if err := json.Unmarshal([]byte(m[1]), &got); err != nil || m[0] != "midgard/tg/command" {
		t.Fatalf("command: %v %v", m, err)
	}
	id, _ := got["bifrost"].(map[string]any)
	if got["action"] != "open" || id["device"] != "iphone" || id["user"] != "alice" {
		t.Fatalf("gateway did not stamp the sender: %v", got)
	}
	if u := e.broker.Users(); len(u) == 0 || u[len(u)-1] != "midgard" {
		t.Fatalf("broker users: %v", u)
	}

	// StopAll ends the session; OnClose gets an empty reason.
	app.StopAll()
	if r := h.waitClosed(t); r != "" {
		t.Fatalf("OnClose after StopAll: %q", r)
	}
	if s.IsConnected() || s.Publish("midgard/tg/command", []byte("x"), 0, false) == nil {
		t.Fatal("session alive after StopAll")
	}

	// A publish outside the allowlist makes the gateway end the session.
	h2 := newHandler()
	s2, err := app.ConnectMQTT("midgard", "", 0, h2)
	if err != nil {
		t.Fatal(err)
	}
	s2.Publish("zigbee2mqtt/tor/set", []byte("open"), 0, false)
	if r := h2.waitClosed(t); r == "" {
		t.Fatal("denied publish must close the session with a reason")
	}
	if s2.IsConnected() {
		t.Fatal("session alive after denied publish")
	}
}
