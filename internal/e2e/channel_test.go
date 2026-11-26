package e2e

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MichaelBMF/bifrost/internal/mqttc"
	"github.com/MichaelBMF/bifrost/internal/services/mqtt"
	"github.com/MichaelBMF/bifrost/mobile"
)

// waitEvent reads channel events until one satisfies ok.
func waitEvent(t *testing.T, events <-chan mqtt.Event, ok func(mqtt.Event) bool) mqtt.Event {
	t.Helper()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case e := <-events:
			if ok(e) {
				return e
			}
		case <-timeout:
			t.Fatal("expected event did not arrive")
		}
	}
}

func idIs(id int64) func(mqtt.Event) bool {
	return func(e mqtt.Event) bool { return e.ID == id }
}

type chanHandler struct {
	events chan mqtt.Event
	closed chan string
}

func (h *chanHandler) OnMessage(msg []byte) {
	var e mqtt.Event
	if err := json.Unmarshal(msg, &e); err == nil {
		h.events <- e
	}
}
func (h *chanHandler) OnClose(err string) { h.closed <- err }

// TestMQTTServiceMessageMode runs the app path of v0.4.0: the mobile binding opens a
// channel in message mode, the agent's mqtt service talks MQTT to the broker.
func TestMQTTServiceMessageMode(t *testing.T) {
	e := setup(t)
	app, err := mobile.NewClient(filepath.Join(e.dir, "app"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Pair(e.pairCode(t, "iphone", "midgard", "ha"), "michael", "iPhone"); err != nil {
		t.Fatalf("pairing: %v", err)
	}

	// Watch the broker directly, as Home Assistant would.
	bc, err := net.Dial("tcp", e.broker.Addr())
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan mqttc.Message, 16)
	watcher, err := mqttc.Connect(bc, mqttc.Options{ClientID: "ha", OnMessage: func(m mqttc.Message) { seen <- m }})
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if err := watcher.Subscribe("midgard/#", 1); err != nil {
		t.Fatal(err)
	}

	h := &chanHandler{events: make(chan mqtt.Event, 64), closed: make(chan string, 1)}
	var ch *mobile.Channel
	eventually(t, func() error { // the relay learns the new device asynchronously
		var err error
		ch, err = app.OpenChannel("midgard", h)
		return err
	})
	send := func(s string) {
		t.Helper()
		if err := ch.Send([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}

	send(`{"op":"sub","id":1,"filter":"midgard/tg/#","qos":1}`)
	if ev := waitEvent(t, h.events, idIs(1)); ev.Op != "ack" {
		t.Fatalf("sub: %+v", ev)
	}

	// Publish: allowed topic, forged identity is replaced by the pairing's.
	send(`{"op":"pub","id":2,"topic":"midgard/tg/command","payload":{"action":"open","bifrost":{"device":"forged"}},"qos":1}`)
	if ev := waitEvent(t, h.events, idIs(2)); ev.Op != "ack" {
		t.Fatalf("pub: %+v", ev)
	}
	select {
	case m := <-seen:
		var got struct {
			Action  string
			Bifrost struct {
				Device, User string
			}
		}
		json.Unmarshal(m.Payload, &got)
		if m.Topic != "midgard/tg/command" || got.Action != "open" || got.Bifrost.Device != "iphone" || got.Bifrost.User != "michael" {
			t.Fatalf("broker got %s %s", m.Topic, m.Payload)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("publish did not reach the broker")
	}

	// Denied publish and subscribe: error, but the channel stays open.
	send(`{"op":"pub","id":3,"topic":"zigbee2mqtt/tor/set","payload_text":"open"}`)
	if ev := waitEvent(t, h.events, idIs(3)); ev.Op != "error" || !strings.Contains(ev.Error, "denied") {
		t.Fatalf("denied pub: %+v", ev)
	}
	send(`{"op":"sub","id":4,"filter":"#"}`)
	if ev := waitEvent(t, h.events, idIs(4)); ev.Op != "error" {
		t.Fatalf("denied sub: %+v", ev)
	}
	send(`{"op":"ping","id":5}`)
	if ev := waitEvent(t, h.events, idIs(5)); ev.Op != "ack" {
		t.Fatalf("ping: %+v", ev)
	}
	select {
	case m := <-seen:
		t.Fatalf("denied publish reached the broker: %s", m.Topic)
	default:
	}

	// Broker to app: JSON and plain text payloads.
	e.broker.Publish("midgard/tg/state", []byte(`{"state":"open"}`), true)
	ev := waitEvent(t, h.events, func(e mqtt.Event) bool { return e.Op == "msg" && e.Topic == "midgard/tg/state" })
	if string(ev.Payload) != `{"state":"open"}` {
		t.Fatalf("state: %+v", ev)
	}
	e.broker.Publish("midgard/tg/text", []byte("ON"), false)
	ev = waitEvent(t, h.events, func(e mqtt.Event) bool { return e.Op == "msg" && e.Topic == "midgard/tg/text" })
	if ev.PayloadText == nil || *ev.PayloadText != "ON" {
		t.Fatalf("text: %+v", ev)
	}
	found := false
	for _, u := range e.broker.Users() {
		found = found || u == "midgard"
	}
	if !found {
		t.Fatalf("agent did not log in as midgard: %v", e.broker.Users())
	}

	// A passthrough service has no message mode.
	if _, err := app.OpenChannel("ha", h); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("ha in message mode: %v", err)
	}

	ch.Close()
	select {
	case reason := <-h.closed:
		if reason != "" {
			t.Fatalf("OnClose after Close: %q", reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OnClose not called")
	}
	if ch.IsOpen() || ch.Send([]byte("{}")) == nil {
		t.Fatal("closed channel still usable")
	}
}

// TestChannelBrokerLost: if the broker goes away, the app learns it from OnClose.
func TestChannelBrokerLost(t *testing.T) {
	e := setup(t)
	app, _ := mobile.NewClient(filepath.Join(e.dir, "app"))
	if _, err := app.Pair(e.pairCode(t, "iphone", "midgard"), "", ""); err != nil {
		t.Fatal(err)
	}
	h := &chanHandler{events: make(chan mqtt.Event, 64), closed: make(chan string, 1)}
	eventually(t, func() error { _, err := app.OpenChannel("midgard", h); return err })
	e.broker.DropAll()
	ev := waitEvent(t, h.events, func(e mqtt.Event) bool { return e.Op == "error" })
	if !strings.Contains(ev.Error, "broker") {
		t.Fatalf("event: %+v", ev)
	}
	select {
	case reason := <-h.closed:
		if reason == "" {
			t.Fatal("OnClose without a reason")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("OnClose not called")
	}
}

// Stream mode (all clients before v0.4.0) keeps working for the same service name.
func TestStreamModeStillWorks(t *testing.T) {
	e := setup(t)
	app, _ := mobile.NewClient(filepath.Join(e.dir, "app"))
	if _, err := app.Pair(e.pairCode(t, "iphone", "ha"), "", ""); err != nil {
		t.Fatal(err)
	}
	var port int
	eventually(t, func() error { var err error; port, err = app.StartForward("ha", 0); return err })
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if err := roundTrip(c, 1000); err != nil {
		t.Fatal(err)
	}
}
