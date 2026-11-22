package mqttgw

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		filter, topic string
		want          bool
	}{
		{"midgard/+/command", "midgard/tg/command", true},
		{"midgard/+/command", "midgard/tg/state", false},
		{"midgard/+/command", "midgard/tg/command/x", false},
		{"midgard/#", "midgard", true},
		{"midgard/#", "midgard/a/b", true},
		{"midgard/#", "other/a", false},
		{"#", "$SYS/broker", false},
		{"midgard/tg/command", "midgard/tg/+", false},
	}
	for _, c := range cases {
		if got := match(c.filter, c.topic); got != c.want {
			t.Errorf("match(%q, %q) = %v", c.filter, c.topic, got)
		}
	}
}

func TestCovered(t *testing.T) {
	cases := []struct {
		allowed, sub string
		want         bool
	}{
		{"midgard/#", "midgard/tg/state", true},
		{"midgard/#", "midgard/+/state", true},
		{"midgard/#", "midgard/#", true},
		{"midgard/#", "#", false},
		{"midgard/+/state", "midgard/tg/state", true},
		{"midgard/+/state", "midgard/+/state", true},
		{"midgard/+/state", "midgard/#", false},
		{"midgard/tg/state", "midgard/+/state", false},
		{"midgard/#", "midgard/a#", false},
		{"#", "$SYS/#", false},
	}
	for _, c := range cases {
		if got := covered(c.allowed, c.sub); got != c.want {
			t.Errorf("covered(%q, %q) = %v", c.allowed, c.sub, got)
		}
	}
}

func connectPacket(clientID, user, pass string) packet {
	flags := byte(0x02)
	payload := putStr(nil, clientID)
	if user != "" {
		flags |= 0x80
		payload = putStr(payload, user)
		if pass != "" {
			flags |= 0x40
			payload = putStr(payload, pass)
		}
	}
	body := putStr(nil, "MQTT")
	body = append(body, 4, flags, 0, 30)
	return packet{header: 0x10, body: append(body, payload...)}
}

func publishPacket(topic, payload string) packet {
	return packet{header: 0x30, body: append(putStr(nil, topic), payload...)}
}

func subscribePacket(filter string) packet {
	body := []byte{0, 1}
	body = putStr(body, filter)
	return packet{header: 0x82, body: append(body, 0)}
}

// fakeBroker accepts one connection and reports the packets it receives.
func fakeBroker(t *testing.T) (string, chan packet) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan packet, 16)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for {
			p, err := readPacket(r)
			if err != nil {
				close(got)
				return
			}
			if p.typ() == 1 {
				c.Write([]byte{0x20, 2, 0, 0})
			}
			got <- p
		}
	}()
	return ln.Addr().String(), got
}

func newGateway(t *testing.T, broker string) *Config {
	t.Helper()
	pw := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pw, []byte("s3cret\n"), 0o600)
	c := &Config{Broker: broker, Username: "midgard", PasswordFile: pw,
		Publish: []string{"midgard/+/command"}, Subscribe: []string{"midgard/#"}}
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}
	return c
}

func next(t *testing.T, ch chan packet) packet {
	t.Helper()
	select {
	case p, ok := <-ch:
		if !ok {
			t.Fatal("broker connection closed")
		}
		return p
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
	return packet{}
}

func TestGatewayInjectsCredentialsAndFilters(t *testing.T) {
	addr, got := fakeBroker(t)
	gw := newGateway(t, addr)
	dev, gwSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- gw.Serve(Peer{Device: "michael-iphone", User: "michael", UserBound: true}, gwSide) }()

	// The device sends its own (wrong) credentials; they must be replaced.
	go dev.Write(connectPacket("app1", "intruder", "guess").bytes())
	conn := next(t, got)
	r := &reader{b: conn.body}
	r.str()
	r.u8()
	flags := r.u8()
	r.u16()
	id, user, pass := r.str(), r.str(), r.str()
	if r.err != nil || flags&0xc0 != 0xc0 || id != "michael-iphone-app1" || user != "midgard" || pass != "s3cret" {
		t.Fatalf("CONNECT to broker: flags %x id %q user %q pass %q err %v", flags, id, user, pass, r.err)
	}
	ack := make([]byte, 4)
	if _, err := dev.Read(ack); err != nil || ack[0] != 0x20 {
		t.Fatalf("no CONNACK for device: %v %x", err, ack)
	}

	go dev.Write(subscribePacket("midgard/tg/state").bytes())
	if p := next(t, got); p.typ() != 8 {
		t.Fatalf("expected SUBSCRIBE, got type %d", p.typ())
	}
	// The device tries to claim another identity; the gateway overwrites it.
	go dev.Write(publishPacket("midgard/tg/command", `{"action":"einfahren","bifrost":{"device":"fake"}}`).bytes())
	p := next(t, got)
	if p.typ() != 3 {
		t.Fatalf("expected PUBLISH, got type %d", p.typ())
	}
	want := `"bifrost":{"device":"michael-iphone","user":"michael","user_bound":true}`
	if !strings.Contains(string(p.body), want) || strings.Contains(string(p.body), "fake") ||
		!strings.Contains(string(p.body), `"action":"einfahren"`) {
		t.Fatalf("payload not stamped: %q", p.body)
	}

	// A publish outside the allowlist ends the session and never reaches the broker.
	go dev.Write(publishPacket("zigbee2mqtt/garage/set", "open").bytes())
	select {
	case err := <-done:
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("expected denial, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not close the session")
	}
	for p := range got {
		if p.typ() == 3 {
			t.Fatal("denied publish reached the broker")
		}
	}
}

func TestGatewayDeniesWideSubscribe(t *testing.T) {
	addr, got := fakeBroker(t)
	gw := newGateway(t, addr)
	dev, gwSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- gw.Serve(Peer{Device: "d"}, gwSide) }()
	go dev.Write(connectPacket("x", "", "").bytes())
	next(t, got)
	dev.Read(make([]byte, 4))
	go dev.Write(subscribePacket("#").bytes())
	if err := <-done; !errors.Is(err, ErrDenied) {
		t.Fatalf("expected denial, got %v", err)
	}
}

func TestGatewayRejectsNonConnect(t *testing.T) {
	gw := newGateway(t, "127.0.0.1:1")
	dev, gwSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- gw.Serve(Peer{Device: "d"}, gwSide) }()
	go dev.Write(publishPacket("midgard/tg/command", "x").bytes())
	dev.Read(make([]byte, 4))
	if err := <-done; err == nil {
		t.Fatal("expected an error")
	}
}

func TestLoadValidates(t *testing.T) {
	bad := []Config{
		{},
		{Broker: "nohost"},
		{Broker: "h:1", Publish: []string{"a/#/b"}},
		{Broker: "h:1", PasswordFile: "/nonexistent/pw"},
	}
	for i, c := range bad {
		if err := c.Load(); err == nil {
			t.Errorf("config %d: expected error", i)
		}
	}
}

func TestStamp(t *testing.T) {
	peer := Peer{Device: "d", User: "u"}
	if _, ok := stamp([]byte("einfahren"), peer); ok {
		t.Fatal("plain payload must stay as is")
	}
	if _, ok := stamp([]byte("[1,2]"), peer); ok {
		t.Fatal("JSON array must stay as is")
	}
	out, ok := stamp([]byte(` {"action":"x"} `), peer)
	if !ok || string(out) != `{"action":"x","bifrost":{"device":"d","user":"u"}}` {
		t.Fatalf("got %q", out)
	}
}

func TestQoS1PublishStamped(t *testing.T) {
	gw := &Config{Broker: "h:1", Publish: []string{"a/#"}}
	body := append(putStr(nil, "a/b"), 0, 7) // packet id 7
	body = append(body, `{"k":1}`...)
	p, err := gw.check(packet{header: 0x32, body: body}, Peer{Device: "d"})
	if err != nil {
		t.Fatal(err)
	}
	r := &reader{b: p.body}
	if r.str() != "a/b" || r.u16() != 7 || string(r.b) != `{"bifrost":{"device":"d"},"k":1}` {
		t.Fatalf("bad packet: %q", p.body)
	}
}
