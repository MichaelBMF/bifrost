package mqttgw

import "testing"

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

func TestAllowlists(t *testing.T) {
	c := &Config{Broker: "h:1", Publish: []string{"midgard/+/command"}, Subscribe: []string{"midgard/#"}}
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}
	if !c.MayPublish("midgard/tg/command") || c.MayPublish("midgard/tg/state") || c.MayPublish("zigbee2mqtt/x/set") {
		t.Fatal("publish allowlist")
	}
	if !c.MaySubscribe("midgard/tg/#") || c.MaySubscribe("#") || c.MaySubscribe("$SYS/#") {
		t.Fatal("subscribe allowlist")
	}
	if !c.AddsIdentity() {
		t.Fatal("identity must default to on")
	}
}
