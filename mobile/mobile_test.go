package mobile

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnpairedClient(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "bifrost")
	c, err := NewClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsPaired() {
		t.Fatal("new client must not be paired")
	}
	var in map[string]any
	if err := json.Unmarshal([]byte(c.Info()), &in); err != nil {
		t.Fatal(err)
	}
	if in["paired"] != false || in["device_fp"] == "" {
		t.Fatalf("unexpected info: %v", in)
	}
	if _, err := c.OpenChannel("mqtt", nopHandler{}); err == nil {
		t.Fatal("OpenChannel must fail before pairing")
	}
	if err := c.Probe("mqtt"); err == nil {
		t.Fatal("Probe must fail before pairing")
	}
	if _, err := c.Pair("garbage", "alice", "phone"); err == nil {
		t.Fatal("Pair must reject an invalid code")
	}
	c.StopAll()

	// The device key is persistent across NewClient calls and replaced by Unpair.
	fp := in["device_fp"]
	c2, err := NewClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(c2.Info()), &in)
	if in["device_fp"] != fp {
		t.Fatal("device key changed between NewClient calls")
	}
	if err := c2.Unpair(); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(c2.Info()), &in)
	if in["device_fp"] == fp {
		t.Fatal("Unpair must replace the device key")
	}
	if _, err := NewClient(""); err == nil {
		t.Fatal("empty stateDir must be rejected")
	}
}

// The binding must stay small and only be a transport: no wireguard-go, no gVisor,
// no agent/relay code, no service (MQTT belongs to the app and the agent's service).
func TestNoServerDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Skipf("go list not available: %v %s", err, out)
	}
	for _, bad := range []string{"wireguard", "gvisor", "internal/agent", "internal/relay", "internal/wg", "qrterminal",
		"internal/services", "internal/mqttgw", "internal/mqttc"} {
		if strings.Contains(string(out), bad) {
			t.Errorf("mobile depends on %s", bad)
		}
	}
}

type nopHandler struct{}

func (nopHandler) OnMessage([]byte) {}
func (nopHandler) OnClose(string)   {}
