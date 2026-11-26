package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/MichaelBMF/bifrost/internal/services/all"
)

func writeConfig(t *testing.T, body string) string {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "pw"), []byte("x\n"), 0o600)
	p := filepath.Join(dir, "asgard.json")
	os.WriteFile(p, []byte(strings.ReplaceAll(body, "PW", filepath.Join(dir, "pw"))), 0o600)
	return p
}

func TestLoadConfigMQTTGateway(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, `{"services":{"ha":"127.0.0.1:8123"},
		"mqtt_gateways":{"mqtt":{"broker":"127.0.0.1:1883","username":"midgard","password_file":"PW",
		"publish":["midgard/+/command"],"subscribe":["midgard/#"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.hasService("mqtt") || !c.hasService("ha") || c.hasService("other") {
		t.Fatal("hasService wrong")
	}
	if _, err := LoadConfig(writeConfig(t, `{"services":{"mqtt":"127.0.0.1:1883"},
		"mqtt_gateways":{"mqtt":{"broker":"127.0.0.1:1883"}}}`)); err == nil {
		t.Fatal("duplicate service name should be rejected")
	}
	if _, err := LoadConfig(writeConfig(t, `{"mqtt_gateways":{"mqtt":{"broker":"127.0.0.1:1883","password_file":"/nope"}}}`)); err == nil {
		t.Fatal("missing password file should be rejected")
	}
}

func TestLoadConfigTypedServices(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, `{"services":{
		"ha":{"type":"tcp","target":"127.0.0.1:8123"},
		"midgard":{"type":"mqtt","broker":"127.0.0.1:1883","username":"midgard","password_file":"PW",
		  "publish":["midgard/+/command"],"subscribe":["midgard/#"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.hasService("ha") || !c.hasService("midgard") {
		t.Fatal("typed services missing")
	}
	for _, bad := range []string{
		`{"services":{"x":{"target":"127.0.0.1:1"}}}`,
		`{"services":{"x":{"type":"nope"}}}`,
		`{"services":{"x":{"type":"tcp"}}}`,
		`{"services":{"x":"no-port"}}`,
	} {
		if _, err := LoadConfig(writeConfig(t, bad)); err == nil {
			t.Errorf("%s: should be rejected", bad)
		}
	}
}

// The transport core must not know any service: services register themselves.
func TestCoreImportsNoService(t *testing.T) {
	for _, pkg := range []string{".", "../client", "../relay", "../wire", "../../mobile"} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Skipf("go list not available: %v %s", err, out)
		}
		for _, bad := range []string{"internal/services", "internal/mqttgw", "internal/mqttc"} {
			if strings.Contains(string(out), bad) {
				t.Errorf("%s depends on %s", pkg, bad)
			}
		}
	}
}
