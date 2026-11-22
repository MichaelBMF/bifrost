package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
