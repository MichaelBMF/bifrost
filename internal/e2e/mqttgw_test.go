package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MichaelBMF/bifrost/internal/client"
	"github.com/MichaelBMF/bifrost/internal/mqttc/mqtttest"
	"github.com/MichaelBMF/bifrost/internal/mqttgw"
)

func midgardConfig(t *testing.T, b *mqtttest.Broker) *mqttgw.Config {
	pw := filepath.Join(t.TempDir(), "mqtt-pw")
	os.WriteFile(pw, []byte("broker-secret\n"), 0o600)
	return &mqttgw.Config{Broker: b.Addr(), Username: "midgard", PasswordFile: pw,
		Publish: []string{"midgard/+/command"}, Subscribe: []string{"midgard/#"}}
}

// Since v0.5.0 the mqtt service only has the message mode: a device that opens it as
// a byte stream (and would speak MQTT itself) is refused.
func TestMQTTServiceRefusesStreamMode(t *testing.T) {
	e := setup(t)
	phone, _ := client.Open(filepath.Join(e.dir, "old-phone"))
	if _, err := phone.Pair(e.pairCode(t, "old-phone", "midgard"), client.PairOptions{}); err != nil {
		t.Fatalf("pairing: %v", err)
	}
	var err error
	eventually(t, func() error {
		var c interface{ Close() error }
		c, err = phone.DialService("midgard")
		if err == nil {
			c.Close()
			t.Fatal("stream mode to the mqtt service must be refused")
		}
		if strings.Contains(err.Error(), "mode") {
			return nil
		}
		return err // the relay may not know the device yet
	})
}
