package e2e

import (
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MichaelBMF/bifrost/internal/client"
	"github.com/MichaelBMF/bifrost/internal/mqttgw"
)

// brokerLog collects raw packets the fake broker received, for assertions.
var brokerLog = make(chan []byte, 64)

// fakeMQTTBroker acknowledges CONNECT and forwards every packet body to brokerLog.
func fakeMQTTBroker(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					h := make([]byte, 2)
					if _, err := io.ReadFull(c, h); err != nil {
						return
					}
					body := make([]byte, h[1]) // test packets are < 128 bytes
					if _, err := io.ReadFull(c, body); err != nil {
						return
					}
					if h[0]>>4 == 1 {
						c.Write([]byte{0x20, 2, 0, 0})
					}
					brokerLog <- append([]byte{h[0]}, body...)
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func gatewayConfig(t *testing.T) *mqttgw.Config {
	pw := filepath.Join(t.TempDir(), "mqtt-pw")
	os.WriteFile(pw, []byte("broker-secret\n"), 0o600)
	gw := &mqttgw.Config{Broker: fakeMQTTBroker(t), Username: "midgard", PasswordFile: pw,
		Publish: []string{"midgard/+/command"}, Subscribe: []string{"midgard/#"}}
	if err := gw.Load(); err != nil {
		t.Fatal(err)
	}
	return gw
}

func mqttStr(s string) []byte { return append([]byte{0, byte(len(s))}, s...) }

func TestMQTTGatewayEndToEnd(t *testing.T) {
	e := setup(t)
	phone, _ := client.Open(filepath.Join(e.dir, "gw-phone"))
	if _, err := phone.Pair(e.pairCode(t, "gw-phone", "mqttgw"), client.PairOptions{}); err != nil {
		t.Fatalf("pairing: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	for len(brokerLog) > 0 {
		<-brokerLog
	}

	c, err := phone.DialService("mqttgw")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// CONNECT without credentials, client ID "app".
	body := append(mqttStr("MQTT"), 4, 0x02, 0, 30)
	body = append(body, mqttStr("app")...)
	c.Write(append([]byte{0x10, byte(len(body))}, body...))
	ack := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(c, ack); err != nil || ack[0] != 0x20 || ack[3] != 0 {
		t.Fatalf("CONNACK: %x %v", ack, err)
	}
	conn := <-brokerLog
	if !bytes.Contains(conn, []byte("gw-phone-app")) || !bytes.Contains(conn, []byte("midgard")) ||
		!bytes.Contains(conn, []byte("broker-secret")) {
		t.Fatalf("broker did not get the gateway credentials: %q", conn)
	}

	pub := append(mqttStr("midgard/tg/command"), "einfahren"...)
	c.Write(append([]byte{0x30, byte(len(pub))}, pub...))
	select {
	case p := <-brokerLog:
		if p[0]>>4 != 3 || !bytes.Contains(p, []byte("einfahren")) {
			t.Fatalf("unexpected packet at broker: %q", p)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("publish did not reach the broker")
	}

	// Outside the allowlist: the gateway drops the session.
	bad := append(mqttStr("zigbee2mqtt/tor/set"), "open"...)
	c.Write(append([]byte{0x30, byte(len(bad))}, bad...))
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("session should be closed after a denied publish")
	}
	select {
	case p := <-brokerLog:
		t.Fatalf("denied publish reached the broker: %q", p)
	case <-time.After(300 * time.Millisecond):
	}
}
