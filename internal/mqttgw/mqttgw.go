// Package mqttgw is an MQTT 3.1.1 gateway for paired devices.
//
// The device speaks MQTT through its bifrost tunnel without any broker credentials.
// The agent opens its own connection to the broker, replaces the credentials in the
// CONNECT packet with the gateway's, and checks every PUBLISH and SUBSCRIBE of the
// device against the gateway's topic allowlist. A device's access therefore ends
// with its pairing: revoking it in bifrost also cuts off MQTT.
package mqttgw

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config is one gateway as configured in asgard.json ("mqtt_gateways").
type Config struct {
	Broker   string `json:"broker"`   // host:port of the MQTT broker
	Username string `json:"username"` // broker user of the gateway
	// PasswordFile holds the broker password. Environment variables are expanded, so
	// "${CREDENTIALS_DIRECTORY}/mqtt-midgard" works with systemd LoadCredential=.
	PasswordFile string `json:"password_file"`
	// Publish and Subscribe are MQTT topic filters ("+" and "#" allowed). A device may
	// publish to topics matched by Publish and subscribe to filters within Subscribe.
	Publish   []string `json:"publish"`
	Subscribe []string `json:"subscribe"`
	// Identity adds the sender to every JSON-object payload the device publishes, as
	// "bifrost": {"device": ..., "user": ..., "user_bound": ...}. These values come from
	// the pairing, not from the app, so the receiver (e.g. Home Assistant) can trust
	// them. Any "bifrost" field sent by the device is replaced. Default: on.
	Identity *bool `json:"identity,omitempty"`

	password string
}

// Peer is the paired device behind a gateway session.
type Peer struct {
	Device    string `json:"device"`               // name from `bifrost pair -name`
	User      string `json:"user,omitempty"`       // user from the pairing
	UserBound bool   `json:"user_bound,omitempty"` // true if the admin bound the user (`-user`)
}

func (c *Config) identity() bool { return c.Identity == nil || *c.Identity }

// Load validates the config and reads the password file.
func (c *Config) Load() error {
	if c.Broker == "" {
		return errors.New("broker missing")
	}
	if _, _, err := net.SplitHostPort(c.Broker); err != nil {
		return fmt.Errorf("broker: %w", err)
	}
	if c.PasswordFile != "" {
		b, err := os.ReadFile(os.ExpandEnv(c.PasswordFile))
		if err != nil {
			return fmt.Errorf("password_file: %w", err)
		}
		c.password = strings.TrimRight(string(b), "\r\n")
	}
	for _, f := range append(append([]string{}, c.Publish...), c.Subscribe...) {
		if !validFilter(f) {
			return fmt.Errorf("invalid topic filter %q", f)
		}
	}
	return nil
}

const maxPacket = 256 << 10

var ErrDenied = errors.New("denied by gateway")

type packet struct {
	header byte
	body   []byte
}

func (p packet) typ() byte { return p.header >> 4 }

func (p packet) bytes() []byte {
	out := []byte{p.header}
	n := len(p.body)
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return append(out, p.body...)
}

func readPacket(r *bufio.Reader) (packet, error) {
	h, err := r.ReadByte()
	if err != nil {
		return packet{}, err
	}
	n, mul := 0, 1
	for i := 0; ; i++ {
		if i == 4 {
			return packet{}, errors.New("malformed remaining length")
		}
		b, err := r.ReadByte()
		if err != nil {
			return packet{}, err
		}
		n += int(b&0x7f) * mul
		mul *= 128
		if b&0x80 == 0 {
			break
		}
	}
	if n > maxPacket {
		return packet{}, fmt.Errorf("packet too large (%d bytes)", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return packet{}, err
	}
	return packet{header: h, body: body}, nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) u8() byte {
	if r.err != nil || len(r.b) < 1 {
		r.err = errors.New("short packet")
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) u16() uint16 {
	if r.err != nil || len(r.b) < 2 {
		r.err = errors.New("short packet")
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *reader) str() string {
	n := int(r.u16())
	if r.err != nil || len(r.b) < n {
		r.err = errors.New("short packet")
		return ""
	}
	v := string(r.b[:n])
	r.b = r.b[n:]
	return v
}

func putStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

var clientIDChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// rewriteConnect builds the CONNECT the broker sees: the gateway's credentials,
// the device name as client ID prefix, no will message unless it is allowed.
func (c *Config) rewriteConnect(p packet, device string) (packet, error) {
	if p.typ() != 1 {
		return packet{}, errors.New("first packet is not CONNECT")
	}
	r := &reader{b: p.body}
	proto := r.str()
	level := r.u8()
	flags := r.u8()
	keepAlive := r.u16()
	clientID := r.str()
	var willTopic, willMsg string
	if flags&0x04 != 0 {
		willTopic = r.str()
		willMsg = r.str()
	}
	if r.err != nil {
		return packet{}, r.err
	}
	if proto != "MQTT" || level != 4 {
		return packet{}, fmt.Errorf("only MQTT 3.1.1 is supported (got %q level %d)", proto, level)
	}
	willOK := flags&0x04 != 0 && matchAny(c.Publish, willTopic)

	id := clientIDChars.ReplaceAllString(device, "_") + "-" + clientIDChars.ReplaceAllString(clientID, "_")
	if len(id) > 64 {
		id = id[:64]
	}
	out := putStr(nil, "MQTT")
	newFlags := flags & 0x02 // clean session
	if willOK {
		newFlags |= flags & 0x3c // will flag, QoS, retain
	}
	if c.Username != "" {
		newFlags |= 0x80
		if c.password != "" {
			newFlags |= 0x40
		}
	}
	out = append(out, 4, newFlags)
	out = binary.BigEndian.AppendUint16(out, keepAlive)
	out = putStr(out, id)
	if willOK {
		out = putStr(out, willTopic)
		out = putStr(out, willMsg)
	}
	if c.Username != "" {
		out = putStr(out, c.Username)
		if c.password != "" {
			out = putStr(out, c.password)
		}
	}
	return packet{header: 0x10, body: out}, nil
}

// check enforces the allowlist on device-to-broker packets and stamps the sender
// identity into published JSON objects.
func (c *Config) check(p packet, peer Peer) (packet, error) {
	switch p.typ() {
	case 1:
		return p, errors.New("second CONNECT")
	case 3: // PUBLISH
		r := &reader{b: p.body}
		topic := r.str()
		if r.err != nil {
			return p, r.err
		}
		if !matchAny(c.Publish, topic) {
			return p, fmt.Errorf("%w: publish to %q", ErrDenied, topic)
		}
		head := len(p.body) - len(r.b) // topic
		if (p.header>>1)&3 > 0 {
			head += 2 // packet identifier
		}
		if head > len(p.body) {
			return p, errors.New("short packet")
		}
		payload := p.body[head:]
		stamped := false
		if c.identity() {
			if out, ok := stamp(payload, peer); ok {
				p = packet{header: p.header, body: append(append([]byte{}, p.body[:head]...), out...)}
				stamped = true
			}
		}
		log.Printf("mqtt %s (user %q): publish %s, %d bytes%s", peer.Device, peer.User, topic, len(payload),
			map[bool]string{true: ", identity added", false: ""}[stamped])
	case 8: // SUBSCRIBE
		r := &reader{b: p.body}
		r.u16()
		for len(r.b) > 0 && r.err == nil {
			f := r.str()
			r.u8()
			if r.err == nil && !coveredByAny(c.Subscribe, f) {
				return p, fmt.Errorf("%w: subscribe to %q", ErrDenied, f)
			}
		}
		return p, r.err
	}
	return p, nil
}

// stamp sets payload["bifrost"] = peer if the payload is a JSON object.
func stamp(payload []byte, peer Peer) ([]byte, bool) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, false
	}
	id, err := json.Marshal(peer)
	if err != nil {
		return nil, false
	}
	obj["bifrost"] = id
	out, err := json.Marshal(obj)
	if err != nil || len(out) > maxPacket-1024 {
		return nil, false
	}
	return out, true
}

// Serve runs one device connection until either side closes it.
func (c *Config) Serve(peer Peer, client net.Conn) error {
	device := peer.Device
	defer client.Close()
	cr := bufio.NewReader(client)
	client.SetReadDeadline(time.Now().Add(15 * time.Second))
	first, err := readPacket(cr)
	if err != nil {
		return fmt.Errorf("reading CONNECT: %w", err)
	}
	client.SetReadDeadline(time.Time{})
	conn, err := c.rewriteConnect(first, device)
	if err != nil {
		client.Write([]byte{0x20, 0x02, 0x00, 0x01}) // CONNACK: unacceptable protocol version
		return err
	}
	broker, err := net.DialTimeout("tcp", c.Broker, 5*time.Second)
	if err != nil {
		client.Write([]byte{0x20, 0x02, 0x00, 0x03}) // CONNACK: server unavailable
		return fmt.Errorf("broker: %w", err)
	}
	defer broker.Close()
	if _, err := broker.Write(conn.bytes()); err != nil {
		return err
	}

	var once sync.Once
	var result error
	stop := func(err error) {
		once.Do(func() {
			result = err
			client.Close()
			broker.Close()
		})
	}
	go func() { // broker -> device: unchanged
		_, err := io.Copy(client, broker)
		stop(err)
	}()
	for { // device -> broker: checked packet by packet
		p, err := readPacket(cr)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				err = nil
			}
			stop(err)
			break
		}
		p, err = c.check(p, peer)
		if err != nil {
			log.Printf("mqtt %s (user %q): %v", peer.Device, peer.User, err)
			stop(err)
			break
		}
		if _, err := broker.Write(p.bytes()); err != nil {
			stop(err)
			break
		}
	}
	return result
}

// MARK: topic filters

func validFilter(f string) bool {
	if f == "" {
		return false
	}
	levels := strings.Split(f, "/")
	for i, l := range levels {
		if strings.Contains(l, "#") && (l != "#" || i != len(levels)-1) {
			return false
		}
		if strings.Contains(l, "+") && l != "+" {
			return false
		}
	}
	return true
}

// match reports whether topic (no wildcards) matches filter.
func match(filter, topic string) bool {
	if topic == "" || strings.ContainsAny(topic, "+#") || strings.HasPrefix(topic, "$") {
		return false
	}
	f, t := strings.Split(filter, "/"), strings.Split(topic, "/")
	for i, l := range f {
		if l == "#" {
			return true
		}
		if i >= len(t) || (l != "+" && l != t[i]) {
			return false
		}
	}
	return len(f) == len(t)
}

func matchAny(filters []string, topic string) bool {
	for _, f := range filters {
		if match(f, topic) {
			return true
		}
	}
	return false
}

// covered reports whether every topic matched by sub is also matched by allowed.
func covered(allowed, sub string) bool {
	if !validFilter(sub) || strings.HasPrefix(sub, "$") {
		return false
	}
	a, s := strings.Split(allowed, "/"), strings.Split(sub, "/")
	for i, l := range a {
		if l == "#" {
			return true
		}
		if i >= len(s) {
			return false
		}
		switch {
		case s[i] == "#":
			return false
		case l == "+":
			continue
		case s[i] == "+" || s[i] != l:
			return false
		}
	}
	return len(a) == len(s)
}

func coveredByAny(allowed []string, sub string) bool {
	for _, a := range allowed {
		if covered(a, sub) {
			return true
		}
	}
	return false
}
