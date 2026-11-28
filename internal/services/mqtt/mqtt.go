// Package mqtt is the MQTT service: the agent talks to the MQTT broker on behalf of a
// paired device. The device needs no broker credentials and no MQTT library.
//
// Config in asgard.json (the older "mqtt_gateways" section is still read as the same):
//
//	"midgard": {"type": "mqtt", "broker": "127.0.0.1:1883", "username": "midgard",
//	            "password_file": "${CREDENTIALS_DIRECTORY}/bifrost-mqtt-midgard",
//	            "publish": ["midgard/+/command"], "subscribe": ["midgard/#"]}
//
// The service only accepts message mode (wire.ModeMsg). The stream mode, in which
// the device spoke MQTT 3.1.1 itself, was removed in bifrost v0.5.0.
//
// Each message is one JSON object. Device to agent:
//
//	{"op":"sub",   "id":1, "filter":"midgard/#", "qos":1}
//	{"op":"unsub", "id":2, "filter":"midgard/#"}
//	{"op":"pub",   "id":3, "topic":"midgard/tg/command", "payload":{"action":"open"}, "qos":1, "retain":false}
//	{"op":"ping",  "id":4}
//
// A pub carries exactly one of "payload" (any JSON value, sent as its JSON text),
// "payload_text" (a string, sent as is) or "payload_b64" (bytes, base64). "id" is
// optional; with an id the agent answers every op with {"op":"ack","id":n} or
// {"op":"error","id":n,"error":"..."}. A denied op does not end the channel.
//
// Agent to device:
//
//	{"op":"msg", "topic":"midgard/tg/state", "payload":{"state":"open"}, "retain":true}
//
// with "payload" if the MQTT payload is valid JSON, else "payload_text" if it is
// UTF-8, else "payload_b64". If the broker connection ends, the agent sends
// {"op":"error","error":"..."} and closes the channel.
//
// Publish and subscribe are checked against the allowlists, and JSON objects that
// the device publishes get "bifrost": {"device","user","user_bound"} from the pairing.
package mqtt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/MichaelBMF/bifrost/internal/mqttc"
	"github.com/MichaelBMF/bifrost/internal/mqttgw"
	"github.com/MichaelBMF/bifrost/internal/service"
	"github.com/MichaelBMF/bifrost/internal/wire"
)

func init() {
	service.Register("mqtt", func(raw json.RawMessage) (service.Service, error) {
		var c mqttgw.Config
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		return New(&c)
	})
}

// New validates c, reads its password file and returns the service.
func New(c *mqttgw.Config) (service.Service, error) {
	if err := c.Load(); err != nil {
		return nil, err
	}
	return &svc{cfg: c}, nil
}

type svc struct{ cfg *mqttgw.Config }

func (s *svc) Modes() []service.Mode { return []service.Mode{wire.ModeMsg} }
func (s *svc) String() string        { return "mqtt " + s.cfg.Broker }

func (s *svc) Serve(p service.Peer, mode service.Mode, ch service.Channel, accept func() error) error {
	gp := mqttgw.Peer{Device: p.Device, User: p.User, UserBound: p.UserBound}
	return s.serveMessages(gp, ch, accept)
}

// Request is a message from the device.
type Request struct {
	Op          string          `json:"op"`
	ID          int64           `json:"id,omitempty"`
	Topic       string          `json:"topic,omitempty"`
	Filter      string          `json:"filter,omitempty"`
	QoS         int             `json:"qos,omitempty"`
	Retain      bool            `json:"retain,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	PayloadText *string         `json:"payload_text,omitempty"`
	PayloadB64  *string         `json:"payload_b64,omitempty"`
}

// Event is a message to the device.
type Event struct {
	Op          string          `json:"op"`
	ID          int64           `json:"id,omitempty"`
	Error       string          `json:"error,omitempty"`
	Topic       string          `json:"topic,omitempty"`
	Retain      bool            `json:"retain,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	PayloadText *string         `json:"payload_text,omitempty"`
	PayloadB64  *string         `json:"payload_b64,omitempty"`
}

var clientIDChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func clientID(device string) string {
	var r [3]byte
	rand.Read(r[:])
	id := clientIDChars.ReplaceAllString(device, "_")
	if len(id) > 40 {
		id = id[:40]
	}
	return id + "-" + hex.EncodeToString(r[:])
}

func send(ch service.Channel, e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return ch.WriteMsg(b)
}

// encodePayload fills the payload field that fits b.
func encodePayload(e *Event, b []byte) {
	switch {
	case len(b) > 0 && json.Valid(b):
		e.Payload = json.RawMessage(b)
	case utf8.Valid(b):
		s := string(b)
		e.PayloadText = &s
	default:
		s := base64.StdEncoding.EncodeToString(b)
		e.PayloadB64 = &s
	}
}

// decodePayload returns the MQTT payload of a pub request.
func decodePayload(r *Request) ([]byte, error) {
	n := 0
	var out []byte
	if len(r.Payload) > 0 {
		n++
		out = r.Payload
	}
	if r.PayloadText != nil {
		n++
		out = []byte(*r.PayloadText)
	}
	if r.PayloadB64 != nil {
		n++
		b, err := base64.StdEncoding.DecodeString(*r.PayloadB64)
		if err != nil {
			return nil, fmt.Errorf("payload_b64: %w", err)
		}
		out = b
	}
	if n > 1 {
		return nil, errors.New("use only one of payload, payload_text, payload_b64")
	}
	return out, nil
}

func (s *svc) serveMessages(peer mqttgw.Peer, ch service.Channel, accept func() error) error {
	defer ch.Close()
	conn, err := net.DialTimeout("tcp", s.cfg.Broker, 5*time.Second)
	if err != nil {
		return fmt.Errorf("broker: %w", err)
	}
	ended := make(chan error, 1)
	sess, err := mqttc.Connect(conn, mqttc.Options{
		ClientID: clientID(peer.Device),
		Username: s.cfg.Username,
		Password: s.cfg.Password(),
		OnMessage: func(m mqttc.Message) {
			e := Event{Op: "msg", Topic: m.Topic, Retain: m.Retained}
			encodePayload(&e, m.Payload)
			if err := send(ch, e); err != nil {
				log.Printf("mqtt %s: message on %s not delivered: %v", peer.Device, m.Topic, err)
				if !errors.Is(err, net.ErrClosed) {
					_ = send(ch, Event{Op: "error", Error: fmt.Sprintf("message on %s not delivered: %v", m.Topic, err)})
				}
			}
		},
		OnClose: func(err error) { ended <- err },
	})
	if err != nil {
		return fmt.Errorf("broker: %w", err)
	}
	defer sess.Close()
	if err := accept(); err != nil {
		return err
	}
	go func() { // broker gone: tell the device and end the channel
		if err := <-ended; err != nil {
			_ = send(ch, Event{Op: "error", Error: "broker connection lost"})
			log.Printf("mqtt %s: broker connection lost: %v", peer.Device, err)
		}
		ch.Close()
	}()

	for {
		b, err := ch.ReadMsg()
		if err != nil {
			return nil // device closed the channel
		}
		var r Request
		if err := json.Unmarshal(b, &r); err != nil {
			_ = send(ch, Event{Op: "error", Error: "invalid JSON"})
			continue
		}
		if err := s.handle(sess, peer, &r); err != nil {
			if !errors.Is(err, mqttgw.ErrDenied) && errors.Is(err, mqttc.ErrClosed) {
				return nil
			}
			log.Printf("mqtt %s (user %q): %s: %v", peer.Device, peer.User, r.Op, err)
			_ = send(ch, Event{Op: "error", ID: r.ID, Error: err.Error()})
			continue
		}
		if r.ID != 0 {
			_ = send(ch, Event{Op: "ack", ID: r.ID})
		}
	}
}

func (s *svc) handle(sess *mqttc.Session, peer mqttgw.Peer, r *Request) error {
	if r.QoS < 0 || r.QoS > 1 {
		return errors.New("qos must be 0 or 1")
	}
	switch r.Op {
	case "ping":
		return nil
	case "sub":
		if !s.cfg.MaySubscribe(r.Filter) {
			return fmt.Errorf("%w: subscribe to %q", mqttgw.ErrDenied, r.Filter)
		}
		return sess.Subscribe(r.Filter, r.QoS)
	case "unsub":
		return sess.Unsubscribe(r.Filter)
	case "pub":
		if !mqttgw.ValidTopic(r.Topic) || !s.cfg.MayPublish(r.Topic) {
			return fmt.Errorf("%w: publish to %q", mqttgw.ErrDenied, r.Topic)
		}
		payload, err := decodePayload(r)
		if err != nil {
			return err
		}
		stamped := false
		if s.cfg.AddsIdentity() {
			if out, ok := mqttgw.Stamp(payload, peer); ok {
				payload, stamped = out, true
			}
		}
		log.Printf("mqtt %s (user %q): publish %s, %d bytes%s", peer.Device, peer.User, r.Topic, len(payload),
			map[bool]string{true: ", identity added", false: ""}[stamped])
		return sess.Publish(r.Topic, payload, r.QoS, r.Retain)
	}
	return fmt.Errorf("unknown op %q", r.Op)
}
