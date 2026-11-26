// Package mqtttest is a minimal in-memory MQTT 3.1.1 broker for tests: CONNECT,
// PUBLISH (QoS 0/1, retained), SUBSCRIBE, UNSUBSCRIBE, PINGREQ, DISCONNECT.
package mqtttest

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// Broker is a running test broker.
type Broker struct {
	ln net.Listener

	mu       sync.Mutex
	subs     map[*conn][]sub
	retained map[string][]byte
	users    []string
}

// Users returns the user name of every CONNECT so far, in order.
func (b *Broker) Users() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.users...)
}

type sub struct {
	filter string
	qos    byte
}

type conn struct {
	c   net.Conn
	wmu sync.Mutex
	id  uint16
}

// Start starts a broker on 127.0.0.1 and stops it when the test ends.
func Start(t testing.TB) *Broker {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &Broker{ln: ln, subs: map[*conn][]sub{}, retained: map[string][]byte{}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(&conn{c: c})
		}
	}()
	return b
}

// Addr is the broker's host:port.
func (b *Broker) Addr() string { return b.ln.Addr().String() }

// Clients returns the number of connected clients.
func (b *Broker) Clients() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// Publish delivers a message to all subscribers, as if another client had sent it.
func (b *Broker) Publish(topic string, payload []byte, retain bool) {
	b.route(topic, payload, retain)
}

// DropAll closes every client connection.
func (b *Broker) DropAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for c := range b.subs {
		c.c.Close()
	}
}

func (b *Broker) serve(c *conn) {
	defer c.c.Close()
	r := bufio.NewReader(c.c)
	h, body, err := read(r)
	if err != nil || h>>4 != 1 {
		return
	}
	b.mu.Lock()
	b.users = append(b.users, connectUser(body))
	b.subs[c] = nil
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.subs, c)
		b.mu.Unlock()
	}()
	c.write(0x20, []byte{0, 0})
	for {
		h, body, err := read(r)
		if err != nil {
			return
		}
		switch h >> 4 {
		case 3:
			qos := (h >> 1) & 3
			n := int(binary.BigEndian.Uint16(body))
			topic := string(body[2 : 2+n])
			rest := body[2+n:]
			if qos == 1 {
				c.write(0x40, rest[:2])
				rest = rest[2:]
			}
			b.route(topic, append([]byte{}, rest...), h&1 != 0)
		case 8:
			id := body[:2]
			rest := body[2:]
			var codes []byte
			var added []sub
			for len(rest) > 0 {
				n := int(binary.BigEndian.Uint16(rest))
				f := string(rest[2 : 2+n])
				q := rest[2+n]
				rest = rest[3+n:]
				added = append(added, sub{f, q})
				codes = append(codes, q)
			}
			b.mu.Lock()
			b.subs[c] = append(b.subs[c], added...)
			var ret []func()
			for topic, payload := range b.retained {
				for _, s := range added {
					if match(s.filter, topic) {
						ret = append(ret, func() { c.publish(topic, payload, s.qos, true) })
						break
					}
				}
			}
			b.mu.Unlock()
			c.write(0x90, append(append([]byte{}, id...), codes...))
			for _, f := range ret {
				f()
			}
		case 10:
			n := int(binary.BigEndian.Uint16(body[2:]))
			f := string(body[4 : 4+n])
			b.mu.Lock()
			var keep []sub
			for _, s := range b.subs[c] {
				if s.filter != f {
					keep = append(keep, s)
				}
			}
			b.subs[c] = keep
			b.mu.Unlock()
			c.write(0xb0, body[:2])
		case 12:
			c.write(0xd0, nil)
		case 14:
			return
		}
	}
}

func (b *Broker) route(topic string, payload []byte, retain bool) {
	b.mu.Lock()
	if retain {
		b.retained[topic] = payload
	}
	type target struct {
		c   *conn
		qos byte
	}
	var ts []target
	for c, subs := range b.subs {
		for _, s := range subs {
			if match(s.filter, topic) {
				ts = append(ts, target{c, s.qos})
				break
			}
		}
	}
	b.mu.Unlock()
	for _, t := range ts {
		t.c.publish(topic, payload, t.qos, false)
	}
}

func (c *conn) publish(topic string, payload []byte, qos byte, retain bool) {
	h := byte(0x30) | qos<<1
	if retain {
		h |= 1
	}
	body := binary.BigEndian.AppendUint16(nil, uint16(len(topic)))
	body = append(body, topic...)
	if qos > 0 {
		c.wmu.Lock()
		c.id++
		id := c.id
		c.wmu.Unlock()
		body = binary.BigEndian.AppendUint16(body, id)
	}
	c.write(h, append(body, payload...))
}

func (c *conn) write(h byte, body []byte) {
	out := []byte{h}
	n := len(body)
	for {
		x := byte(n % 128)
		n /= 128
		if n > 0 {
			x |= 0x80
		}
		out = append(out, x)
		if n == 0 {
			break
		}
	}
	c.wmu.Lock()
	c.c.Write(append(out, body...))
	c.wmu.Unlock()
}

func read(r *bufio.Reader) (byte, []byte, error) {
	h, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n, mul := 0, 1
	for i := 0; i < 4; i++ {
		x, err := r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		n += int(x&0x7f) * mul
		mul *= 128
		if x&0x80 == 0 {
			body := make([]byte, n)
			_, err := io.ReadFull(r, body)
			return h, body, err
		}
	}
	return 0, nil, errors.New("malformed length")
}

func connectUser(body []byte) string {
	str := func(b []byte) (string, []byte) {
		n := int(binary.BigEndian.Uint16(b))
		return string(b[2 : 2+n]), b[2+n:]
	}
	_, rest := str(body) // "MQTT"
	flags := rest[1]
	rest = rest[4:]
	_, rest = str(rest) // client id
	if flags&0x04 != 0 {
		_, rest = str(rest)
		_, rest = str(rest)
	}
	if flags&0x80 == 0 {
		return ""
	}
	u, _ := str(rest)
	return u
}

func match(filter, topic string) bool {
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
