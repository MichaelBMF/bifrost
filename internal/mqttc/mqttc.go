// Package mqttc is a small MQTT 3.1.1 client that runs over an existing connection,
// typically a bifrost tunnel to an MQTT gateway. It lets the app speak MQTT inside its
// own process, so no local TCP port is needed that other processes could use.
//
// Supported: clean sessions, QoS 0 and 1 (publish and subscribe), retained messages,
// keep-alive. QoS 2, wills and persistent sessions are not supported.
package mqttc

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Message is one PUBLISH received from the broker.
type Message struct {
	Topic    string
	Payload  []byte
	Retained bool
}

// Options configure a session.
type Options struct {
	ClientID  string        // optional; the gateway prefixes it with the device name
	KeepAlive time.Duration // default 30 s; 0 or less uses the default
	// AckTimeout bounds the wait for CONNACK, PUBACK, SUBACK and UNSUBACK. Default 15 s.
	AckTimeout time.Duration
	// OnMessage is called for every received message, one at a time and in order, on a
	// goroutine of the session. It may call Publish and Subscribe.
	OnMessage func(Message)
	// OnClose is called once when the session ends; err is nil after Close.
	OnClose func(err error)
}

// ErrClosed is returned by calls on a session that has ended.
var ErrClosed = errors.New("mqtt session closed")

const maxPacket = 256 << 10

// Session is a connected MQTT session. All methods are safe for concurrent use.
type Session struct {
	conn net.Conn
	opts Options

	wmu sync.Mutex // serializes writes

	mu      sync.Mutex
	nextID  uint16
	pending map[uint16]chan []byte // packet id -> ack body
	err     error                  // set when the session ended
	done    chan struct{}

	qmu   sync.Mutex
	qcond *sync.Cond
	queue []Message
}

// Connect sends CONNECT over conn, waits for CONNACK and starts the session. On
// error conn is closed.
func Connect(conn net.Conn, opts Options) (*Session, error) {
	if opts.KeepAlive <= 0 {
		opts.KeepAlive = 30 * time.Second
	}
	if opts.KeepAlive > 65535*time.Second {
		opts.KeepAlive = 65535 * time.Second
	}
	if opts.AckTimeout <= 0 {
		opts.AckTimeout = 15 * time.Second
	}
	s := &Session{conn: conn, opts: opts, pending: map[uint16]chan []byte{}, done: make(chan struct{})}
	s.qcond = sync.NewCond(&s.qmu)

	body := putStr(nil, "MQTT")
	body = append(body, 4, 0x02) // level 3.1.1, clean session
	body = binary.BigEndian.AppendUint16(body, uint16(opts.KeepAlive/time.Second))
	body = putStr(body, opts.ClientID)
	if _, err := conn.Write(encode(0x10, body)); err != nil {
		conn.Close()
		return nil, err
	}
	r := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(opts.AckTimeout))
	h, ack, err := readPacket(r)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading CONNACK: %w", err)
	}
	if h>>4 != 2 || len(ack) != 2 {
		conn.Close()
		return nil, errors.New("expected CONNACK")
	}
	if ack[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("connection refused by broker (code %d)", ack[1])
	}
	go s.readLoop(r)
	go s.pingLoop()
	go s.dispatch()
	return s, nil
}

// Publish sends a message. With qos 1 it waits for the broker's PUBACK.
func (s *Session) Publish(topic string, payload []byte, qos int, retain bool) error {
	if topic == "" || len(topic) > 65535 || strings.ContainsAny(topic, "+#") {
		return fmt.Errorf("invalid topic %q", topic)
	}
	if qos != 0 && qos != 1 {
		return fmt.Errorf("unsupported QoS %d (0 or 1)", qos)
	}
	h := byte(0x30) | byte(qos<<1)
	if retain {
		h |= 0x01
	}
	if qos == 0 {
		body := append(putStr(nil, topic), payload...)
		return s.write(encode(h, body))
	}
	id, ch, err := s.newID()
	if err != nil {
		return err
	}
	body := putStr(nil, topic)
	body = binary.BigEndian.AppendUint16(body, id)
	body = append(body, payload...)
	_, err = s.request(id, ch, encode(h, body))
	return err
}

// Subscribe subscribes to filter with the given maximum QoS (0 or 1) and waits for
// SUBACK. A gateway closes the session for filters outside its allowlist.
func (s *Session) Subscribe(filter string, qos int) error {
	if !validFilter(filter) {
		return fmt.Errorf("invalid topic filter %q", filter)
	}
	if qos != 0 && qos != 1 {
		return fmt.Errorf("unsupported QoS %d (0 or 1)", qos)
	}
	id, ch, err := s.newID()
	if err != nil {
		return err
	}
	body := binary.BigEndian.AppendUint16(nil, id)
	body = putStr(body, filter)
	body = append(body, byte(qos))
	ack, err := s.request(id, ch, encode(0x82, body))
	if err != nil {
		return err
	}
	if len(ack) != 1 || ack[0] == 0x80 {
		return fmt.Errorf("subscription to %q refused", filter)
	}
	return nil
}

// Unsubscribe removes a subscription and waits for UNSUBACK.
func (s *Session) Unsubscribe(filter string) error {
	if !validFilter(filter) {
		return fmt.Errorf("invalid topic filter %q", filter)
	}
	id, ch, err := s.newID()
	if err != nil {
		return err
	}
	body := binary.BigEndian.AppendUint16(nil, id)
	body = putStr(body, filter)
	_, err = s.request(id, ch, encode(0xa2, body))
	return err
}

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns why the session ended: nil while it runs and after Close.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if errors.Is(s.err, ErrClosed) {
		return nil
	}
	return s.err
}

// Close sends DISCONNECT and closes the connection.
func (s *Session) Close() {
	select {
	case <-s.done:
		return
	default:
	}
	s.wmu.Lock()
	s.conn.SetWriteDeadline(time.Now().Add(time.Second))
	s.conn.Write([]byte{0xe0, 0})
	s.wmu.Unlock()
	s.end(ErrClosed)
}

func (s *Session) end(err error) {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return
	}
	s.err = err
	for id, ch := range s.pending {
		close(ch)
		delete(s.pending, id)
	}
	close(s.done)
	s.mu.Unlock()
	s.conn.Close()
	s.qmu.Lock()
	s.qcond.Broadcast()
	s.qmu.Unlock()
}

func (s *Session) write(b []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	select {
	case <-s.done:
		return ErrClosed
	default:
	}
	s.conn.SetWriteDeadline(time.Now().Add(s.opts.AckTimeout))
	if _, err := s.conn.Write(b); err != nil {
		s.end(err)
		return err
	}
	return nil
}

func (s *Session) newID() (uint16, chan []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, nil, ErrClosed
	}
	for range 65536 {
		s.nextID++
		if s.nextID == 0 {
			s.nextID = 1
		}
		if _, used := s.pending[s.nextID]; !used {
			ch := make(chan []byte, 1)
			s.pending[s.nextID] = ch
			return s.nextID, ch, nil
		}
	}
	return 0, nil, errors.New("too many requests in flight")
}

func (s *Session) request(id uint16, ch chan []byte, pkt []byte) ([]byte, error) {
	if err := s.write(pkt); err != nil {
		s.drop(id)
		return nil, err
	}
	t := time.NewTimer(s.opts.AckTimeout)
	defer t.Stop()
	select {
	case ack, ok := <-ch:
		if !ok {
			return nil, s.closedErr()
		}
		return ack, nil
	case <-t.C:
		s.drop(id)
		return nil, errors.New("timeout waiting for the broker")
	}
}

func (s *Session) closedErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil || errors.Is(s.err, ErrClosed) {
		return ErrClosed
	}
	return fmt.Errorf("%w: %v", ErrClosed, s.err)
}

func (s *Session) drop(id uint16) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

func (s *Session) ack(id uint16, body []byte) {
	s.mu.Lock()
	ch := s.pending[id]
	delete(s.pending, id)
	s.mu.Unlock()
	if ch != nil {
		ch <- body
	}
}

func (s *Session) readLoop(r *bufio.Reader) {
	for {
		// The broker answers every PINGREQ, so silence for 1.5 keep-alive intervals
		// means the connection is dead.
		s.conn.SetReadDeadline(time.Now().Add(s.opts.KeepAlive * 3 / 2))
		h, body, err := readPacket(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("connection closed by the gateway")
			}
			s.end(err)
			return
		}
		switch h >> 4 {
		case 3: // PUBLISH
			if err := s.onPublish(h, body); err != nil {
				s.end(err)
				return
			}
		case 4, 11: // PUBACK, UNSUBACK
			if len(body) >= 2 {
				s.ack(binary.BigEndian.Uint16(body), nil)
			}
		case 9: // SUBACK
			if len(body) >= 2 {
				s.ack(binary.BigEndian.Uint16(body), body[2:])
			}
		case 13: // PINGRESP
		default:
			s.end(fmt.Errorf("unexpected packet type %d", h>>4))
			return
		}
	}
}

func (s *Session) onPublish(h byte, body []byte) error {
	qos := (h >> 1) & 3
	if qos > 1 {
		return fmt.Errorf("QoS %d is not supported", qos)
	}
	if len(body) < 2 {
		return errors.New("short PUBLISH")
	}
	n := int(binary.BigEndian.Uint16(body))
	if len(body) < 2+n {
		return errors.New("short PUBLISH")
	}
	topic := string(body[2 : 2+n])
	rest := body[2+n:]
	if qos == 1 {
		if len(rest) < 2 {
			return errors.New("short PUBLISH")
		}
		id := rest[:2]
		rest = rest[2:]
		if err := s.write([]byte{0x40, 2, id[0], id[1]}); err != nil {
			return err
		}
	}
	s.qmu.Lock()
	s.queue = append(s.queue, Message{Topic: topic, Payload: rest, Retained: h&1 != 0})
	s.qcond.Signal()
	s.qmu.Unlock()
	return nil
}

// dispatch delivers queued messages to OnMessage, then calls OnClose.
func (s *Session) dispatch() {
	for {
		s.qmu.Lock()
		for len(s.queue) == 0 {
			select {
			case <-s.done:
				s.qmu.Unlock()
				if s.opts.OnClose != nil {
					s.opts.OnClose(s.Err())
				}
				return
			default:
			}
			s.qcond.Wait()
		}
		m := s.queue[0]
		s.queue = s.queue[1:]
		s.qmu.Unlock()
		if s.opts.OnMessage != nil {
			s.opts.OnMessage(m)
		}
	}
}

func (s *Session) pingLoop() {
	t := time.NewTicker(s.opts.KeepAlive)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.write([]byte{0xc0, 0})
		}
	}
}

// MARK: encoding

func encode(header byte, body []byte) []byte {
	out := []byte{header}
	n := len(body)
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
	return append(out, body...)
}

func readPacket(r *bufio.Reader) (byte, []byte, error) {
	h, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n, mul := 0, 1
	for i := 0; ; i++ {
		if i == 4 {
			return 0, nil, errors.New("malformed remaining length")
		}
		b, err := r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		n += int(b&0x7f) * mul
		mul *= 128
		if b&0x80 == 0 {
			break
		}
	}
	if n > maxPacket {
		return 0, nil, fmt.Errorf("packet too large (%d bytes)", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return h, body, nil
}

func putStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func validFilter(f string) bool {
	if f == "" || len(f) > 65535 {
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
