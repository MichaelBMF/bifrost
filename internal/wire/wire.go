// Package wire contains framing, JSON helpers and the Noise layer.
package wire

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const maxFrame = 65535

// WriteFrame writes [2-byte length][data].
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) > maxFrame {
		return errors.New("frame too large")
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	_, err := w.Write(buf)
	return err
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteFrame(w, b)
}

func ReadJSON(r io.Reader, v any) error {
	b, err := ReadFrame(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Hello is the first message after the TLS handshake with the relay.
type Hello struct {
	Role      string `json:"role"` // agent | dial | pair
	AgentID   string `json:"agent_id"`
	TokenHash string `json:"token_hash,omitempty"`
}

// StreamHeader is sent by the relay to the agent before each forwarded stream.
type StreamHeader struct {
	Kind      string `json:"kind"` // dial | pair
	RelayID   string `json:"relay_id"`
	TokenHash string `json:"token_hash,omitempty"`
}

// Control messages travel on the agent <-> relay control channel.
type Control struct {
	Op   string   `json:"op"` // sync_devices | pair_open | pair_close
	Keys []string `json:"keys,omitempty"`
	Hash string   `json:"hash,omitempty"`
	TTL  int      `json:"ttl,omitempty"`
}

type Status struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func TokenHash(token []byte) string {
	s := sha256.Sum256(token)
	return fmt.Sprintf("%x", s)
}

// PinnedTLSConfig verifies the server solely by the hash of its public key.
func PinnedTLSConfig(cert tls.Certificate, pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate (pinning)
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			if fmt.Sprintf("%x", s) != pin {
				return errors.New("relay pin mismatch")
			}
			return nil
		},
	}
}

// ---------- Noise ----------

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

func Prologue(agentID string) []byte { return []byte("bifrost/1 " + agentID) }

// SecureConn is a byte stream over Noise transport messages.
type SecureConn struct {
	net.Conn
	send, recv *noise.CipherState
	rbuf       []byte
	wmu, rmu   sync.Mutex
}

func (s *SecureConn) WriteMsg(b []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	ct, err := s.send.Encrypt(nil, nil, b)
	if err != nil {
		return err
	}
	return WriteFrame(s.Conn, ct)
}

func (s *SecureConn) ReadMsg() ([]byte, error) {
	ct, err := ReadFrame(s.Conn)
	if err != nil {
		return nil, err
	}
	return s.recv.Decrypt(nil, nil, ct)
}

func (s *SecureConn) WriteJSON(v any) error {
	b, _ := json.Marshal(v)
	return s.WriteMsg(b)
}

func (s *SecureConn) ReadJSON(v any) error {
	b, err := s.ReadMsg()
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (s *SecureConn) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	for len(s.rbuf) == 0 {
		b, err := s.ReadMsg()
		if err != nil {
			return 0, err
		}
		s.rbuf = b
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *SecureConn) Write(p []byte) (int, error) {
	const chunk = maxFrame - 16 // room for the Poly1305 tag
	n := 0
	for len(p) > 0 {
		c := p
		if len(c) > chunk {
			c = c[:chunk]
		}
		if err := s.WriteMsg(c); err != nil {
			return n, err
		}
		n += len(c)
		p = p[len(c):]
	}
	return n, nil
}

// ClientHandshake runs the app side as initiator. It knows the agent's static key (from the QR code).
// psk != nil => Noise_IKpsk2 (pairing), otherwise Noise_IK.
func ClientHandshake(c net.Conn, static noise.DHKey, peer, psk, prologue []byte) (*SecureConn, error) {
	cfg := noise.Config{CipherSuite: suite, Pattern: noise.HandshakeIK, Initiator: true,
		StaticKeypair: static, PeerStatic: peer, Prologue: prologue}
	if psk != nil {
		cfg.PresharedKey, cfg.PresharedKeyPlacement = psk, 2
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	defer c.SetDeadline(time.Time{})
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := WriteFrame(c, msg); err != nil {
		return nil, err
	}
	in, err := ReadFrame(c)
	if err != nil {
		return nil, err
	}
	_, cs1, cs2, err := hs.ReadMessage(nil, in)
	if err != nil {
		return nil, fmt.Errorf("noise handshake failed: %w", err)
	}
	return &SecureConn{Conn: c, send: cs1, recv: cs2}, nil
}

// ServerHandshake runs the agent side as responder. After message 1, check is called with
// the initiator's static key; returning an error aborts the handshake.
func ServerHandshake(c net.Conn, static noise.DHKey, usePSK bool, psk, prologue []byte,
	check func(peerStatic []byte) error) (*SecureConn, []byte, error) {
	cfg := noise.Config{CipherSuite: suite, Pattern: noise.HandshakeIK, Initiator: false,
		StaticKeypair: static, Prologue: prologue}
	if usePSK {
		cfg.PresharedKey, cfg.PresharedKeyPlacement = psk, 2
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	defer c.SetDeadline(time.Time{})
	in, err := ReadFrame(c)
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, in); err != nil {
		return nil, nil, fmt.Errorf("noise msg1: %w", err)
	}
	peer := append([]byte(nil), hs.PeerStatic()...)
	if err := check(peer); err != nil {
		return nil, nil, err
	}
	msg, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := WriteFrame(c, msg); err != nil {
		return nil, nil, err
	}
	return &SecureConn{Conn: c, send: cs2, recv: cs1}, peer, nil
}

// Pipe copies in both directions and closes both sides as soon as one ends.
func Pipe(a, b io.ReadWriteCloser) {
	var once sync.Once
	closeBoth := func() { a.Close(); b.Close() }
	go func() { io.Copy(a, b); once.Do(closeBoth) }()
	io.Copy(b, a)
	once.Do(closeBoth)
}
