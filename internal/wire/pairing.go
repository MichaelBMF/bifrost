package wire

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
)

// PairingCode is the content of the QR code ("bifrost1:" + base64url(JSON)).
type PairingCode struct {
	Relay    string `json:"r"`
	RelayPin string `json:"p"`
	AgentID  string `json:"a"`
	AgentPub string `json:"k"`
	Token    string `json:"t"`
}

func (p PairingCode) String() string {
	b, _ := json.Marshal(p)
	return "bifrost1:" + base64.RawURLEncoding.EncodeToString(b)
}

func ParsePairingCode(s string) (PairingCode, error) {
	var p PairingCode
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "bifrost1:") {
		return p, errors.New("not a bifrost1 code")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "bifrost1:"))
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if p.Relay == "" || p.RelayPin == "" || p.AgentID == "" || p.AgentPub == "" || p.Token == "" {
		return p, errors.New("incomplete pairing code")
	}
	return p, nil
}

// PairRequest is the app's first encrypted message during pairing (Noise_IKpsk2).
// User and DeviceName are optional and self-asserted by the app; older clients
// send only relay_id.
type PairRequest struct {
	RelayID    string `json:"relay_id"`
	User       string `json:"user,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
}

// PairResponse is the agent's answer to a PairRequest.
type PairResponse struct {
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	Name       string   `json:"name,omitempty"` // agent-assigned device name (primary key)
	Services   []string `json:"services,omitempty"`
	DeviceFP   string   `json:"device_fp,omitempty"`
	AgentFP    string   `json:"agent_fp,omitempty"`
	User       string   `json:"user,omitempty"`
	DeviceName string   `json:"device_name,omitempty"`
}

// MaxLabelLen limits user and device names exchanged during pairing.
const MaxLabelLen = 64

// CleanLabel trims a user or device name, drops control characters and limits its length.
func CleanLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > MaxLabelLen {
		s = string(r[:MaxLabelLen])
	}
	return strings.TrimSpace(s)
}
