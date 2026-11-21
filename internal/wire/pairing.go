package wire

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
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
