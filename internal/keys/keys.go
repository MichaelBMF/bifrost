// Package keys manages the keys of a component:
// an Ed25519 key for the outer TLS layer and an X25519 key for Noise.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/flynn/noise"
)

type Identity struct {
	TLSKey ed25519.PrivateKey
	Noise  noise.DHKey
	WG     noise.DHKey // WireGuard key (Curve25519), relay and agent only
}

type fileFormat struct {
	TLSSeed   string `json:"tls_seed"`
	NoisePriv string `json:"noise_priv"`
	NoisePub  string `json:"noise_pub"`
	WGPriv    string `json:"wg_priv"`
	WGPub     string `json:"wg_pub"`
}

func Generate() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	wgk, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{TLSKey: priv, Noise: kp, WG: wgk}, nil
}

// LoadOrCreate reads the key file or creates it with mode 0600.
func LoadOrCreate(path string) (*Identity, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id, err := Generate()
		if err != nil {
			return nil, false, err
		}
		return id, true, id.Save(path)
	}
	if err != nil {
		return nil, false, err
	}
	var f fileFormat
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, false, err
	}
	seed, err := hex.DecodeString(f.TLSSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, false, errors.New("invalid tls_seed")
	}
	np, err1 := hex.DecodeString(f.NoisePriv)
	nb, err2 := hex.DecodeString(f.NoisePub)
	if err1 != nil || err2 != nil {
		return nil, false, errors.New("invalid Noise key")
	}
	id := &Identity{TLSKey: ed25519.NewKeyFromSeed(seed), Noise: noise.DHKey{Private: np, Public: nb}}
	wp, err1 := hex.DecodeString(f.WGPriv)
	wb, err2 := hex.DecodeString(f.WGPub)
	if err1 != nil || err2 != nil || len(wp) != 32 || len(wb) != 32 {
		// older key file without a WireGuard key: add one
		if id.WG, err = noise.DH25519.GenerateKeypair(rand.Reader); err != nil {
			return nil, false, err
		}
		return id, false, id.Save(path)
	}
	id.WG = noise.DHKey{Private: wp, Public: wb}
	return id, false, nil
}

func (i *Identity) Save(path string) error {
	b, _ := json.MarshalIndent(fileFormat{
		TLSSeed:   hex.EncodeToString(i.TLSKey.Seed()),
		NoisePriv: hex.EncodeToString(i.Noise.Private),
		NoisePub:  hex.EncodeToString(i.Noise.Public),
		WGPriv:    hex.EncodeToString(i.WG.Private),
		WGPub:     hex.EncodeToString(i.WG.Public),
	}, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// Certificate creates a self-signed certificate. Trust does not come from a CA
// but from the hash of the public key (pinning or allowlist).
func (i *Identity) Certificate() (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bifrost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, i.TLSKey.Public(), i.TLSKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: i.TLSKey}, nil
}

// TLSID is the hex-encoded SHA-256 of the SubjectPublicKeyInfo.
func (i *Identity) TLSID() string {
	der, _ := x509.MarshalPKIXPublicKey(i.TLSKey.Public())
	return hashHex(der)
}

func CertID(c *x509.Certificate) string { return hashHex(c.RawSubjectPublicKeyInfo) }

func hashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// WGPublic is the WireGuard public key in the usual base64 format.
func (i *Identity) WGPublic() string { return base64.StdEncoding.EncodeToString(i.WG.Public) }

func ParseWGKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("invalid WireGuard key")
	}
	return b, nil
}

// Fingerprint returns a short form of a key that can be read aloud, e.g. "ABCD-EFGH-IJKL-MNOP".
func Fingerprint(key []byte) string {
	s := sha256.Sum256(key)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s[:10])
	return strings.Join([]string{enc[0:4], enc[4:8], enc[8:12], enc[12:16]}, "-")
}
