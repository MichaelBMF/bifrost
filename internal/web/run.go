package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Run serves the UI until the listener fails.
func Run(cfg *Config) error {
	s, err := New(cfg)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	switch cfg.TLS.Mode {
	case "off":
		log.Printf("hlidskjalf on http://%s (no TLS: use only behind a TLS proxy)", cfg.Listen)
		return srv.ListenAndServe()
	case "files":
		log.Printf("hlidskjalf on https://%s", cfg.Listen)
		return srv.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key)
	default:
		certFile, keyFile, fp, err := ensureSelfSigned(cfg.StateDir, cfg.Listen)
		if err != nil {
			return err
		}
		log.Printf("hlidskjalf on https://%s (self-signed certificate, SHA-256 %s)", cfg.Listen, fp)
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		return srv.ListenAndServeTLS(certFile, keyFile)
	}
}

// ensureSelfSigned creates (once) a long-lived self-signed certificate in dir and
// returns its paths and SHA-256 fingerprint, so the browser warning can be checked.
func ensureSelfSigned(dir, listen string) (certFile, keyFile, fingerprint string, err error) {
	certFile = filepath.Join(dir, "hlidskjalf-cert.pem")
	keyFile = filepath.Join(dir, "hlidskjalf-key.pem")
	if _, err := os.Stat(certFile); err != nil {
		if err := writeSelfSigned(certFile, keyFile, listen); err != nil {
			return "", "", "", err
		}
	}
	b, err := os.ReadFile(certFile)
	if err != nil {
		return "", "", "", err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", "", "", fmt.Errorf("%s: not a PEM certificate", certFile)
	}
	sum := sha256.Sum256(block.Bytes)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return certFile, keyFile, strings.Join(parts, ":"), nil
}

func writeSelfSigned(certFile, keyFile, listen string) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "hlidskjalf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	if host, _, err := net.SplitHostPort(listen); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, n.IP)
			}
		}
	}
	if h, err := os.Hostname(); err == nil {
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
