// Package update fetches signed bifrost releases from GitHub.
//
// A release carries SHA256SUMS and SHA256SUMS.minisig. The signature is checked
// against a minisign public key, and its trusted comment must read
// "bifrost <tag>", so an old (validly signed) SHA256SUMS cannot be passed off
// as a newer release. The package file is then checked against SHA256SUMS.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"aead.dev/minisign"
)

// Source says where releases come from and how they are checked.
type Source struct {
	Repo       string             // "owner/name"
	PublicKey  minisign.PublicKey // release signing key
	HTTP       *http.Client       // nil: http.DefaultClient
	APIBase    string             // default https://api.github.com
	ReleaseURL string             // default https://github.com; downloads are <ReleaseURL>/<Repo>/releases/download/<tag>/<file>
}

const (
	maxSmall = 1 << 20   // SHA256SUMS, signature, API response
	maxAsset = 256 << 20 // a package
)

var tagRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// ParseTag accepts "v1.2.3" or "1.2.3" and returns the canonical tag "v1.2.3".
func ParseTag(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	if !tagRE.MatchString(s) {
		return "", fmt.Errorf("not a release version: %q", s)
	}
	return s, nil
}

// Newer reports whether tag a is a higher version than tag b. Both must be
// canonical tags (see ParseTag).
func Newer(a, b string) bool {
	pa, pb := tagRE.FindStringSubmatch(a), tagRE.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// PublicKeyFromFile reads a minisign public key file.
func PublicKeyFromFile(path string) (minisign.PublicKey, error) {
	return minisign.PublicKeyFromFile(path)
}

func (s *Source) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return http.DefaultClient
}

func (s *Source) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bifrost-upgrade")
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", url, limit)
	}
	return b, nil
}

func (s *Source) assetURL(tag, name string) string {
	base := s.ReleaseURL
	if base == "" {
		base = "https://github.com"
	}
	return fmt.Sprintf("%s/%s/releases/download/%s/%s", strings.TrimRight(base, "/"), s.Repo, tag, name)
}

// Latest returns the tag of the newest published release.
func (s *Source) Latest(ctx context.Context) (string, error) {
	base := s.APIBase
	if base == "" {
		base = "https://api.github.com"
	}
	b, err := s.get(ctx, fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(base, "/"), s.Repo), maxSmall)
	if err != nil {
		return "", err
	}
	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", fmt.Errorf("latest release: %w", err)
	}
	return ParseTag(r.TagName)
}

// Sums downloads SHA256SUMS of a release and verifies its signature and
// trusted comment. It returns file name -> SHA-256 (hex).
func (s *Source) Sums(ctx context.Context, tag string) (map[string]string, error) {
	sums, err := s.get(ctx, s.assetURL(tag, "SHA256SUMS"), maxSmall)
	if err != nil {
		return nil, err
	}
	sig, err := s.get(ctx, s.assetURL(tag, "SHA256SUMS.minisig"), maxSmall)
	if err != nil {
		return nil, err
	}
	return VerifySums(s.PublicKey, tag, sums, sig)
}

// VerifySums checks a SHA256SUMS file against its minisign signature and the
// expected release tag, and parses it.
func VerifySums(key minisign.PublicKey, tag string, sums, sig []byte) (map[string]string, error) {
	if !minisign.Verify(key, sums, sig) {
		return nil, errors.New("SHA256SUMS: signature does not verify with the release key")
	}
	var parsed minisign.Signature
	if err := parsed.UnmarshalText(sig); err != nil {
		return nil, fmt.Errorf("SHA256SUMS.minisig: %w", err)
	}
	if want := "bifrost " + tag; parsed.TrustedComment != want {
		return nil, fmt.Errorf("SHA256SUMS: signed for %q, want %q", parsed.TrustedComment, want)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || len(f[0]) != 64 {
			continue
		}
		out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
	}
	if len(out) == 0 {
		return nil, errors.New("SHA256SUMS: no entries")
	}
	return out, nil
}

// DebName is the package file name of a release for a Debian architecture.
func DebName(tag, arch string) string {
	return fmt.Sprintf("bifrost_%s_%s.deb", strings.TrimPrefix(tag, "v"), arch)
}

// FetchDeb downloads the .deb of release tag for arch into dir, after checking
// the release signature, and verifies its checksum. It returns the file path.
func (s *Source) FetchDeb(ctx context.Context, tag, arch, dir string) (string, error) {
	sums, err := s.Sums(ctx, tag)
	if err != nil {
		return "", err
	}
	name := DebName(tag, arch)
	want, ok := sums[name]
	if !ok {
		return "", fmt.Errorf("release %s has no %s", tag, name)
	}
	b, err := s.get(ctx, s.assetURL(tag, name), maxAsset)
	if err != nil {
		return "", err
	}
	got := sha256.Sum256(b)
	if hex.EncodeToString(got[:]) != want {
		return "", fmt.Errorf("%s: checksum mismatch", name)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
