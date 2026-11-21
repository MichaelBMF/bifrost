package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// fakeAgent mimics the agent's admin API.
type fakeAgent struct {
	mu      sync.Mutex
	devices map[string]map[string]any
	pairs   []url.Values
	revoked []string
}

func (f *fakeAgent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewEncoder(w).Encode(f.devices)
	})
	mux.HandleFunc("POST /pair", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.pairs = append(f.pairs, r.URL.Query())
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"code": "bifrost1:eyJyIjoieCJ9"})
	})
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		name := r.URL.Query().Get("name")
		if _, ok := f.devices[name]; !ok {
			http.Error(w, "unknown device", 404)
			return
		}
		delete(f.devices, name)
		f.revoked = append(f.revoked, name)
	})
	return mux
}

type harness struct {
	t      *testing.T
	agent  *fakeAgent
	ui     *httptest.Server
	client *http.Client
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	agent := &fakeAgent{devices: map[string]map[string]any{
		"mac":     {"fingerprint": "AAAA-BBBB", "services": []string{"mqtt"}, "added": "2026-11-21T17:00:00Z"},
		"monitor": {"fingerprint": "CCCC-DDDD", "services": []string{"mqtt"}, "added": "2026-11-21T17:05:00Z", "user": "ops"},
	}}
	agentSrv := httptest.NewServer(agent.handler())
	t.Cleanup(agentSrv.Close)

	hash, _ := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	cfg := &Config{
		Admin:     strings.TrimPrefix(agentSrv.URL, "http://"),
		Users:     []User{{Name: "michael", PasswordHash: string(hash)}},
		Protected: []string{"monitor"},
		Services:  []string{"mqtt", "ha"},
		TLS:       TLSConfig{Mode: "off"},
	}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ui := httptest.NewServer(s.Handler())
	t.Cleanup(ui.Close)
	jar, _ := cookiejar.New(nil)
	return &harness{t: t, agent: agent, ui: ui, client: &http.Client{Jar: jar}}
}

func (h *harness) get(path string) (int, string) {
	h.t.Helper()
	resp, err := h.client.Get(h.ui.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (h *harness) post(path string, form url.Values) (int, string) {
	h.t.Helper()
	resp, err := h.client.PostForm(h.ui.URL+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (h *harness) login() string {
	h.t.Helper()
	code, body := h.post("/login", url.Values{"user": {"michael"}, "password": {"correct horse battery"}})
	if code != 200 || !strings.Contains(body, "Neues Gerät koppeln") {
		h.t.Fatalf("login failed: %d %s", code, body)
	}
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatal("no csrf token on page")
	}
	return m[1]
}

func TestRequiresLogin(t *testing.T) {
	h := newHarness(t)
	code, body := h.get("/")
	if code != 200 || !strings.Contains(body, `action="/login"`) {
		t.Fatalf("expected login page, got %d", code)
	}
	code, _ = h.post("/revoke", url.Values{"name": {"mac"}, "confirm": {"mac"}})
	if len(h.agent.revoked) != 0 {
		t.Fatalf("revoke without session reached the agent (status %d)", code)
	}
}

func TestWrongPassword(t *testing.T) {
	h := newHarness(t)
	code, body := h.post("/login", url.Values{"user": {"michael"}, "password": {"nope"}})
	if code != http.StatusUnauthorized || !strings.Contains(body, "falsch") {
		t.Fatalf("expected 401, got %d", code)
	}
	code, _ = h.post("/login", url.Values{"user": {"nobody"}, "password": {"correct horse battery"}})
	if code != http.StatusUnauthorized {
		t.Fatalf("unknown user: expected 401, got %d", code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	h := newHarness(t)
	last := 0
	for i := 0; i < 7; i++ {
		last, _ = h.post("/login", url.Values{"user": {"michael"}, "password": {"nope"}})
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures, got %d", last)
	}
}

func TestDevicesAndProtection(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	_, body := h.get("/")
	if !strings.Contains(body, "mac") || !strings.Contains(body, "geschützt") || !strings.Contains(body, "ops") {
		t.Fatal("device list incomplete")
	}

	// CSRF token is required.
	if code, _ := h.post("/revoke", url.Values{"name": {"mac"}, "confirm": {"mac"}}); code != http.StatusForbidden {
		t.Fatalf("missing csrf: expected 403, got %d", code)
	}
	// Protected devices cannot be revoked.
	if code, _ := h.post("/revoke", url.Values{"csrf": {csrf}, "name": {"monitor"}, "confirm": {"monitor"}}); code != http.StatusBadRequest {
		t.Fatalf("protected revoke: expected 400, got %d", code)
	}
	// The name must be typed exactly.
	if code, _ := h.post("/revoke", url.Values{"csrf": {csrf}, "name": {"mac"}, "confirm": {"Mac"}}); code != http.StatusBadRequest {
		t.Fatalf("wrong confirmation: expected 400, got %d", code)
	}
	if len(h.agent.revoked) != 0 {
		t.Fatalf("agent got revokes: %v", h.agent.revoked)
	}
	code, body := h.post("/revoke", url.Values{"csrf": {csrf}, "name": {"mac"}, "confirm": {"mac"}})
	if code != 200 || !strings.Contains(body, "Gerät widerrufen") {
		t.Fatalf("revoke: %d", code)
	}
	if len(h.agent.revoked) != 1 || h.agent.revoked[0] != "mac" {
		t.Fatalf("agent revokes: %v", h.agent.revoked)
	}
}

func TestPairShowsQR(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	code, body := h.post("/pair", url.Values{"csrf": {csrf}, "name": {"michael-iphone"}, "user": {"michael"},
		"services": {"mqtt", "evil"}})
	if code != 200 || !strings.Contains(body, "data:image/svg") || !strings.Contains(body, "bifrost1:eyJyIjoieCJ9") {
		t.Fatalf("pair page: %d", code)
	}
	if len(h.agent.pairs) != 1 {
		t.Fatalf("pairs: %v", h.agent.pairs)
	}
	q := h.agent.pairs[0]
	if q.Get("name") != "michael-iphone" || q.Get("services") != "mqtt" || q.Get("user") != "michael" {
		t.Fatalf("agent got %v (unknown services must be dropped)", q)
	}

	// Invalid and duplicate names never reach the agent.
	for _, name := range []string{"Bad Name", "mac", "monitor", ""} {
		if code, _ := h.post("/pair", url.Values{"csrf": {csrf}, "name": {name}, "services": {"mqtt"}}); code != http.StatusBadRequest {
			t.Fatalf("name %q: expected 400, got %d", name, code)
		}
	}
	if len(h.agent.pairs) != 1 {
		t.Fatalf("agent got extra pair requests: %v", h.agent.pairs)
	}
}

func TestLogoutAndHeaders(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp, err := h.client.Get(h.ui.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, k := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"} {
		if resp.Header.Get(k) == "" {
			t.Errorf("missing header %s", k)
		}
	}
	h.post("/logout", url.Values{"csrf": {csrf}})
	if _, body := h.get("/"); !strings.Contains(body, `action="/login"`) {
		t.Fatal("still logged in after logout")
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{},
		{Users: []User{{Name: "x", PasswordHash: "plain"}}, TLS: TLSConfig{Mode: "off"}},
		{Users: []User{{Name: "x", PasswordHash: "$2a$10$abc"}}},
		{Users: []User{{Name: "x", PasswordHash: "$2a$10$abc"}}, TLS: TLSConfig{Mode: "files"}},
	}
	for i, c := range bad {
		if err := c.normalize(); err == nil {
			t.Errorf("config %d: expected an error", i)
		}
	}
}

func TestSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	_, _, fp1, err := ensureSelfSigned(dir, "0.0.0.0:8443")
	if err != nil {
		t.Fatal(err)
	}
	_, _, fp2, err := ensureSelfSigned(dir, "0.0.0.0:8443")
	if err != nil || fp1 != fp2 {
		t.Fatalf("certificate not reused: %v %s %s", err, fp1, fp2)
	}
}
