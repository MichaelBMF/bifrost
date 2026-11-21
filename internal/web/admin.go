package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Device is one entry of the agent's GET /devices. User, DeviceName and UserBound
// are only reported by agents that support user/device names in pairing.
type Device struct {
	Name        string   `json:"-"`
	Fingerprint string   `json:"fingerprint"`
	Services    []string `json:"services"`
	Added       string   `json:"added"`
	User        string   `json:"user"`
	UserBound   bool     `json:"user_bound"`
	DeviceName  string   `json:"device_name"`
	Protected   bool     `json:"-"`
}

func (d Device) AddedTime() string {
	t, err := time.Parse(time.RFC3339, d.Added)
	if err != nil {
		return d.Added
	}
	return t.Local().Format("02.01.2006 15:04")
}

// adminClient talks to the agent's local admin API.
type adminClient struct {
	base string
	http *http.Client
}

func newAdminClient(addr string) *adminClient {
	return &adminClient{base: "http://" + addr, http: &http.Client{Timeout: 10 * time.Second}}
}

func (a *adminClient) do(method, path string, q url.Values) ([]byte, error) {
	u := a.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent admin API unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: %s", strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (a *adminClient) Devices() ([]Device, error) {
	body, err := a.do("GET", "/devices", nil)
	if err != nil {
		return nil, err
	}
	m := map[string]Device{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("agent: unexpected /devices response: %w", err)
	}
	out := make([]Device, 0, len(m))
	for name, d := range m {
		d.Name = name
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Pair starts a pairing window and returns the bifrost1: code. user is passed on
// as an optional binding; agents without user support ignore it.
func (a *adminClient) Pair(name string, services []string, user string) (string, error) {
	q := url.Values{"name": {name}, "services": {strings.Join(services, ",")}}
	if user != "" {
		q.Set("user", user)
	}
	body, err := a.do("POST", "/pair", q)
	if err != nil {
		return "", err
	}
	var out struct{ Code string }
	if err := json.Unmarshal(body, &out); err != nil || !strings.HasPrefix(out.Code, "bifrost1:") {
		return "", fmt.Errorf("agent: unexpected /pair response")
	}
	return out.Code, nil
}

func (a *adminClient) Revoke(name string) error {
	_, err := a.do("POST", "/revoke", url.Values{"name": {name}})
	return err
}
