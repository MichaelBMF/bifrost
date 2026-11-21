package update

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"aead.dev/minisign"
)

func TestParseTagAndNewer(t *testing.T) {
	for in, want := range map[string]string{"v1.2.3": "v1.2.3", "0.1.0": "v0.1.0", " v10.0.1\n": "v10.0.1"} {
		got, err := ParseTag(in)
		if err != nil || got != want {
			t.Errorf("ParseTag(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "dev", "v1.2", "v1.2.3-rc1", "0.0.0~SNAPSHOT-3f273c2"} {
		if _, err := ParseTag(bad); err == nil {
			t.Errorf("ParseTag(%q) accepted", bad)
		}
	}
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.2.0", "v0.1.0", true},
		{"v0.1.0", "v0.1.0", false},
		{"v0.1.0", "v0.2.0", false},
		{"v0.10.0", "v0.9.9", true},
		{"v1.0.0", "v0.99.99", true},
		{"v0.1.1", "v0.1.0", true},
		{"garbage", "v0.1.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

// The real v0.1.0 release must verify with the committed key.
func TestRealRelease(t *testing.T) {
	key, err := PublicKeyFromFile("../../packaging/minisign.pub")
	if err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile("testdata/SHA256SUMS")
	sig, _ := os.ReadFile("testdata/SHA256SUMS.minisig")
	m, err := VerifySums(key, "v0.1.0", sums, sig)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m[DebName("v0.1.0", "amd64")]; !ok {
		t.Errorf("no amd64 package in %v", m)
	}
	if _, err := VerifySums(key, "v0.2.0", sums, sig); err == nil {
		t.Error("v0.1.0 sums accepted as v0.2.0")
	}
	tampered := []byte(strings.Replace(string(sums), "a", "b", 1))
	if _, err := VerifySums(key, "v0.1.0", tampered, sig); err == nil {
		t.Error("tampered sums accepted")
	}
}

type fakeRelease struct {
	priv   minisign.PrivateKey
	pub    minisign.PublicKey
	latest string
	files  map[string][]byte // "<tag>/<name>"
	srv    *httptest.Server
	src    *Source
}

func newFake(t *testing.T) *fakeRelease {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRelease{priv: priv, pub: pub, files: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/repos/o/r/releases/latest" {
			fmt.Fprintf(w, `{"tag_name":%q}`, f.latest)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/dl/o/r/releases/download/")
		b, ok := f.files[p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(f.srv.Close)
	f.src = &Source{Repo: "o/r", PublicKey: pub, APIBase: f.srv.URL + "/api", ReleaseURL: f.srv.URL + "/dl"}
	return f
}

// publish adds a release; comment overrides the trusted comment if not empty.
func (f *fakeRelease) publish(tag, comment string, deb []byte) {
	name := DebName(tag, "amd64")
	h := sha256.Sum256(deb)
	sums := []byte(hex.EncodeToString(h[:]) + "  " + name + "\n")
	if comment == "" {
		comment = "bifrost " + tag
	}
	f.files[tag+"/"+name] = deb
	f.files[tag+"/SHA256SUMS"] = sums
	f.files[tag+"/SHA256SUMS.minisig"] = minisign.SignWithComments(f.priv, sums, comment, "test")
	f.latest = tag
}

func TestFetchDeb(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	f.publish("v0.2.0", "", []byte("package 0.2.0"))

	tag, err := f.src.Latest(ctx)
	if err != nil || tag != "v0.2.0" {
		t.Fatalf("Latest = %q, %v", tag, err)
	}
	path, err := f.src.FetchDeb(ctx, tag, "amd64", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "package 0.2.0" {
		t.Errorf("got %q", b)
	}
	if _, err := f.src.FetchDeb(ctx, tag, "arm64", t.TempDir()); err == nil {
		t.Error("missing arch accepted")
	}
}

func TestFetchDebRejects(t *testing.T) {
	ctx := context.Background()

	t.Run("swapped package", func(t *testing.T) {
		f := newFake(t)
		f.publish("v0.2.0", "", []byte("good"))
		f.files["v0.2.0/"+DebName("v0.2.0", "amd64")] = []byte("evil")
		if _, err := f.src.FetchDeb(ctx, "v0.2.0", "amd64", t.TempDir()); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("old sums replayed under new tag", func(t *testing.T) {
		f := newFake(t)
		f.publish("v0.2.0", "bifrost v0.1.0", []byte("old"))
		if _, err := f.src.FetchDeb(ctx, "v0.2.0", "amd64", t.TempDir()); err == nil || !strings.Contains(err.Error(), "signed for") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("other key", func(t *testing.T) {
		f := newFake(t)
		f.publish("v0.2.0", "", []byte("pkg"))
		other, _, _ := minisign.GenerateKey(rand.Reader)
		f.src.PublicKey = other
		if _, err := f.src.FetchDeb(ctx, "v0.2.0", "amd64", t.TempDir()); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("bad latest tag", func(t *testing.T) {
		f := newFake(t)
		f.latest = "nightly"
		if _, err := f.src.Latest(ctx); err == nil {
			t.Error("accepted")
		}
	})
}
