package fetch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func newFetcher(t *testing.T, srv *httptest.Server) *Fetcher {
	f := New(t.TempDir(), "keytree/test")
	f.GitHubURL = srv.URL
	f.GitLabURL = srv.URL
	f.Client.Timeout = 500 * time.Millisecond
	return f
}

func TestKeysBehaviour(t *testing.T) {
	good := testKey(t)
	var body atomic.Value
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow.keys" {
			time.Sleep(time.Second)
		}
		w.WriteHeader(int(status.Load()))
		w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	f := newFetcher(t, srv)
	ctx := context.Background()
	src := Source{Kind: "github", Name: "ragibkl"}

	// 200 with keys: fresh, and cached.
	status.Store(200)
	body.Store(good + "\n")
	r := f.Keys(ctx, src)
	if r.Err != nil || r.Stale || len(r.Keys) != 1 || r.Keys[0] != good {
		t.Fatalf("good fetch: %+v", r)
	}

	// Failures fall back to the cached copy.
	for name, set := range map[string]func(){
		"500":         func() { status.Store(500); body.Store("oops") },
		"404":         func() { status.Store(404); body.Store("") },
		"html on 200": func() { status.Store(200); body.Store("<html>captive portal</html>") },
		"one bad line": func() {
			status.Store(200)
			body.Store(good + "\nnot a key\n")
		},
	} {
		set()
		r := f.Keys(ctx, src)
		if r.Err == nil || !r.Stale || len(r.Keys) != 1 || r.Keys[0] != good {
			t.Errorf("%s: want stale cached key, got %+v", name, r)
		}
	}

	// Timeout with no cache for that user: error, no keys.
	r = f.Keys(ctx, Source{Kind: "github", Name: "slow"})
	if r.Err == nil || r.Stale || len(r.Keys) != 0 {
		t.Errorf("timeout: %+v", r)
	}

	// An empty 200 is a user with no keys, not a failure.
	status.Store(200)
	body.Store("")
	r = f.Keys(ctx, src)
	if r.Err != nil || len(r.Keys) != 0 {
		t.Errorf("empty body: %+v", r)
	}
}

func TestKeysLiteral(t *testing.T) {
	k := testKey(t)
	f := New("", "")
	r := f.Keys(context.Background(), Source{Kind: "keys", Keys: []string{k + " comment dropped"}})
	if r.Err != nil || len(r.Keys) != 1 || r.Keys[0] != k {
		t.Fatalf("%+v", r)
	}
}

func TestKeysURLs(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+" "+r.Header.Get("User-Agent"))
	}))
	defer srv.Close()
	f := newFetcher(t, srv)
	f.Keys(context.Background(), Source{Kind: "github", Name: "gh-user"})
	f.Keys(context.Background(), Source{Kind: "gitlab", Name: "gl.user"})
	want := "/gh-user.keys keytree/test|/gl.user.keys keytree/test"
	if got := strings.Join(paths, "|"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadOnlyCache(t *testing.T) {
	k := testKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(k))
	}))
	defer srv.Close()
	f := newFetcher(t, srv)
	f.ReadOnly = true
	f.Keys(context.Background(), Source{Kind: "github", Name: "a"})
	entries, _ := os.ReadDir(f.CacheDir)
	if len(entries) != 0 {
		t.Fatalf("read-only fetcher wrote cache: %v", entries)
	}
}

func TestConfigETag(t *testing.T) {
	var hits, notModified atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("version: 1\n"))
	}))
	defer srv.Close()
	f := newFetcher(t, srv)
	for i := 0; i < 2; i++ {
		data, err := f.Config(context.Background(), srv.URL+"/keytree.yaml")
		if err != nil || string(data) != "version: 1\n" {
			t.Fatalf("run %d: %q %v", i, data, err)
		}
	}
	if hits.Load() != 2 || notModified.Load() != 1 {
		t.Fatalf("hits=%d notModified=%d", hits.Load(), notModified.Load())
	}

	// A 304 with the cached body gone is an error, not an empty config.
	os.Remove(filepath.Join(f.CacheDir, "config.yaml"))
	os.WriteFile(filepath.Join(f.CacheDir, "config.etag"), []byte(`"v1"`), 0o600)
	if _, err := f.Config(context.Background(), srv.URL+"/keytree.yaml"); err != nil {
		t.Fatalf("missing body should refetch without If-None-Match: %v", err)
	}
}

func TestConfigErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Write([]byte(strings.Repeat("x", maxConfigSize+1)))
			return
		}
		w.WriteHeader(503)
	}))
	defer srv.Close()
	f := newFetcher(t, srv)
	for _, u := range []string{srv.URL + "/down", srv.URL + "/big", "file:///does/not/exist"} {
		if _, err := f.Config(context.Background(), u); err == nil {
			t.Errorf("%s: expected error", u)
		}
	}
}
