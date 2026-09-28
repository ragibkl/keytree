// Package fetch downloads the access file and users' public keys, keeping a
// last-known-good copy of each on disk.
package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ragibkl/keytree/internal/config"
)

const (
	maxConfigSize = 1 << 20
	maxKeysSize   = 256 << 10
)

// Fetcher downloads configs and keys. The base URLs are overridable so
// tests can point them at a fake server.
type Fetcher struct {
	Client    *http.Client
	UserAgent string
	GitHubURL string // default https://github.com
	GitLabURL string // default https://gitlab.com
	// CacheDir holds last-known-good copies. Empty disables caching.
	CacheDir string
	// ReadOnly uses the cache but never writes it (for --dry-run).
	ReadOnly bool
}

// New returns a Fetcher with a timeout and the public defaults.
func New(cacheDir, userAgent string) *Fetcher {
	return &Fetcher{
		Client:    &http.Client{Timeout: 10 * time.Second},
		UserAgent: userAgent,
		GitHubURL: "https://github.com",
		GitLabURL: "https://gitlab.com",
		CacheDir:  cacheDir,
	}
}

// Config returns the access file at source (https://, http:// or file://).
// Over HTTP it sends the cached ETag, so an unchanged file costs a 304.
func (f *Fetcher) Config(ctx context.Context, source string) ([]byte, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, fmt.Errorf("source %q: %w", source, err)
	}
	if u.Scheme == "file" {
		data, err := os.ReadFile(u.Path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", u.Path, err)
		}
		return data, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	f.setUA(req)
	cached, cerr := f.readCache("config.yaml")
	etag, _ := f.readCache("config.etag")
	if cerr == nil && len(etag) > 0 {
		req.Header.Set("If-None-Match", string(etag))
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", source, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if cerr != nil {
			return nil, fmt.Errorf("fetch %s: 304 but no cached copy", source)
		}
		return cached, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("fetch %s: HTTP %d", source, resp.StatusCode)
	}
	body, err := readLimited(resp.Body, maxConfigSize)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", source, err)
	}
	if f.writeCache("config.yaml", body) == nil {
		if e := resp.Header.Get("ETag"); e != "" {
			f.writeCache("config.etag", []byte(e))
		} else {
			f.removeCache("config.etag")
		}
	}
	return body, nil
}

// Source is one place a user's keys come from.
type Source struct {
	Kind string // "github", "gitlab" or "keys"
	Name string // username for github/gitlab
	Keys []string
}

// Label identifies the source in authorized_keys comments and logs.
func (s Source) Label() string {
	if s.Kind == "keys" {
		return "key"
	}
	return s.Kind + ":" + s.Name
}

// Sources lists a user's key sources in a fixed order.
func Sources(u config.User) []Source {
	var out []Source
	if u.GitHub != "" {
		out = append(out, Source{Kind: "github", Name: u.GitHub})
	}
	if u.GitLab != "" {
		out = append(out, Source{Kind: "gitlab", Name: u.GitLab})
	}
	if len(u.Keys) > 0 {
		out = append(out, Source{Kind: "keys", Keys: u.Keys})
	}
	return out
}

// Result is the outcome of fetching one source.
type Result struct {
	Keys []string // normalized "type base64" lines
	// Stale is set when the fetch failed and Keys came from the cache.
	Stale bool
	// Err is the fetch error, set whenever the fetch itself failed (even if
	// stale keys were available).
	Err error
}

// Keys fetches a source's keys. When a remote fetch fails, the last good
// copy is used instead and Stale is set.
func (f *Fetcher) Keys(ctx context.Context, s Source) Result {
	if s.Kind == "keys" {
		keys, err := ParseKeys([]byte(strings.Join(s.Keys, "\n")))
		return Result{Keys: keys, Err: err}
	}
	base := f.GitHubURL
	if s.Kind == "gitlab" {
		base = f.GitLabURL
	}
	cacheName := filepath.Join(s.Kind, s.Name+".keys")

	keys, err := f.fetchKeys(ctx, strings.TrimRight(base, "/")+"/"+url.PathEscape(s.Name)+".keys")
	if err == nil {
		f.writeCache(cacheName, []byte(strings.Join(keys, "\n")))
		return Result{Keys: keys}
	}
	err = fmt.Errorf("%s: %w", s.Label(), err)
	if data, cerr := f.readCache(cacheName); cerr == nil {
		if cached, perr := ParseKeys(data); perr == nil {
			return Result{Keys: cached, Stale: true, Err: err}
		}
	}
	return Result{Err: err}
}

func (f *Fetcher) fetchKeys(ctx context.Context, u string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	f.setUA(req)
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := readLimited(resp.Body, maxKeysSize)
	if err != nil {
		return nil, err
	}
	return ParseKeys(body)
}

// ParseKeys parses one public key per line. Any line that is not a plain
// key (an HTML error page, say) fails the whole response. An empty body is
// valid: the user has no keys.
func ParseKeys(data []byte) ([]string, error) {
	var keys []string
	for i, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		pub, _, options, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("line %d is not an SSH public key", i+1)
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("line %d has key options, which are not supported", i+1)
		}
		keys = append(keys, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))))
	}
	return keys, nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response larger than %d bytes", limit)
	}
	return data, nil
}

func (f *Fetcher) setUA(req *http.Request) {
	if f.UserAgent != "" {
		req.Header.Set("User-Agent", f.UserAgent)
	}
}

func (f *Fetcher) readCache(name string) ([]byte, error) {
	if f.CacheDir == "" {
		return nil, errors.New("no cache")
	}
	return os.ReadFile(filepath.Join(f.CacheDir, name))
}

func (f *Fetcher) writeCache(name string, data []byte) error {
	if f.CacheDir == "" || f.ReadOnly {
		return nil
	}
	p := filepath.Join(f.CacheDir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return WriteFileAtomic(p, data, 0o600)
}

func (f *Fetcher) removeCache(name string) {
	if f.CacheDir != "" && !f.ReadOnly {
		os.Remove(filepath.Join(f.CacheDir, name))
	}
}

// WriteFileAtomic writes data to a temp file next to path and renames it
// into place. Used for keytree's own state, which only root can write.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
