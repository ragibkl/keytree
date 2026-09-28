// Package syncer runs one keytree sync: fetch the access file, work out this
// server's accounts, fetch keys, and update each authorized_keys.
package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ragibkl/keytree/internal/authkeys"
	"github.com/ragibkl/keytree/internal/config"
	"github.com/ragibkl/keytree/internal/fetch"
	"github.com/ragibkl/keytree/internal/passwd"
)

// Exit statuses.
const (
	OK          = 0 // everything applied
	Partial     = 1 // something failed; old keys were kept where it did
	ConfigError = 2 // the access file or local config is unusable; nothing changed
)

// Options configures one run. All host paths are already joined with any
// --root prefix.
type Options struct {
	Name       string // this server's name
	Source     string // access file URL
	PasswdPath string
	StateDir   string
	DryRun     bool
}

// Syncer performs runs.
type Syncer struct {
	Opts    Options
	Fetcher *fetch.Fetcher
	Log     *log.Logger
	// HomePrefix is joined in front of every home directory (the --root).
	HomePrefix string
}

type state struct {
	Accounts []string `json:"accounts"`
}

// Run performs one sync and returns an exit status.
func (s *Syncer) Run(ctx context.Context) int {
	if !s.Opts.DryRun {
		if err := os.MkdirAll(s.Opts.StateDir, 0o700); err != nil {
			s.Log.Printf("error: state dir: %v", err)
			return Partial
		}
		unlock, err := lock(filepath.Join(s.Opts.StateDir, "lock"))
		if err != nil {
			s.Log.Printf("error: %v", err)
			return Partial
		}
		defer unlock()
	}

	data, err := s.Fetcher.Config(ctx, s.Opts.Source)
	if err != nil {
		s.Log.Printf("error: %v; nothing changed", err)
		return Partial
	}
	file, err := config.Parse(data)
	if err != nil {
		s.Log.Printf("error: %s: %v; nothing changed", s.Opts.Source, err)
		return ConfigError
	}
	access := file.Resolve(s.Opts.Name)
	if len(access.Matched) == 0 {
		s.Log.Printf("warn: no servers entry matches %q; nothing changed", s.Opts.Name)
		return ConfigError
	}

	accounts, err := passwd.Load(s.Opts.PasswdPath)
	if err != nil {
		s.Log.Printf("error: %v; nothing changed", err)
		return Partial
	}
	prev := s.loadState()

	status := OK
	results := s.fetchAll(ctx, file, access)
	var managed []string

	for _, name := range slices.Sorted(maps.Keys(access.Accounts)) {
		entry, ok := accounts[name]
		if !ok {
			s.Log.Printf("warn: account %q does not exist here; skipped", name)
			continue
		}
		managed = append(managed, name)
		acct := s.account(entry)
		lines, failed := s.linesFor(acct, file, access.Accounts[name], results)
		if failed {
			status = Partial
		}
		if !s.update(acct, lines) {
			status = Partial
		}
	}

	// Accounts keytree managed before but which lost their last entry.
	for _, name := range prev.Accounts {
		if _, still := access.Accounts[name]; still {
			continue
		}
		entry, ok := accounts[name]
		if !ok {
			continue
		}
		if !s.update(s.account(entry), nil) {
			status = Partial
			managed = append(managed, name) // retry the removal next run
		}
	}

	if s.Opts.DryRun {
		return status
	}
	sort.Strings(managed)
	if err := s.saveState(state{Accounts: managed}); err != nil {
		s.Log.Printf("error: save state: %v", err)
		status = Partial
	}
	if status == OK {
		stamp := []byte(time.Now().UTC().Format(time.RFC3339) + "\n")
		if err := fetch.WriteFileAtomic(filepath.Join(s.Opts.StateDir, "last-success"), stamp, 0o644); err != nil {
			s.Log.Printf("error: write last-success: %v", err)
		}
	}
	return status
}

func (s *Syncer) account(e passwd.Entry) authkeys.Account {
	return authkeys.Account{Name: e.Name, UID: e.UID, GID: e.GID, Home: filepath.Join(s.HomePrefix, e.Home)}
}

// fetchAll fetches every source needed on this server once, a few at a time.
func (s *Syncer) fetchAll(ctx context.Context, file *config.File, access config.Access) map[string]fetch.Result {
	users := map[string]bool{}
	for _, us := range access.Accounts {
		for _, u := range us {
			users[u] = true
		}
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 4)
		results = map[string]fetch.Result{}
		seen    = map[string]bool{}
	)
	for u := range users {
		for _, src := range fetch.Sources(file.Users[u]) {
			key := sourceKey(u, src)
			if seen[key] {
				continue
			}
			seen[key] = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				r := s.Fetcher.Keys(ctx, src)
				<-sem
				mu.Lock()
				results[key] = r
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	return results
}

func sourceKey(user string, src fetch.Source) string {
	return user + "\x00" + src.Label()
}

// linesFor builds an account's block. When a source failed with no cached
// copy, the lines it contributed last time are carried over from the
// current block, so a failed fetch never removes anyone.
func (s *Syncer) linesFor(acct authkeys.Account, file *config.File, users []string, results map[string]fetch.Result) ([]string, bool) {
	failed := false
	var current []string
	currentLoaded := false
	seen := map[string]bool{}
	var lines []string
	add := func(key, comment string) {
		if file.IsRevoked(key) {
			if !seen[key] {
				s.Log.Printf("%s: skipping revoked key (%s)", acct.Name, comment)
			}
			seen[key] = true
			return
		}
		if seen[key] {
			return
		}
		seen[key] = true
		lines = append(lines, key+" "+comment)
	}

	for _, u := range users {
		for _, src := range fetch.Sources(file.Users[u]) {
			comment := "keytree:" + u + " " + src.Label()
			r := results[sourceKey(u, src)]
			if r.Err != nil {
				failed = true
				if r.Stale {
					s.Log.Printf("warn: %s: %v; using cached keys", acct.Name, r.Err)
				} else {
					s.Log.Printf("warn: %s: %v; keeping keys already in the file", acct.Name, r.Err)
					if !currentLoaded {
						current, _ = authkeys.Read(acct)
						currentLoaded = true
					}
					for _, l := range current {
						if key, ok := strings.CutSuffix(l, " "+comment); ok {
							add(key, comment)
						}
					}
					continue
				}
			}
			for _, k := range r.Keys {
				add(k, comment)
			}
		}
	}
	return lines, failed
}

func (s *Syncer) update(acct authkeys.Account, lines []string) bool {
	changed, err := authkeys.Update(acct, lines, s.Opts.DryRun)
	if err != nil {
		s.Log.Printf("error: %s: %v; skipped", acct.Name, err)
		return false
	}
	verb := "updated"
	if s.Opts.DryRun {
		verb = "would update"
	}
	switch {
	case changed && len(lines) == 0:
		s.Log.Printf("%s: %s (block removed)", acct.Name, verb)
	case changed:
		s.Log.Printf("%s: %s (%d keys)", acct.Name, verb, len(lines))
	}
	return true
}

func (s *Syncer) loadState() state {
	var st state
	data, err := os.ReadFile(filepath.Join(s.Opts.StateDir, "state.json"))
	if err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			s.Log.Printf("warn: state.json unreadable (%v); starting fresh", err)
		}
	}
	return st
}

func (s *Syncer) saveState(st state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return fetch.WriteFileAtomic(filepath.Join(s.Opts.StateDir, "state.json"), append(data, '\n'), 0o600)
}

// lock takes an exclusive, non-blocking lock so runs never overlap.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another keytree sync is running")
		}
		return nil, fmt.Errorf("lock: %w", err)
	}
	return func() { f.Close() }, nil
}
