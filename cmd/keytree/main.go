// Command keytree syncs SSH access from a shared config file into
// authorized_keys.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ragibkl/keytree/internal/config"
	"github.com/ragibkl/keytree/internal/fetch"
	"github.com/ragibkl/keytree/internal/syncer"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `keytree: pull-based SSH access from a shared config file.

Usage:
  keytree sync  [flags]            update authorized_keys on this server
  keytree plan  [flags] [FILE]     show who gets which account on a server
  keytree check FILE...            validate access files (for CI)
  keytree version

Run "keytree <command> -h" for a command's flags.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return syncer.ConfigError
	}
	switch args[0] {
	case "sync":
		return cmdSync(args[1:], stderr)
	case "plan":
		return cmdPlan(args[1:], stdout, stderr)
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "keytree", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "keytree: unknown command %q\n\n%s", args[0], usage)
		return syncer.ConfigError
	}
}

// hostFlags are the flags that locate things on the host. Every default
// lives under --root, so tests can run against a temp directory and never
// touch the real system.
type hostFlags struct {
	root, config, stateDir, source, name string
	githubURL, gitlabURL                 string
}

func (h *hostFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&h.root, "root", "/", "prefix for every host path: /etc/passwd, home directories, state and config defaults")
	fs.StringVar(&h.config, "config", "", "local config file (default <root>/etc/keytree/config.yaml)")
	fs.StringVar(&h.stateDir, "state-dir", "", "state and cache directory (default <root>/var/lib/keytree)")
	fs.StringVar(&h.source, "source", "", "access file URL or GitHub owner[/repo][@branch], overriding the local config")
	fs.StringVar(&h.name, "name", "", "server name, overriding the local config and hostname")
	fs.StringVar(&h.githubURL, "github-url", "https://github.com", "GitHub base URL (for testing)")
	fs.StringVar(&h.gitlabURL, "gitlab-url", "https://gitlab.com", "GitLab base URL (for testing)")
}

// resolve fills in source and name from the local config and hostname.
// The local config is optional when --source and --name are both given.
func (h *hostFlags) resolve() error {
	if h.config == "" {
		h.config = filepath.Join(h.root, "etc/keytree/config.yaml")
	}
	if h.stateDir == "" {
		h.stateDir = filepath.Join(h.root, "var/lib/keytree")
	}
	if h.source == "" || h.name == "" {
		data, err := os.ReadFile(h.config)
		if err != nil && (h.source == "" || !os.IsNotExist(err)) {
			return fmt.Errorf("local config: %w", err)
		}
		if err == nil {
			local, err := config.ParseLocal(data)
			if err != nil {
				return err
			}
			if h.source == "" {
				h.source = local.Source
			}
			if h.name == "" {
				h.name = local.Name
			}
		}
	}
	src, err := config.ExpandSource(h.source)
	if err != nil {
		return err
	}
	h.source = src
	if h.name == "" {
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("hostname: %w", err)
		}
		h.name, _, _ = strings.Cut(host, ".")
	}
	return nil
}

func (h *hostFlags) fetcher() *fetch.Fetcher {
	f := fetch.New(filepath.Join(h.stateDir, "cache"), "keytree/"+version)
	f.GitHubURL = h.githubURL
	f.GitLabURL = h.gitlabURL
	return f
}

func cmdSync(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var h hostFlags
	h.register(fs)
	dryRun := fs.Bool("dry-run", false, "show what would change without writing anything")
	jitter := fs.Duration("jitter", 0, "sleep a random time up to this long first, to spread load across servers")
	every := fs.Duration("every", 0, "keep running, syncing at this interval (for containers without cron)")
	if err := fs.Parse(args); err != nil {
		return syncer.ConfigError
	}
	logger := log.New(stderr, "keytree: ", 0)
	if err := h.resolve(); err != nil {
		logger.Printf("error: %v", err)
		return syncer.ConfigError
	}
	if *jitter > 0 {
		time.Sleep(rand.N(*jitter))
	}
	if *every <= 0 {
		return syncOnce(&h, *dryRun, logger)
	}
	for {
		if status := syncOnce(&h, *dryRun, logger); status != syncer.OK {
			logger.Printf("sync finished with status %d; next try in %s", status, *every)
		}
		time.Sleep(*every)
	}
}

func syncOnce(h *hostFlags, dryRun bool, logger *log.Logger) int {
	f := h.fetcher()
	f.ReadOnly = dryRun
	s := &syncer.Syncer{
		Opts: syncer.Options{
			Name:       h.name,
			Source:     h.source,
			PasswdPath: filepath.Join(h.root, "etc/passwd"),
			StateDir:   h.stateDir,
			DryRun:     dryRun,
		},
		Fetcher:    f,
		Log:        logger,
		HomePrefix: h.root,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return s.Run(ctx)
}

func cmdPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var h hostFlags
	h.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: keytree plan [flags] [FILE]\n\nWith FILE, reads that access file instead of fetching the source.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return syncer.ConfigError
	}

	var data []byte
	var err error
	if fs.NArg() > 0 {
		h.source = "file://" + mustAbs(fs.Arg(0))
	}
	if err := h.resolve(); err != nil {
		fmt.Fprintf(stderr, "keytree: %v\n", err)
		return syncer.ConfigError
	}
	f := h.fetcher()
	f.ReadOnly = true
	if data, err = f.Config(context.Background(), h.source); err != nil {
		fmt.Fprintf(stderr, "keytree: %v\n", err)
		return syncer.Partial
	}
	file, err := config.Parse(data)
	if err != nil {
		fmt.Fprintf(stderr, "keytree: %v\n", err)
		return syncer.ConfigError
	}

	access := file.Resolve(h.name)
	fmt.Fprintf(stdout, "server %s\n", h.name)
	if len(access.Matched) == 0 {
		fmt.Fprintln(stdout, "  no servers entry matches; sync would change nothing")
		return syncer.ConfigError
	}
	fmt.Fprintf(stdout, "  matched: %s\n", strings.Join(access.Matched, ", "))
	for _, account := range slices.Sorted(maps.Keys(access.Accounts)) {
		users := access.Accounts[account]
		if len(users) == 0 {
			fmt.Fprintf(stdout, "  %s: nobody (block removed)\n", account)
			continue
		}
		fmt.Fprintf(stdout, "  %s:\n", account)
		for _, u := range users {
			var labels []string
			for _, src := range fetch.Sources(file.Users[u]) {
				if src.Kind == "keys" {
					labels = append(labels, fmt.Sprintf("%d literal key(s)", len(src.Keys)))
				} else {
					labels = append(labels, src.Label())
				}
			}
			fmt.Fprintf(stdout, "    %s (%s)\n", u, strings.Join(labels, ", "))
		}
	}
	return 0
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: keytree check FILE...")
		return syncer.ConfigError
	}
	status := 0
	for _, p := range args {
		data, err := os.ReadFile(p)
		if err == nil {
			_, err = config.Parse(data)
		}
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", p, err)
			status = syncer.ConfigError
			continue
		}
		fmt.Fprintf(stdout, "%s: ok\n", p)
	}
	return status
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}
