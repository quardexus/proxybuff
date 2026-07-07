// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/quardexus/proxybuff/internal/cache"
	"github.com/quardexus/proxybuff/internal/config"
	"github.com/quardexus/proxybuff/internal/proxy"
	"github.com/quardexus/proxybuff/internal/version"
)

func main() {
	args := os.Args[1:]

	if len(args) > 0 && args[0] == "status" {
		runStatus(args[1:])
		return
	}

	if len(args) > 0 && args[0] == "clear-cache" {
		runClearCache(args[1:])
		return
	}

	if len(args) > 0 && args[0] == "clear-certs" {
		runClearCerts(args[1:])
		return
	}

	var writeEffectiveConfigPath string
	args = stripWriteEffectiveConfig(args, &writeEffectiveConfigPath)

	for _, a := range args {
		if a == "--version" || a == "-version" {
			fmt.Printf("%s %s (Developed by %s)\n", version.Project, version.Version, version.Author)
			return
		}
		if a == "--help" || a == "-h" || a == "-help" {
			printUsage()
			return
		}
	}

	cfg, err := config.Parse(args)
	if err != nil {
		log.Printf("config error: %v\n", err)
		printUsage()
		os.Exit(2)
	}

	logCloser := setupLogging(cfg.LogFile)
	if logCloser != nil {
		defer logCloser()
	}

	if writeEffectiveConfigPath != "" {
		if err := writeEffectiveConfig(writeEffectiveConfigPath, cfg); err != nil {
			log.Printf("write effective config: %v\n", err)
			os.Exit(2)
		}
	}

	h, err := proxy.New(cfg)
	if err != nil {
		log.Fatalf("init: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	h.StartBackground(ctx)

	if err := runServers(ctx, cfg, h); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `%s %s (Developed by %s)

Usage:
  proxybuff --origin <url> [--http[=<port|addr>]] [--https[=<port|addr>]] [--cache <pattern>] [--ttl 10m] [--cache-dir ./cache] [--age-header]
  proxybuff --config /path/to/config.json
  proxybuff status      [--cache-dir ./cache] [--config /path/to/config.json]
  proxybuff clear-cache [--cache-dir ./cache] [--config /path/to/config.json] [--yes]
  proxybuff clear-certs [--cache-dir ./cache] [--config /path/to/config.json] [--yes]
  proxybuff --version

Commands:
  status        Show cache statistics and list cached files
  clear-cache   Remove all cached entries (keeps ACME certs); pass --yes to skip confirmation
  clear-certs   Remove all cached ACME certificates (forces re-issuance); pass --yes to skip confirmation

Flags:
  --origin      Upstream origin URL to proxy (required). You can also pass host[:port] without scheme.
  --listen      DEPRECATED: alias for --http
  --http        HTTP listener (required): port/address (e.g. 8080, :8080, 127.0.0.1:8080)
  --https       HTTPS listener: bool to enable/disable, or port/address (e.g. 443, :443, 127.0.0.1:443)
  --tls-domain  TLS domain(s) for ACME certificates when HTTPS is enabled (repeatable or comma-separated)
  --cache       Cache path pattern (repeatable). '*' matches any chars including '/'. '/' caches only root path.
  --recache     Auto-refresh cached path pattern (repeatable). When an entry is close to expiry, ProxyBuff refreshes it in the background.
  --recache-ahead    How long before expiry to trigger refresh (default 5m)
  --recache-workers  Max concurrent background refresh workers (default 4)
  --ttl         Cache TTL duration (default 10m)
  --cache-dir   Cache directory path (default ./cache)
  --log-file    Optional log file path (also logs to stdout)
  --age-header  Add standard Age header on cache HIT (optional)
  --use-origin-host  Send Host header from --origin (default: forward original client Host)
  --insecure-skip-verify  Skip TLS certificate verification for https origins (dangerous)
  --config      Read JSON config file (unknown keys rejected)
  --write-effective-config  Write effective config JSON to a file (for Docker entrypoint)

`, version.Project, version.Version, version.Author)
}

func stripWriteEffectiveConfig(args []string, outPath *string) []string {
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--write-effective-config" {
			if i+1 < len(args) {
				*outPath = args[i+1]
				i++
				continue
			}
			// keep invalid form; config.Parse will error and usage will print
		}
		if strings.HasPrefix(a, "--write-effective-config=") {
			*outPath = strings.TrimPrefix(a, "--write-effective-config=")
			continue
		}
		filtered = append(filtered, a)
	}
	return filtered
}

func writeEffectiveConfig(path string, cfg config.Config) error {
	type fileHost struct {
		Match              []string `json:"match,omitempty"`
		Origin             string   `json:"origin,omitempty"`
		Cache              []string `json:"cache,omitempty"`
		Recache            []string `json:"recache,omitempty"`
		TTL                string   `json:"ttl,omitempty"`
		TLSDomains         []string `json:"tlsDomains,omitempty"`
		UseOriginHost      bool     `json:"useOriginHost"`
		InsecureSkipVerify bool     `json:"insecureSkipVerify"`
		AgeHeader          bool     `json:"ageHeader"`
	}
	type fileCfg struct {
		Listen             string     `json:"listen"`
		HTTPEnabled        bool       `json:"httpEnabled"`
		HttpListen         string     `json:"httpListen"`
		HTTPSEnabled       bool       `json:"httpsEnabled"`
		HttpsListen        string     `json:"httpsListen"`
		TLSDomains         []string   `json:"tlsDomains"`
		Origin             string     `json:"origin"`
		CacheDir           string     `json:"cacheDir"`
		LogFile            string     `json:"logFile"`
		TTL                string     `json:"ttl"`
		Cache              []string   `json:"cache"`
		Recache            []string   `json:"recache"`
		RecacheAhead       string     `json:"recacheAhead"`
		RecacheWorkers     int        `json:"recacheWorkers"`
		AgeHeader          bool       `json:"ageHeader"`
		UseOriginHost      bool       `json:"useOriginHost"`
		InsecureSkipVerify bool       `json:"insecureSkipVerify"`
		CacheVaryHost      bool       `json:"cacheVaryHost"`
		CacheKeyQuery      bool       `json:"cacheKeyQuery"`
		Hosts              []fileHost `json:"hosts,omitempty"`
	}

	payload := fileCfg{
		Listen:             cfg.Listen,
		HTTPEnabled:        cfg.HTTPEnabled,
		HttpListen:         cfg.HttpListen,
		HTTPSEnabled:       cfg.HTTPSEnabled,
		HttpsListen:        cfg.HttpsListen,
		TLSDomains:         cfg.TLSDomains,
		Origin:             cfg.Origin,
		CacheDir:           cfg.CacheDir,
		LogFile:            cfg.LogFile,
		TTL:                cfg.TTL.String(),
		Cache:              cfg.Cache,
		Recache:            cfg.Recache,
		RecacheAhead:       cfg.RecacheAhead.String(),
		RecacheWorkers:     cfg.RecacheWorkers,
		AgeHeader:          cfg.AgeHeader,
		UseOriginHost:      cfg.UseOriginHost,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		CacheVaryHost:      cfg.CacheVaryHost,
		CacheKeyQuery:      cfg.CacheKeyQuery,
	}

	for _, hc := range cfg.Hosts {
		payload.Hosts = append(payload.Hosts, fileHost{
			Match:              hc.Match,
			Origin:             hc.Origin,
			Cache:              hc.Cache,
			Recache:            hc.Recache,
			TTL:                hc.TTL.String(),
			TLSDomains:         hc.TLSDomains,
			UseOriginHost:      hc.UseOriginHost,
			InsecureSkipVerify: hc.InsecureSkipVerify,
			AgeHeader:          hc.AgeHeader,
		})
	}

	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func setupLogging(path string) (closeFn func()) {
	log.SetFlags(log.LstdFlags)
	log.SetOutput(os.Stdout)
	if strings.TrimSpace(path) == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("log-file open failed (%s): %v", path, err)
		return nil
	}
	log.SetOutput(io.MultiWriter(os.Stdout, f))
	return func() { _ = f.Close() }
}

func runServers(ctx context.Context, cfg config.Config, h *proxy.Handler) error {
	if len(cfg.Hosts) > 0 {
		log.Printf("%s %s starting, hosts=%d, defaultOrigin=%q", version.Project, version.Version, len(cfg.Hosts), cfg.Origin)
	} else {
		log.Printf("%s %s starting, origin=%s", version.Project, version.Version, cfg.Origin)
	}

	var certMgr *autocert.Manager
	if cfg.HTTPSEnabled {
		certDir := filepath.Join(cfg.CacheDir, "certs")
		log.Printf("https enabled: listen=%s, certCache=%s, domains=%s", cfg.HttpsListen, certDir, strings.Join(h.TLSDomains(), ","))
		log.Printf("acme note: ensure external TCP/80 is forwarded to this instance's HTTP listener for HTTP-01 challenges")
		log.Printf("acme note: wildcard domains obtain a separate certificate per subdomain on demand (HTTP-01); a single true wildcard certificate would require DNS-01, which is not supported")

		certMgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(certDir),
			HostPolicy: h.HostPolicy,
		}
	}

	errCh := make(chan error, 3)
	started := 0
	var servers []*http.Server

	if cfg.HTTPEnabled {
		var handler http.Handler = h
		if certMgr != nil {
			// When HTTPS is enabled, use HTTP only for ACME HTTP-01 challenges and redirect everything else.
			handler = certMgr.HTTPHandler(redirectToHTTPSHandler(cfg.HttpsListen))
			log.Printf("http enabled: listen=%s (acme http-01 + redirect to https)", cfg.HttpListen)
		} else {
			log.Printf("http enabled: listen=%s", cfg.HttpListen)
		}
		srv := &http.Server{
			Addr:              cfg.HttpListen,
			Handler:           handler,
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		servers = append(servers, srv)
		started++
		go func() {
			err := srv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("http listen: %w", err)
			}
		}()
	}

	if certMgr != nil {
		httpsSrv := &http.Server{
			Addr:              cfg.HttpsListen,
			Handler:           h,
			TLSConfig:         certMgr.TLSConfig(),
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		servers = append(servers, httpsSrv)
		started++
		log.Printf("https enabled: listen=%s", cfg.HttpsListen)
		go func() {
			err := httpsSrv.ListenAndServeTLS("", "")
			if err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("https listen: %w", err)
			}
		}()
	}

	if started == 0 {
		return fmt.Errorf("no listeners started")
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Printf("shutdown requested: %v", ctx.Err())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, srv := range servers {
			_ = srv.Shutdown(shutdownCtx)
		}
		return nil
	}
}

func redirectToHTTPSHandler(httpsListen string) http.Handler {
	httpsPort := portFromListenAddr(httpsListen)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostWithPort(r.Host, httpsPort)
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

func portFromListenAddr(addr string) string {
	// addr can be "0.0.0.0:443", ":443", "127.0.0.1:8443"
	if addr == "" {
		return "443"
	}
	if strings.HasPrefix(addr, ":") {
		p := strings.TrimPrefix(addr, ":")
		if p != "" {
			return p
		}
		return "443"
	}
	_, p, err := net.SplitHostPort(addr)
	if err == nil && p != "" {
		return p
	}
	return "443"
}

func hostWithPort(hostport string, httpsPort string) string {
	if strings.TrimSpace(hostport) == "" {
		return "localhost"
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	// If caller is already using default https port, omit it.
	if httpsPort == "443" {
		return host
	}
	// Preserve IPv6 bracket formatting if needed.
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + httpsPort
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("proxybuff status", flag.ExitOnError)
	cacheDir := fs.String("cache-dir", "./cache", "cache directory path")
	configPath := fs.String("config", "", "path to JSON config file (optional, to read cache-dir)")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	isCacheDirExplicit := false
	isConfigExplicit := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "cache-dir":
			isCacheDirExplicit = true
		case "config":
			isConfigExplicit = true
		}
	})

	var cfg statusConfig
	// Default behavior: if neither --cache-dir nor --config was provided, try "./config.json"
	// next to the proxybuff binary (best-effort).
	if !isCacheDirExplicit && !isConfigExplicit {
		if exe, err := os.Executable(); err == nil {
			if dir := filepath.Dir(exe); strings.TrimSpace(dir) != "" {
				autoCfg := filepath.Join(dir, "config.json")
				if _, err := os.Stat(autoCfg); err == nil {
					*configPath = autoCfg
				}
			}
		}
	}

	if strings.TrimSpace(*configPath) != "" {
		var err error
		cfg, err = readStatusConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "status: read config: %v\n", err)
			os.Exit(2)
		}

		if !isCacheDirExplicit && strings.TrimSpace(cfg.CacheDir) != "" {
			*cacheDir = cfg.CacheDir
		}
	}

	cd := cache.Disk{Dir: *cacheDir, TTL: 1} // TTL doesn't matter for walking

	var recacheMatchers []cache.Matcher
	if len(cfg.Recache) > 0 {
		recacheMatchers, _ = cache.CompileMatchers(cfg.Recache)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PATH\tSIZE\tCREATED\tEXPIRES\tTTL_LEFT\tRECACHE\tCACHE_FILE")

	count := 0
	totalSize := int64(0)
	now := time.Now()

	err := cd.Walk(func(meta cache.Meta, bodyPath string) error {
		count++
		totalSize += meta.Size

		isRecache := ""
		if len(recacheMatchers) > 0 {
			for _, m := range recacheMatchers {
				if m.Match(meta.Path) {
					isRecache = "YES"
					break
				}
			}
		}

		// Calculate TTL remaining
		ttl := meta.ExpiresAt.Sub(now).Round(time.Second)
		if ttl < 0 {
			ttl = 0
		}

		created := meta.CreatedAt.Format(time.RFC3339)
		expires := meta.ExpiresAt.Format(time.RFC3339)
		cacheFile := bodyPath
		if rel, err := filepath.Rel(cd.Dir, bodyPath); err == nil {
			cacheFile = rel
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			meta.Path,
			byteCountIEC(meta.Size),
			created,
			expires,
			ttl,
			isRecache,
			cacheFile,
		)
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking cache: %v\n", err)
		os.Exit(1)
	}

	w.Flush()
	fmt.Printf("\nTotal: %d files, %s\n", count, byteCountIEC(totalSize))
}

// resolveClearCacheDir applies the shared status/clear cache-dir resolution to
// the parsed flag set: an explicit --cache-dir wins; otherwise --config's
// cacheDir is used; otherwise ./config.json next to the binary is tried. It
// updates *cacheDir in place. cmd is used only for error messages.
func resolveClearCacheDir(fs *flag.FlagSet, cmd string, cacheDir, configPath *string) {
	isCacheDirExplicit := false
	isConfigExplicit := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "cache-dir":
			isCacheDirExplicit = true
		case "config":
			isConfigExplicit = true
		}
	})

	// Default behavior: if neither --cache-dir nor --config was provided, try
	// "./config.json" next to the proxybuff binary (best-effort).
	if !isCacheDirExplicit && !isConfigExplicit {
		if exe, err := os.Executable(); err == nil {
			if dir := filepath.Dir(exe); strings.TrimSpace(dir) != "" {
				autoCfg := filepath.Join(dir, "config.json")
				if _, err := os.Stat(autoCfg); err == nil {
					*configPath = autoCfg
				}
			}
		}
	}

	if strings.TrimSpace(*configPath) != "" {
		cfg, err := readStatusConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: read config: %v\n", cmd, err)
			os.Exit(2)
		}
		if !isCacheDirExplicit && strings.TrimSpace(cfg.CacheDir) != "" {
			*cacheDir = cfg.CacheDir
		}
	}
}

func runClearCache(args []string) {
	fs := flag.NewFlagSet("proxybuff clear-cache", flag.ExitOnError)
	cacheDir := fs.String("cache-dir", "./cache", "cache directory path")
	configPath := fs.String("config", "", "path to JSON config file (optional, to read cache-dir)")
	yes := fs.Bool("yes", false, "skip confirmation and clear immediately")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	resolveClearCacheDir(fs, "clear-cache", cacheDir, configPath)

	cd := cache.Disk{Dir: *cacheDir, TTL: 1} // TTL doesn't matter for clearing

	// Without --yes, report what would be removed and stop (safe, non-interactive).
	if !*yes {
		count := 0
		totalSize := int64(0)
		err := cd.Walk(func(meta cache.Meta, bodyPath string) error {
			count++
			totalSize += meta.Size
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "clear-cache: scan cache: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Would remove %d cached files (%s) from %s\n", count, byteCountIEC(totalSize), *cacheDir)
		fmt.Println("ACME certificates (certs/) are preserved. Re-run with --yes to confirm.")
		return
	}

	deleted, err := cd.ClearCache()
	if err != nil {
		fmt.Fprintf(os.Stderr, "clear-cache: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Cleared %d cached entries from %s (ACME certs preserved)\n", deleted, *cacheDir)
}

func runClearCerts(args []string) {
	fs := flag.NewFlagSet("proxybuff clear-certs", flag.ExitOnError)
	cacheDir := fs.String("cache-dir", "./cache", "cache directory path")
	configPath := fs.String("config", "", "path to JSON config file (optional, to read cache-dir)")
	yes := fs.Bool("yes", false, "skip confirmation and clear immediately")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	resolveClearCacheDir(fs, "clear-certs", cacheDir, configPath)

	cd := cache.Disk{Dir: *cacheDir, TTL: 1} // TTL doesn't matter for clearing
	certsDir := cd.CertsDir()

	// Without --yes, report what would be removed and stop (safe, non-interactive).
	if !*yes {
		entries, err := os.ReadDir(certsDir)
		if err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "clear-certs: scan certs: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Would remove %d ACME cert-cache entries from %s\n", len(entries), certsDir)
		fmt.Println("WARNING: next TLS handshake re-issues certs via ACME (mind the CA rate limits). Re-run with --yes to confirm.")
		return
	}

	deleted, err := cd.ClearCerts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "clear-certs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Cleared %d ACME cert-cache entries from %s (certs re-issue on next handshake)\n", deleted, certsDir)
}

func byteCountIEC(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

type statusConfig struct {
	CacheDir string   `json:"cacheDir"`
	Recache  []string `json:"recache"`
}

func readStatusConfig(path string) (statusConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return statusConfig{}, err
	}
	var cfg statusConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return statusConfig{}, err
	}
	cfg.CacheDir = strings.TrimSpace(cfg.CacheDir)
	return cfg, nil
}
