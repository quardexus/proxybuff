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
  proxybuff status [--cache-dir ./cache] [--config /path/to/config.json]
  proxybuff --version

Commands:
  status        Show cache statistics and list cached files

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
	type fileCfg struct {
		Listen             string   `json:"listen"`
		HTTPEnabled        bool     `json:"httpEnabled"`
		HttpListen         string   `json:"httpListen"`
		HTTPSEnabled       bool     `json:"httpsEnabled"`
		HttpsListen        string   `json:"httpsListen"`
		TLSDomains         []string `json:"tlsDomains"`
		Origin             string   `json:"origin"`
		CacheDir           string   `json:"cacheDir"`
		LogFile            string   `json:"logFile"`
		TTL                string   `json:"ttl"`
		Cache              []string `json:"cache"`
		Recache            []string `json:"recache"`
		RecacheAhead       string   `json:"recacheAhead"`
		RecacheWorkers     int      `json:"recacheWorkers"`
		AgeHeader          bool     `json:"ageHeader"`
		UseOriginHost      bool     `json:"useOriginHost"`
		InsecureSkipVerify bool     `json:"insecureSkipVerify"`
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

func runServers(ctx context.Context, cfg config.Config, h http.Handler) error {
	log.Printf("%s %s starting, origin=%s", version.Project, version.Version, cfg.Origin)

	var certMgr *autocert.Manager
	if cfg.HTTPSEnabled {
		certDir := filepath.Join(cfg.CacheDir, "certs")
		log.Printf("https enabled: listen=%s, certCache=%s, domains=%s", cfg.HttpsListen, certDir, strings.Join(cfg.TLSDomains, ","))
		log.Printf("acme note: ensure external TCP/80 is forwarded to this instance's HTTP listener for HTTP-01 challenges")

		certMgr = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(certDir),
			HostPolicy: autocert.HostWhitelist(cfg.TLSDomains...),
		}
	}

	errCh := make(chan error, 3)
	started := 0
	var servers []*http.Server

	if cfg.HTTPEnabled {
		handler := h
		if certMgr != nil {
			// When HTTPS is enabled, use HTTP only for ACME HTTP-01 challenges and redirect everything else.
			handler = certMgr.HTTPHandler(redirectToHTTPSHandler(cfg.HttpsListen))
			log.Printf("http enabled: listen=%s (acme http-01 + redirect to https)", cfg.HttpListen)
		} else {
			log.Printf("http enabled: listen=%s", cfg.HttpListen)
		}
		srv := &http.Server{Addr: cfg.HttpListen, Handler: handler}
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

func isPort(addr, port string) bool {
	_, p, err := net.SplitHostPort(addr)
	if err == nil {
		return p == port
	}
	// allow ":80"
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":") == port
	}
	return false
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("proxybuff status", flag.ExitOnError)
	cacheDir := fs.String("cache-dir", "./cache", "cache directory path")
	configPath := fs.String("config", "", "path to JSON config file (optional, to read cache-dir)")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	var cfg statusConfig
	if *configPath != "" {
		var err error
		cfg, err = readStatusConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "status: read config: %v\n", err)
			os.Exit(2)
		}

		isExplicit := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "cache-dir" {
				isExplicit = true
			}
		})
		if !isExplicit && strings.TrimSpace(cfg.CacheDir) != "" {
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
