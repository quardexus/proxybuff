package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quardexus/proxybuff/internal/config"
	"github.com/quardexus/proxybuff/internal/proxy"
	"github.com/quardexus/proxybuff/internal/version"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	args := os.Args[1:]

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

	if err := runServers(cfg, h); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `%s %s (Developed by %s)

Usage:
  proxybuff --origin <url> [--http[=<port|addr>]] [--https[=<port|addr>]] [--cache <pattern>] [--ttl 10m] [--cache-dir ./cache] [--age-header]
  proxybuff --config /path/to/config.json
  proxybuff --version

Flags:
  --origin      Upstream origin URL to proxy (required). You can also pass host[:port] without scheme.
  --listen      DEPRECATED: alias for --http
  --http        HTTP listener: bool to enable/disable, or port/address (e.g. 8080, :8080, 127.0.0.1:8080)
  --https       HTTPS listener: bool to enable/disable, or port/address (e.g. 443, :443, 127.0.0.1:443)
  --cache       Cache path pattern (repeatable). '*' matches any chars including '/'. '/' caches only root path.
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
		Origin             string   `json:"origin"`
		CacheDir           string   `json:"cacheDir"`
		LogFile            string   `json:"logFile"`
		TTL                string   `json:"ttl"`
		Cache              []string `json:"cache"`
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
		Origin:             cfg.Origin,
		CacheDir:           cfg.CacheDir,
		LogFile:            cfg.LogFile,
		TTL:                cfg.TTL.String(),
		Cache:              cfg.Cache,
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

func runServers(cfg config.Config, h http.Handler) error {
	log.Printf("%s %s starting, origin=%s", version.Project, version.Version, cfg.Origin)

	var certMgr *autocert.Manager
	if cfg.HTTPSEnabled {
		certDir := filepath.Join(cfg.CacheDir, "certs")
		log.Printf("https enabled: listen=%s, certCache=%s", cfg.HttpsListen, certDir)
		log.Printf("acme note: Let's Encrypt HTTP-01 requires port 80 reachable for the requested domain")

		certMgr = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(certDir),
			HostPolicy: func(ctx context.Context, host string) error {
				host = strings.TrimSpace(host)
				if host == "" {
					return fmt.Errorf("acme: empty host")
				}
				// refuse IP hosts (LE won't issue for IPs)
				h := host
				if strings.Contains(h, ":") {
					h, _, _ = net.SplitHostPort(host)
				}
				if net.ParseIP(h) != nil {
					return fmt.Errorf("acme: refusing IP host %q", host)
				}
				log.Printf("acme: certificate requested for host=%s", host)
				return nil
			},
		}
	}

	errCh := make(chan error, 3)
	started := 0

	if cfg.HTTPEnabled {
		handler := h
		if certMgr != nil {
			handler = certMgr.HTTPHandler(handler)
		}
		srv := &http.Server{Addr: cfg.HttpListen, Handler: handler}
		started++
		log.Printf("http enabled: listen=%s", cfg.HttpListen)
		go func() {
			err := srv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("http listen: %w", err)
			}
		}()
	}

	if certMgr != nil {
		// Ensure HTTP-01 challenge is served on :80 unless HTTP is already bound to port 80.
		if !cfg.HTTPEnabled || !isPort(cfg.HttpListen, "80") {
			acmeSrv := &http.Server{
				Addr:              ":80",
				Handler:           certMgr.HTTPHandler(nil),
				ReadHeaderTimeout: 5 * time.Second,
			}
			started++
			log.Printf("acme http-01 challenge listener: listen=:80")
			go func() {
				err := acmeSrv.ListenAndServe()
				if err != nil && err != http.ErrServerClosed {
					errCh <- fmt.Errorf("acme http-01 listen: %w", err)
				}
			}()
		}

		httpsSrv := &http.Server{
			Addr:              cfg.HttpsListen,
			Handler:           h,
			TLSConfig:         certMgr.TLSConfig(),
			ReadHeaderTimeout: 15 * time.Second,
		}
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

	return <-errCh
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
