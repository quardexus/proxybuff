package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/quardexus/proxybuff/internal/config"
	"github.com/quardexus/proxybuff/internal/proxy"
	"github.com/quardexus/proxybuff/internal/version"
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

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: h,
	}

	log.Printf("%s %s listening on %s, origin=%s", version.Project, version.Version, cfg.Listen, cfg.Origin)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `%s %s (Developed by %s)

Usage:
  proxybuff --origin <url> [--listen 0.0.0.0:3128] [--cache <pattern>] [--ttl 10m] [--cache-dir ./cache] [--age-header]
  proxybuff --config /path/to/config.json
  proxybuff --version

Flags:
  --origin      Upstream origin URL to proxy (required). You can also pass host[:port] without scheme (defaults to http).
  --listen      Listen address (host:port), default 0.0.0.0:3128
  --cache       Cache path pattern (repeatable). '*' matches any chars including '/'. '/' caches only root path.
  --ttl         Cache TTL duration (default 10m)
  --cache-dir   Cache directory path (default ./cache)
  --age-header  Add standard Age header on cache HIT (optional)
  --use-origin-host  Send Host header from --origin (default: forward original client Host)
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
		Listen        string   `json:"listen"`
		Origin        string   `json:"origin"`
		CacheDir      string   `json:"cacheDir"`
		TTL           string   `json:"ttl"`
		Cache         []string `json:"cache"`
		AgeHeader     bool     `json:"ageHeader"`
		UseOriginHost bool     `json:"useOriginHost"`
	}

	payload := fileCfg{
		Listen:        cfg.Listen,
		Origin:        cfg.Origin,
		CacheDir:      cfg.CacheDir,
		TTL:           cfg.TTL.String(),
		Cache:         cfg.Cache,
		AgeHeader:     cfg.AgeHeader,
		UseOriginHost: cfg.UseOriginHost,
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
