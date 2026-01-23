package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Listen    string        `json:"listen"`
	Origin    string        `json:"origin"`
	CacheDir  string        `json:"cacheDir"`
	TTL       time.Duration `json:"ttl"`
	Cache     []string      `json:"cache"`
	AgeHeader bool          `json:"ageHeader"`
}

func Default() Config {
	return Config{
		Listen:   "0.0.0.0:3128",
		CacheDir: "./cache",
		TTL:      10 * time.Minute,
		Cache:    nil,
	}
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Origin) == "" {
		return errors.New("origin is required")
	}
	if strings.TrimSpace(c.Listen) == "" {
		return errors.New("listen is required")
	}
	if strings.TrimSpace(c.CacheDir) == "" {
		return errors.New("cacheDir is required")
	}
	if c.TTL <= 0 {
		return errors.New("ttl must be > 0")
	}
	return nil
}

// Parse reads configuration from flags, optionally from a JSON config file.
// Unknown JSON keys are rejected.
func Parse(args []string) (Config, error) {
	cfg := Default()

	fs := flag.NewFlagSet("proxybuff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		configPath string
		origin     string
		listen     string
		cacheDir   string
		ttl        time.Duration
		ageHeader  bool
		cacheMulti multiString
	)

	fs.StringVar(&configPath, "config", "", "path to JSON config file")
	fs.StringVar(&origin, "origin", "", "upstream origin URL to proxy (required), e.g. https://example.com")
	fs.StringVar(&listen, "listen", cfg.Listen, "listen address (host:port)")
	fs.StringVar(&cacheDir, "cache-dir", cfg.CacheDir, "cache directory path")
	fs.DurationVar(&ttl, "ttl", cfg.TTL, "cache TTL duration, e.g. 10m, 1h")
	fs.BoolVar(&ageHeader, "age-header", false, "add standard Age header on cache HIT")
	fs.Var(&cacheMulti, "cache", "cache path patterns (repeatable). '*' matches any chars including '/'. '/' caches only root path.")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	// Load config file first (if provided), then override with flags.
	if configPath != "" {
		fileCfg, err := readConfigFile(configPath)
		if err != nil {
			return Config{}, err
		}
		cfg = fileCfg
	}

	// Override from flags (only when explicitly provided).
	if origin != "" {
		cfg.Origin = origin
	}
	if listen != "" {
		cfg.Listen = listen
	}
	if cacheDir != "" {
		cfg.CacheDir = cacheDir
	}
	if ttl != 0 {
		cfg.TTL = ttl
	}
	if ageHeader {
		cfg.AgeHeader = true
	}
	if len(cacheMulti.items) > 0 {
		cfg.Cache = normalizeCachePatterns(cacheMulti.items)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type multiString struct {
	items []string
}

func (m *multiString) String() string {
	return strings.Join(m.items, ",")
}

func (m *multiString) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	m.items = append(m.items, v)
	return nil
}

func normalizeCachePatterns(in []string) []string {
	var out []string
	for _, v := range in {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

func readConfigFile(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var raw struct {
		Listen    *string  `json:"listen"`
		Origin    *string  `json:"origin"`
		CacheDir  *string  `json:"cacheDir"`
		TTL       *string  `json:"ttl"`
		Cache     []string `json:"cache"`
		AgeHeader *bool    `json:"ageHeader"`
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("parse config JSON: %w", err)
	}

	cfg := Default()
	if raw.Listen != nil {
		cfg.Listen = *raw.Listen
	}
	if raw.Origin != nil {
		cfg.Origin = *raw.Origin
	}
	if raw.CacheDir != nil {
		cfg.CacheDir = *raw.CacheDir
	}
	if raw.TTL != nil {
		d, err := time.ParseDuration(*raw.TTL)
		if err != nil {
			return Config{}, fmt.Errorf("parse ttl: %w", err)
		}
		cfg.TTL = d
	}
	if raw.Cache != nil {
		cfg.Cache = normalizeCachePatterns(raw.Cache)
	}
	if raw.AgeHeader != nil {
		cfg.AgeHeader = *raw.AgeHeader
	}
	return cfg, nil
}
