package config

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Deprecated: use HttpListen/HttpEnabled.
	Listen string `json:"listen"`

	HTTPEnabled bool   `json:"httpEnabled"`
	HttpListen  string `json:"httpListen"`

	HTTPSEnabled bool   `json:"httpsEnabled"`
	HttpsListen  string `json:"httpsListen"`

	Origin             string        `json:"origin"`
	CacheDir           string        `json:"cacheDir"`
	TTL                time.Duration `json:"ttl"`
	Cache              []string      `json:"cache"`
	AgeHeader          bool          `json:"ageHeader"`
	UseOriginHost      bool          `json:"useOriginHost"`
	InsecureSkipVerify bool          `json:"insecureSkipVerify"`

	LogFile string `json:"logFile"`
}

func Default() Config {
	return Config{
		HTTPEnabled: true,
		HttpListen:  "0.0.0.0:3128",
		CacheDir:    "./cache",
		TTL:         10 * time.Minute,
		Cache:       nil,
	}
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Origin) == "" {
		return errors.New("origin is required")
	}
	if !c.HTTPEnabled && !c.HTTPSEnabled {
		return errors.New("at least one listener must be enabled (http or https)")
	}
	if c.HTTPEnabled && strings.TrimSpace(c.HttpListen) == "" {
		return errors.New("httpListen is required when http is enabled")
	}
	if c.HTTPSEnabled && strings.TrimSpace(c.HttpsListen) == "" {
		return errors.New("httpsListen is required when https is enabled")
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
		configPath    string
		origin        string
		listen        string
		httpListen    string
		httpsListen   string
		httpEnabled   boolFlag
		httpsEnabled  boolFlag
		cacheDir      string
		logFile       string
		ttl           time.Duration
		ageHeader     bool
		useOriginHost bool
		insecureTLS   boolFlag
		cacheMulti    multiString
		fileExplicit  fileExplicit
	)

	fs.StringVar(&configPath, "config", "", "path to JSON config file")
	fs.StringVar(&origin, "origin", "", "upstream origin URL to proxy (required), e.g. https://example.com")
	fs.StringVar(&listen, "listen", "", "DEPRECATED: alias for --http-listen")
	fs.StringVar(&httpListen, "http-listen", cfg.HttpListen, "HTTP listen address (host:port), empty disables HTTP")
	fs.StringVar(&httpsListen, "https-listen", "", "HTTPS listen address (host:port), empty disables HTTPS")
	fs.Var(&httpEnabled, "http", "enable/disable HTTP listener (default true)")
	fs.Var(&httpsEnabled, "https", "enable/disable HTTPS listener (default false)")
	fs.StringVar(&cacheDir, "cache-dir", cfg.CacheDir, "cache directory path")
	fs.StringVar(&logFile, "log-file", "", "optional log file path (also logs to stdout)")
	fs.DurationVar(&ttl, "ttl", cfg.TTL, "cache TTL duration, e.g. 10m, 1h")
	fs.BoolVar(&ageHeader, "age-header", false, "add standard Age header on cache HIT")
	fs.BoolVar(&useOriginHost, "use-origin-host", false, "send Host header from --origin (default: forward the original client Host)")
	fs.Var(&insecureTLS, "insecure-skip-verify", "skip TLS certificate verification for https origins (dangerous)")
	fs.Var(&cacheMulti, "cache", "cache path patterns (repeatable). '*' matches any chars including '/'. '/' caches only root path.")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	// Load config file first (if provided), then override with flags.
	if configPath != "" {
		fileCfg, exp, err := readConfigFile(configPath)
		if err != nil {
			return Config{}, err
		}
		cfg = fileCfg
		fileExplicit = exp
	}

	// Override from flags (only when explicitly provided).
	if origin != "" {
		cfg.Origin = origin
	}
	if listen != "" && httpListen == cfg.HttpListen {
		// deprecated --listen provided; treat it as http listen
		httpListen = listen
	}
	// If user explicitly passes an empty http-listen, it disables HTTP.
	if httpListen == "" {
		cfg.HttpListen = ""
	} else {
		cfg.HttpListen = httpListen
	}
	if httpsListen != "" {
		cfg.HttpsListen = httpsListen
	}
	if httpEnabled.set {
		cfg.HTTPEnabled = httpEnabled.v
	}
	if httpsEnabled.set {
		cfg.HTTPSEnabled = httpsEnabled.v
	}
	if cacheDir != "" {
		cfg.CacheDir = cacheDir
	}
	if logFile != "" {
		cfg.LogFile = logFile
	}
	if ttl != 0 {
		cfg.TTL = ttl
	}
	if ageHeader {
		cfg.AgeHeader = true
	}
	if useOriginHost {
		cfg.UseOriginHost = true
	}
	if insecureTLS.set {
		cfg.InsecureSkipVerify = insecureTLS.v
	}
	if len(cacheMulti.items) > 0 {
		cfg.Cache = normalizeCachePatterns(cacheMulti.items)
	}

	normalizeOriginAndTLSDefaults(&cfg, fileExplicit.insecureSkipVerifySet || insecureTLS.set)

	// Default enablement behavior:
	// - If httpsListen is provided, enable HTTPS.
	// - If httpListen is empty, disable HTTP.
	if cfg.HttpsListen != "" && !httpsEnabled.set {
		cfg.HTTPSEnabled = true
	}
	if cfg.HttpListen == "" && !httpEnabled.set {
		cfg.HTTPEnabled = false
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

type fileExplicit struct {
	insecureSkipVerifySet bool
}

func readConfigFile(path string) (Config, fileExplicit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fileExplicit{}, fmt.Errorf("read config: %w", err)
	}
	var raw struct {
		Listen             *string  `json:"listen"`
		HTTPEnabled        *bool    `json:"httpEnabled"`
		HttpListen         *string  `json:"httpListen"`
		HTTPSEnabled       *bool    `json:"httpsEnabled"`
		HttpsListen        *string  `json:"httpsListen"`
		Origin             *string  `json:"origin"`
		CacheDir           *string  `json:"cacheDir"`
		LogFile            *string  `json:"logFile"`
		TTL                *string  `json:"ttl"`
		Cache              []string `json:"cache"`
		AgeHeader          *bool    `json:"ageHeader"`
		UseOriginHost      *bool    `json:"useOriginHost"`
		InsecureSkipVerify *bool    `json:"insecureSkipVerify"`
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fileExplicit{}, fmt.Errorf("parse config JSON: %w", err)
	}

	cfg := Default()
	if raw.Listen != nil {
		cfg.Listen = *raw.Listen
	}
	if raw.HTTPEnabled != nil {
		cfg.HTTPEnabled = *raw.HTTPEnabled
	}
	if raw.HttpListen != nil {
		cfg.HttpListen = *raw.HttpListen
	}
	if raw.HTTPSEnabled != nil {
		cfg.HTTPSEnabled = *raw.HTTPSEnabled
	}
	if raw.HttpsListen != nil {
		cfg.HttpsListen = *raw.HttpsListen
	}
	if raw.Origin != nil {
		cfg.Origin = *raw.Origin
	}
	if raw.CacheDir != nil {
		cfg.CacheDir = *raw.CacheDir
	}
	if raw.LogFile != nil {
		cfg.LogFile = *raw.LogFile
	}
	if raw.TTL != nil {
		d, err := time.ParseDuration(*raw.TTL)
		if err != nil {
			return Config{}, fileExplicit{}, fmt.Errorf("parse ttl: %w", err)
		}
		cfg.TTL = d
	}
	if raw.Cache != nil {
		cfg.Cache = normalizeCachePatterns(raw.Cache)
	}
	if raw.AgeHeader != nil {
		cfg.AgeHeader = *raw.AgeHeader
	}
	if raw.UseOriginHost != nil {
		cfg.UseOriginHost = *raw.UseOriginHost
	}
	exp := fileExplicit{}
	if raw.InsecureSkipVerify != nil {
		cfg.InsecureSkipVerify = *raw.InsecureSkipVerify
		exp.insecureSkipVerifySet = true
	}
	normalizeOriginAndTLSDefaults(&cfg, exp.insecureSkipVerifySet)

	// Back-compat: if legacy listen was set in config file, treat it as HttpListen.
	if cfg.HttpListen == "" && cfg.Listen != "" {
		cfg.HttpListen = cfg.Listen
		cfg.HTTPEnabled = true
	}
	return cfg, exp, nil
}

// normalizeOriginAndTLSDefaults allows passing host[:port][/basepath] without a scheme.
// Rules:
// - If scheme is omitted and host is an IP, we probe the port once to detect TLS:
//   - if TLS handshake succeeds, scheme becomes https (and InsecureSkipVerify defaults to true unless explicitly set)
//   - otherwise scheme becomes http
//
// - If scheme is omitted and host is not an IP, default scheme becomes http.
func normalizeOriginAndTLSDefaults(cfg *Config, insecureSkipVerifyExplicit bool) {
	origin := strings.TrimSpace(cfg.Origin)
	cfg.Origin = origin
	if origin == "" {
		return
	}
	if strings.Contains(origin, "://") {
		return
	}

	hostport := origin
	if i := strings.Index(hostport, "/"); i >= 0 {
		hostport = hostport[:i]
	}
	host := hostport
	port := ""
	// Strip port for IPv4/hostname.
	if strings.HasPrefix(host, "[") {
		if j := strings.Index(host, "]"); j > 1 {
			host = host[1:j]
		}
	} else if strings.Count(host, ":") == 1 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else {
			// net.SplitHostPort requires port; fallback
			host = strings.SplitN(host, ":", 2)[0]
		}
	}
	// Extract port if explicitly present.
	if strings.HasPrefix(hostport, "[") {
		if h, p, err := net.SplitHostPort(hostport); err == nil {
			host = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
			port = p
		}
	} else if strings.Count(hostport, ":") == 1 {
		if _, p, err := net.SplitHostPort(hostport); err == nil {
			port = p
		} else {
			// fallback
			if parts := strings.SplitN(hostport, ":", 2); len(parts) == 2 {
				port = parts[1]
			}
		}
	}
	if port == "" {
		port = "80"
	}

	if net.ParseIP(host) != nil {
		if probeTLS(host, port) {
			cfg.Origin = "https://" + origin
			if !insecureSkipVerifyExplicit {
				cfg.InsecureSkipVerify = true
			}
		} else {
			cfg.Origin = "http://" + origin
		}
		return
	}

	cfg.Origin = "http://" + origin
}

func probeTLS(host, port string) bool {
	addr := net.JoinHostPort(host, port)
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	err = tlsConn.Handshake()
	_ = tlsConn.Close()
	return err == nil
}

type boolFlag struct {
	v   bool
	set bool
}

func (b *boolFlag) String() string { return strconv.FormatBool(b.v) }
func (b *boolFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	b.v = v
	b.set = true
	return nil
}
func (b *boolFlag) IsBoolFlag() bool { return true }
