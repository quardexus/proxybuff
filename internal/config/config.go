// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package config

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
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

	TLSDomains []string `json:"tlsDomains"`

	Origin             string        `json:"origin"`
	CacheDir           string        `json:"cacheDir"`
	TTL                time.Duration `json:"ttl"`
	Cache              []string      `json:"cache"`
	Recache            []string      `json:"recache"`
	RecacheAhead       time.Duration `json:"recacheAhead"`
	RecacheWorkers     int           `json:"recacheWorkers"`
	AgeHeader          bool          `json:"ageHeader"`
	UseOriginHost      bool          `json:"useOriginHost"`
	InsecureSkipVerify bool          `json:"insecureSkipVerify"`

	// CacheVaryHost includes the request Host in the cache key (on by default).
	CacheVaryHost bool `json:"cacheVaryHost"`
	// CacheKeyQuery includes the query string in the cache key (on by default).
	CacheKeyQuery bool `json:"cacheKeyQuery"`

	// Hosts, when non-empty, enables multi-host routing. Each entry serves its
	// matching domains from its own origin/cache settings; omitted fields are
	// inherited from the top-level defaults above. When empty, ProxyBuff behaves
	// exactly as a single-origin proxy (backward compatible).
	Hosts []HostConfig `json:"hosts,omitempty"`

	LogFile string `json:"logFile"`
}

// HostConfig is a fully-resolved per-host routing target. It is produced by
// merging a config-file "hosts[]" entry with the top-level defaults.
type HostConfig struct {
	Match              []string
	Origin             string
	Cache              []string
	Recache            []string
	TTL                time.Duration
	TLSDomains         []string
	UseOriginHost      bool
	InsecureSkipVerify bool
	AgeHeader          bool
}

func Default() Config {
	return Config{
		HTTPEnabled:    true,
		HttpListen:     "0.0.0.0:3128",
		CacheDir:       "./cache",
		TTL:            10 * time.Minute,
		Cache:          nil,
		Recache:        nil,
		RecacheAhead:   5 * time.Minute,
		RecacheWorkers: 4,
		CacheVaryHost:  true,
		CacheKeyQuery:  true,
	}
}

func (c *Config) Validate() error {
	if len(c.Hosts) == 0 {
		if strings.TrimSpace(c.Origin) == "" {
			return errors.New("origin is required")
		}
	} else {
		for i := range c.Hosts {
			h := &c.Hosts[i]
			if len(h.Match) == 0 {
				return fmt.Errorf("hosts[%d]: match is required (at least one domain)", i)
			}
			if strings.TrimSpace(h.Origin) == "" {
				return fmt.Errorf("hosts[%d] (%s): origin is required (set it on the host or provide a top-level origin to inherit)", i, h.Match[0])
			}
			if h.TTL <= 0 {
				return fmt.Errorf("hosts[%d] (%s): ttl must be > 0", i, h.Match[0])
			}
		}
	}
	if !c.HTTPEnabled {
		return errors.New("http listener cannot be disabled")
	}
	if c.HTTPEnabled && strings.TrimSpace(c.HttpListen) == "" {
		return errors.New("httpListen is required when http is enabled")
	}
	if c.HTTPSEnabled && strings.TrimSpace(c.HttpsListen) == "" {
		return errors.New("httpsListen is required when https is enabled")
	}
	if c.HTTPSEnabled && c.totalTLSDomains() == 0 {
		return errors.New("tlsDomains is required when https is enabled (use --tls-domain or set tlsDomains per host)")
	}
	if strings.TrimSpace(c.CacheDir) == "" {
		return errors.New("cacheDir is required")
	}
	if c.TTL <= 0 {
		return errors.New("ttl must be > 0")
	}
	if c.RecacheAhead < 0 {
		return errors.New("recacheAhead must be >= 0")
	}
	if c.RecacheWorkers < 0 {
		return errors.New("recacheWorkers must be >= 0")
	}
	return nil
}

func (c *Config) totalTLSDomains() int {
	n := len(c.TLSDomains)
	for i := range c.Hosts {
		n += len(c.Hosts[i].TLSDomains)
	}
	return n
}

// Parse reads configuration from flags, optionally from a JSON config file.
// Unknown JSON keys are rejected.
func Parse(args []string) (Config, error) {
	cfg := Default()

	fs := flag.NewFlagSet("proxybuff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		configPath     string
		origin         string
		listen         string
		httpEnabled    bool
		httpListen     string
		httpsEnabled   bool
		httpsListen    string
		httpFlag       listenFlag
		httpsFlag      listenFlag
		cacheDir       string
		logFile        string
		ttl            time.Duration
		recacheAhead   time.Duration
		recacheWorkers int
		ageHeader      bool
		useOriginHost  bool
		insecureTLS    boolFlag
		cacheVaryHost  bool
		cacheKeyQuery  bool
		cacheMulti     multiString
		recacheMulti   multiString
		tlsDomainMulti multiString
		fileExplicit   fileExplicit
	)

	httpEnabled = cfg.HTTPEnabled
	httpListen = cfg.HttpListen
	httpsEnabled = cfg.HTTPSEnabled
	httpsListen = cfg.HttpsListen

	fs.StringVar(&configPath, "config", "", "path to JSON config file")
	fs.StringVar(&origin, "origin", "", "upstream origin URL to proxy (required), e.g. https://example.com")
	fs.StringVar(&listen, "listen", "", "DEPRECATED: alias for --http")
	httpFlag = newListenFlag(&httpEnabled, &httpListen, "0.0.0.0:3128", "3128", false)
	httpsFlag = newListenFlag(&httpsEnabled, &httpsListen, "0.0.0.0:443", "443", true)
	fs.Var(&httpFlag, "http", "HTTP listener (required for ACME HTTP-01 + redirects): port/address (e.g. 8080, :8080, 127.0.0.1:8080)")
	fs.Var(&httpsFlag, "https", "HTTPS listener: bool to enable/disable, or port/address (e.g. 443, :443, 127.0.0.1:443)")
	fs.Var(&tlsDomainMulti, "tls-domain", "TLS domain(s) for ACME certificates when HTTPS is enabled (repeatable or comma-separated)")
	fs.StringVar(&cacheDir, "cache-dir", cfg.CacheDir, "cache directory path")
	fs.StringVar(&logFile, "log-file", "", "optional log file path (also logs to stdout)")
	fs.DurationVar(&ttl, "ttl", cfg.TTL, "cache TTL duration, e.g. 10m, 1h")
	fs.Var(&recacheMulti, "recache", "auto-refresh cached path patterns (repeatable). When an entry is close to expiry, ProxyBuff refreshes it in the background.")
	fs.DurationVar(&recacheAhead, "recache-ahead", cfg.RecacheAhead, "how long before expiry to trigger background refresh (default 5m)")
	fs.IntVar(&recacheWorkers, "recache-workers", cfg.RecacheWorkers, "max concurrent background refresh workers (default 4)")
	fs.BoolVar(&ageHeader, "age-header", false, "add standard Age header on cache HIT")
	fs.BoolVar(&useOriginHost, "use-origin-host", false, "send Host header from --origin (default: forward the original client Host)")
	fs.Var(&insecureTLS, "insecure-skip-verify", "skip TLS certificate verification for https origins (dangerous)")
	fs.Var(&cacheMulti, "cache", "cache path patterns (repeatable). '*' matches any chars including '/'. '/' caches only root path.")
	fs.BoolVar(&cacheVaryHost, "cache-vary-host", cfg.CacheVaryHost, "include the request Host in the cache key (default true; disable with --cache-vary-host=false)")
	fs.BoolVar(&cacheKeyQuery, "cache-key-query", cfg.CacheKeyQuery, "include the query string in the cache key (default true; disable with --cache-key-query=false)")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

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
	if visited["origin"] {
		cfg.Origin = origin
	}
	if visited["listen"] {
		// deprecated --listen provided; treat it as --http=<value>
		_ = httpFlag.Set(listen)
	}
	if httpFlag.explicitlySet {
		cfg.HTTPEnabled = httpEnabled
		cfg.HttpListen = httpListen
	}
	if httpsFlag.explicitlySet {
		cfg.HTTPSEnabled = httpsEnabled
		cfg.HttpsListen = httpsListen
	}
	if visited["cache-dir"] {
		cfg.CacheDir = cacheDir
	}
	if visited["log-file"] {
		cfg.LogFile = logFile
	}
	if visited["ttl"] {
		cfg.TTL = ttl
	}
	if visited["recache"] {
		cfg.Recache = normalizeCachePatterns(recacheMulti.items)
	}
	if visited["recache-ahead"] {
		cfg.RecacheAhead = recacheAhead
	}
	if visited["recache-workers"] {
		cfg.RecacheWorkers = recacheWorkers
	}
	if visited["age-header"] {
		cfg.AgeHeader = ageHeader
	}
	if visited["use-origin-host"] {
		cfg.UseOriginHost = useOriginHost
	}
	if insecureTLS.set {
		cfg.InsecureSkipVerify = insecureTLS.v
	}
	if visited["tls-domain"] {
		cfg.TLSDomains = normalizeCachePatterns(tlsDomainMulti.items)
	}
	if visited["cache"] {
		cfg.Cache = normalizeCachePatterns(cacheMulti.items)
	}
	if visited["cache-vary-host"] {
		cfg.CacheVaryHost = cacheVaryHost
	}
	if visited["cache-key-query"] {
		cfg.CacheKeyQuery = cacheKeyQuery
	}

	// Ensure recache patterns are also cached.
	cfg.Cache = mergeUnique(cfg.Cache, cfg.Recache)

	normalizeOriginAndTLSDefaults(&cfg, fileExplicit.insecureSkipVerifySet || insecureTLS.set)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func mergeUnique(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
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
		Listen             *string   `json:"listen"`
		HTTPEnabled        *bool     `json:"httpEnabled"`
		HttpListen         *string   `json:"httpListen"`
		HTTPSEnabled       *bool     `json:"httpsEnabled"`
		HttpsListen        *string   `json:"httpsListen"`
		TLSDomains         []string  `json:"tlsDomains"`
		Origin             *string   `json:"origin"`
		CacheDir           *string   `json:"cacheDir"`
		LogFile            *string   `json:"logFile"`
		TTL                *string   `json:"ttl"`
		Cache              []string  `json:"cache"`
		Recache            []string  `json:"recache"`
		RecacheAhead       *string   `json:"recacheAhead"`
		RecacheWorkers     *int      `json:"recacheWorkers"`
		AgeHeader          *bool     `json:"ageHeader"`
		UseOriginHost      *bool     `json:"useOriginHost"`
		InsecureSkipVerify *bool     `json:"insecureSkipVerify"`
		CacheVaryHost      *bool     `json:"cacheVaryHost"`
		CacheKeyQuery      *bool     `json:"cacheKeyQuery"`
		Hosts              []rawHost `json:"hosts"`
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
	if raw.TLSDomains != nil {
		cfg.TLSDomains = normalizeCachePatterns(raw.TLSDomains)
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
	if raw.Recache != nil {
		cfg.Recache = normalizeCachePatterns(raw.Recache)
	}
	if raw.RecacheAhead != nil {
		d, err := time.ParseDuration(*raw.RecacheAhead)
		if err != nil {
			return Config{}, fileExplicit{}, fmt.Errorf("parse recacheAhead: %w", err)
		}
		cfg.RecacheAhead = d
	}
	if raw.RecacheWorkers != nil {
		cfg.RecacheWorkers = *raw.RecacheWorkers
	}
	if raw.AgeHeader != nil {
		cfg.AgeHeader = *raw.AgeHeader
	}
	if raw.UseOriginHost != nil {
		cfg.UseOriginHost = *raw.UseOriginHost
	}
	if raw.CacheVaryHost != nil {
		cfg.CacheVaryHost = *raw.CacheVaryHost
	}
	if raw.CacheKeyQuery != nil {
		cfg.CacheKeyQuery = *raw.CacheKeyQuery
	}
	exp := fileExplicit{}
	if raw.InsecureSkipVerify != nil {
		cfg.InsecureSkipVerify = *raw.InsecureSkipVerify
		exp.insecureSkipVerifySet = true
	}
	normalizeOriginAndTLSDefaults(&cfg, exp.insecureSkipVerifySet)

	// Ensure recache patterns are also cached.
	cfg.Cache = mergeUnique(cfg.Cache, cfg.Recache)

	// Back-compat: if legacy listen was set in config file, treat it as HttpListen.
	if cfg.HttpListen == "" && cfg.Listen != "" {
		cfg.HttpListen = cfg.Listen
		cfg.HTTPEnabled = true
	}

	// Resolve multi-host entries, inheriting from the (already-normalized) top-level defaults.
	for _, rh := range raw.Hosts {
		hc, err := resolveHost(rh, cfg)
		if err != nil {
			return Config{}, fileExplicit{}, err
		}
		cfg.Hosts = append(cfg.Hosts, hc)
	}

	return cfg, exp, nil
}

// rawHost is the on-disk shape of a "hosts[]" entry. Pointer/slice fields
// distinguish "not set" (inherit the top-level default) from an explicit value.
type rawHost struct {
	Match              []string `json:"match"`
	Origin             *string  `json:"origin"`
	Cache              []string `json:"cache"`
	Recache            []string `json:"recache"`
	TTL                *string  `json:"ttl"`
	TLSDomains         []string `json:"tlsDomains"`
	UseOriginHost      *bool    `json:"useOriginHost"`
	InsecureSkipVerify *bool    `json:"insecureSkipVerify"`
	AgeHeader          *bool    `json:"ageHeader"`
}

// resolveHost merges a raw host entry with the top-level defaults into a fully
// resolved HostConfig.
func resolveHost(rh rawHost, base Config) (HostConfig, error) {
	hc := HostConfig{
		Match:              normalizeCachePatterns(rh.Match),
		Cache:              normalizeCachePatterns(rh.Cache),
		Recache:            normalizeCachePatterns(rh.Recache),
		TLSDomains:         normalizeCachePatterns(rh.TLSDomains),
		TTL:                base.TTL,
		UseOriginHost:      base.UseOriginHost,
		AgeHeader:          base.AgeHeader,
		InsecureSkipVerify: base.InsecureSkipVerify,
	}

	if rh.Origin != nil && strings.TrimSpace(*rh.Origin) != "" {
		norm, tlsIP := normalizeOrigin(*rh.Origin)
		hc.Origin = norm
		if rh.InsecureSkipVerify == nil && tlsIP {
			hc.InsecureSkipVerify = true
		}
	} else {
		// Inherit the top-level origin (already normalized).
		hc.Origin = base.Origin
	}

	if rh.TTL != nil {
		d, err := time.ParseDuration(*rh.TTL)
		if err != nil {
			return HostConfig{}, fmt.Errorf("parse host ttl: %w", err)
		}
		hc.TTL = d
	}
	if rh.UseOriginHost != nil {
		hc.UseOriginHost = *rh.UseOriginHost
	}
	if rh.AgeHeader != nil {
		hc.AgeHeader = *rh.AgeHeader
	}
	if rh.InsecureSkipVerify != nil {
		hc.InsecureSkipVerify = *rh.InsecureSkipVerify
	}

	// Inherit caching rules from the top-level when the host omits them.
	if len(hc.Cache) == 0 {
		hc.Cache = base.Cache
	}
	if len(hc.Recache) == 0 {
		hc.Recache = base.Recache
	}
	hc.Cache = mergeUnique(hc.Cache, hc.Recache)

	// Default the host's TLS domains to its concrete (non-wildcard) match entries.
	if len(hc.TLSDomains) == 0 {
		hc.TLSDomains = exactMatchHosts(hc.Match)
	}

	return hc, nil
}

// exactMatchHosts returns the non-wildcard entries of a match list.
func exactMatchHosts(match []string) []string {
	var out []string
	for _, m := range match {
		if !strings.HasPrefix(m, "*.") {
			out = append(out, m)
		}
	}
	return out
}

// normalizeOriginAndTLSDefaults allows passing host[:port][/basepath] without a scheme.
// Rules:
// - If scheme is omitted and host is an IP, we probe the port once to detect TLS:
//   - if TLS handshake succeeds, scheme becomes https (and InsecureSkipVerify defaults to true unless explicitly set)
//   - otherwise scheme becomes http
//
// - If scheme is omitted and host is not an IP, default scheme becomes http.
func normalizeOriginAndTLSDefaults(cfg *Config, insecureSkipVerifyExplicit bool) {
	normalized, tlsIP := normalizeOrigin(cfg.Origin)
	cfg.Origin = normalized
	if tlsIP && !insecureSkipVerifyExplicit {
		cfg.InsecureSkipVerify = true
		log.Printf("proxybuff: WARNING: origin %s uses TLS on a raw IP; certificate verification is disabled (pass --insecure-skip-verify=false to override)", normalized)
	}
}

// normalizeOrigin adds a scheme to a scheme-less origin. For a raw IP that
// answers a TLS handshake it returns https and tlsIP=true (so the caller may
// default InsecureSkipVerify on); otherwise it returns http. An origin that
// already has a scheme is returned unchanged.
func normalizeOrigin(origin string) (normalized string, tlsIP bool) {
	origin = strings.TrimSpace(origin)
	if origin == "" || strings.Contains(origin, "://") {
		return origin, false
	}
	host, port := hostPortFromOrigin(origin)
	if net.ParseIP(host) != nil {
		if probeTLS(host, port) {
			return "https://" + origin, true
		}
		return "http://" + origin, false
	}
	return "http://" + origin, false
}

// hostPortFromOrigin extracts host and port from a scheme-less "host[:port][/path]"
// origin, defaulting the port to 80 when absent.
func hostPortFromOrigin(origin string) (host, port string) {
	hostport := origin
	if i := strings.Index(hostport, "/"); i >= 0 {
		hostport = hostport[:i]
	}
	if strings.HasPrefix(hostport, "[") {
		if h, p, err := net.SplitHostPort(hostport); err == nil {
			return strings.TrimPrefix(strings.TrimSuffix(h, "]"), "["), p
		}
		if j := strings.Index(hostport, "]"); j > 1 {
			return hostport[1:j], "80"
		}
		return hostport, "80"
	}
	if strings.Count(hostport, ":") == 1 {
		if h, p, err := net.SplitHostPort(hostport); err == nil {
			return h, p
		}
		if parts := strings.SplitN(hostport, ":", 2); len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return hostport, "80"
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

type listenFlag struct {
	enabled       *bool
	listen        *string
	defaultAddr   string
	defaultPort   string
	allowDisable  bool
	explicitlySet bool
}

func newListenFlag(enabled *bool, listen *string, defaultAddr, defaultPort string, allowDisable bool) listenFlag {
	return listenFlag{
		enabled:      enabled,
		listen:       listen,
		defaultAddr:  defaultAddr,
		defaultPort:  defaultPort,
		allowDisable: allowDisable,
	}
}

func (l *listenFlag) String() string {
	if l.listen == nil {
		return ""
	}
	return *l.listen
}

func (l *listenFlag) IsBoolFlag() bool { return true }

func (l *listenFlag) Set(s string) error {
	l.explicitlySet = true

	// Allow --http, --http=true/false, or --http=<port|addr>
	if v, err := strconv.ParseBool(s); err == nil {
		if !v && !l.allowDisable {
			return errors.New("http listener cannot be disabled")
		}
		*l.enabled = v
		if v && strings.TrimSpace(*l.listen) == "" {
			*l.listen = l.defaultAddr
		}
		if !v {
			*l.listen = ""
		}
		return nil
	}

	addr := strings.TrimSpace(s)
	if addr == "" {
		if !l.allowDisable {
			return errors.New("http listener cannot be disabled")
		}
		*l.enabled = false
		*l.listen = ""
		return nil
	}
	*l.enabled = true
	*l.listen = normalizeListen(addr, l.defaultPort)
	return nil
}

func normalizeListen(v string, defaultPort string) string {
	// Allow passing just a port number.
	if isAllDigits(v) {
		return "0.0.0.0:" + v
	}
	// Allow ":443" style.
	if strings.HasPrefix(v, ":") {
		return v
	}
	// Otherwise expect host:port.
	if strings.Contains(v, ":") {
		return v
	}
	// Fallback to "0.0.0.0:<defaultPort>"
	return "0.0.0.0:" + defaultPort
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
