// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxyproto

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// DefaultHeaderTimeout bounds how long a trusted peer may take to deliver the
// PROXY header after the connection is accepted.
const DefaultHeaderTimeout = 5 * time.Second

// rejectLogInterval rate-limits the "rejected connection" log line.
const rejectLogInterval = 10 * time.Second

// AllowList is a set of IP prefixes whose connections must carry a PROXY
// protocol header. The zero value matches nothing.
type AllowList struct {
	prefixes []netip.Prefix
}

// ParseAllowList parses IP addresses and CIDR prefixes (IPv4 or IPv6). Every
// entry must be valid; a bare address is treated as a single-host prefix.
// IPv4-mapped IPv6 forms are folded to IPv4 so they match IPv4 peers.
func ParseAllowList(entries []string) (AllowList, error) {
	var out AllowList
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			return AllowList{}, errors.New("empty entry")
		}
		var p netip.Prefix
		if strings.Contains(e, "/") {
			pp, err := netip.ParsePrefix(e)
			if err != nil {
				return AllowList{}, fmt.Errorf("invalid CIDR %q: %v", e, err)
			}
			p = pp
		} else {
			a, err := netip.ParseAddr(e)
			if err != nil {
				return AllowList{}, fmt.Errorf("invalid IP %q: %v", e, err)
			}
			if a.Zone() != "" {
				return AllowList{}, fmt.Errorf("invalid IP %q: zones are not allowed", e)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		out.prefixes = append(out.prefixes, p.Masked())
	}
	return out, nil
}

// Len reports the number of prefixes.
func (a AllowList) Len() int { return len(a.prefixes) }

// Wide returns the prefixes that cover more than one address. Every peer in
// such a range (for a Docker network: the bridge gateway that docker-proxy
// connects from, and every sibling container) may choose its client IP by
// sending its own PROXY header, so callers should warn about them.
func (a AllowList) Wide() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range a.prefixes {
		if p.Bits() < p.Addr().BitLen() {
			out = append(out, p)
		}
	}
	return out
}

// Contains reports whether ip belongs to any prefix.
func (a AllowList) Contains(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap().WithZone("")
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (a AllowList) String() string {
	s := make([]string, len(a.prefixes))
	for i, p := range a.prefixes {
		s[i] = p.String()
	}
	return strings.Join(s, ",")
}

// Listener wraps a raw TCP listener (it must sit below any TLS listener).
//
// Connections from peers in Allow must start with a PROXY protocol header;
// it is parsed lazily, in the goroutine that first calls Read, Write or
// RemoteAddr on the connection (for net/http that is the per-connection serve
// goroutine), so Accept never blocks on a slow or silent peer. A missing,
// malformed, oversized or late (HeaderTimeout) header closes the connection.
//
// Connections from all other peers are returned untouched: their bytes are
// never inspected, so a PROXY line sent by an untrusted client is just
// garbage to the HTTP/TLS layer above.
type Listener struct {
	net.Listener
	Allow AllowList
	// HeaderTimeout bounds the header read; DefaultHeaderTimeout if <= 0.
	HeaderTimeout time.Duration
	// Logf receives rate-limited rejection reports; log.Printf if nil.
	Logf func(format string, args ...any)
	// RejectHint, if set, is appended to rejection reports (e.g. to point
	// out that ACME HTTP-01 challenges on the HTTP listener need the header
	// too).
	RejectHint string

	logMu      sync.Mutex
	nextLog    time.Time
	suppressed int
}

// NewListener wraps inner so that peers in allow must send a PROXY header.
func NewListener(inner net.Listener, allow AllowList) *Listener {
	return &Listener{Listener: inner, Allow: allow, HeaderTimeout: DefaultHeaderTimeout}
}

// Accept returns the next connection. It never reads from the connection.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !l.Allow.Contains(peerIP(c.RemoteAddr())) {
		return c, nil
	}
	return &Conn{Conn: c, l: l}, nil
}

func peerIP(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}
		}
		return ip.Unmap()
	case nil:
		return netip.Addr{}
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.Addr{}
		}
		return ap.Addr().Unmap()
	}
}

func (l *Listener) headerTimeout() time.Duration {
	if l.HeaderTimeout > 0 {
		return l.HeaderTimeout
	}
	return DefaultHeaderTimeout
}

// reject logs a refused connection at most once per rejectLogInterval,
// reporting how many were suppressed in between.
func (l *Listener) reject(peer net.Addr, err error) {
	now := time.Now()
	l.logMu.Lock()
	if now.Before(l.nextLog) {
		l.suppressed++
		l.logMu.Unlock()
		return
	}
	suppressed := l.suppressed
	l.suppressed = 0
	l.nextLog = now.Add(rejectLogInterval)
	l.logMu.Unlock()

	logf := l.Logf
	if logf == nil {
		logf = log.Printf
	}
	hint := ""
	if l.RejectHint != "" {
		hint = "; " + l.RejectHint
	}
	if suppressed > 0 {
		logf("proxy-protocol: rejected connection from trusted peer %s: %v (%d more rejected since last report)%s", peer, err, suppressed, hint)
		return
	}
	logf("proxy-protocol: rejected connection from trusted peer %s: %v%s", peer, err, hint)
}

// Conn is a connection from a trusted peer. Its PROXY header is consumed on
// first use; afterwards RemoteAddr reports the client address from the header
// (unless the header was LOCAL/UNKNOWN) and Read continues with the bytes
// that followed the header.
type Conn struct {
	net.Conn
	l *Listener

	once    sync.Once
	header  Header
	err     error
	remote  net.Addr
	pending []byte

	// dlMu guards the deadline the caller asked for while the header is
	// still being read; it is applied once the header phase ends.
	dlMu         sync.Mutex
	headerDone   bool
	readDeadline time.Time
}

func (c *Conn) init() {
	c.once.Do(c.readHeader)
}

func (c *Conn) readHeader() {
	c.dlMu.Lock()
	dl := time.Now().Add(c.l.headerTimeout())
	if !c.readDeadline.IsZero() && c.readDeadline.Before(dl) {
		dl = c.readDeadline
	}
	c.dlMu.Unlock()
	_ = c.Conn.SetReadDeadline(dl)

	h, rest, err := ReadHeader(c.Conn)

	c.dlMu.Lock()
	c.headerDone = true
	if err == nil {
		err = c.Conn.SetReadDeadline(c.readDeadline)
	}
	c.dlMu.Unlock()

	if err != nil {
		c.err = fmt.Errorf("proxy protocol: %w", err)
		c.l.reject(c.Conn.RemoteAddr(), err)
		_ = c.Conn.Close()
		return
	}
	c.header = h
	c.pending = rest
	if h.HasAddrs() {
		c.remote = &net.TCPAddr{IP: h.Source.Addr().Unmap().AsSlice(), Port: int(h.Source.Port())}
	}
}

// Header returns the parsed PROXY header, reading it first if necessary.
func (c *Conn) Header() (Header, error) {
	c.init()
	return c.header, c.err
}

// Read returns bytes after the PROXY header.
func (c *Conn) Read(b []byte) (int, error) {
	c.init()
	if c.err != nil {
		return 0, c.err
	}
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		if len(c.pending) == 0 {
			c.pending = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// Write writes only after a valid header has been received.
func (c *Conn) Write(b []byte) (int, error) {
	c.init()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Write(b)
}

// ReadFrom lets net/http use the inner connection's io.ReaderFrom (sendfile
// on *net.TCPConn) for cache hits; it only writes, so no buffered header
// bytes are involved.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	c.init()
	if c.err != nil {
		return 0, c.err
	}
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	// c.Conn, not c, so io.Copy cannot recurse into this method.
	return io.Copy(c.Conn, r)
}

// RemoteAddr returns the client address from the PROXY header, or the real
// peer address for LOCAL/UNKNOWN headers and failed connections.
func (c *Conn) RemoteAddr() net.Addr {
	c.init()
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

// SetDeadline sets read and write deadlines. While the header is being read,
// the read deadline is recorded and applied afterwards.
func (c *Conn) SetDeadline(t time.Time) error {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	c.readDeadline = t
	if !c.headerDone {
		return c.Conn.SetWriteDeadline(t)
	}
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline. While the header is being read, it
// is recorded and applied afterwards (the header has its own deadline).
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	c.readDeadline = t
	if !c.headerDone {
		return nil
	}
	return c.Conn.SetReadDeadline(t)
}
