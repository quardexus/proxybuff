// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

// Package proxyproto implements a strict, receive-only parser for the HAProxy
// PROXY protocol (v1 text and v2 binary) and a net.Listener wrapper that
// requires the header from trusted peers (e.g. an edge nginx stream proxy)
// and ignores it from everyone else.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// v1MaxLen is the maximum v1 header length including the trailing CRLF
	// (spec: "PROXY UNKNOWN" + two IPv6 addresses and ports = 107 bytes).
	v1MaxLen = 107
	// v2FixedLen is the fixed v2 preamble: 12-byte signature, ver/cmd,
	// family/transport and a 16-bit payload length.
	v2FixedLen = 16
	// v2MaxPayload bounds the v2 address+TLV block. Addresses need at most
	// 216 bytes (AF_UNIX); the remainder leaves room for common TLVs
	// (ALPN, authority, unique id, SSL info) while keeping memory bounded.
	v2MaxPayload = 2048

	// maxEmptyReads guards against readers that return (0, nil) forever.
	maxEmptyReads = 100
)

var (
	v1Prefix = []byte("PROXY ")
	v2Sig    = []byte("\r\n\r\n\x00\r\nQUIT\n")
)

var (
	// ErrNoHeader is returned when the stream does not start with a PROXY
	// protocol signature (or ends before sending a single byte).
	ErrNoHeader = errors.New("proxyproto: missing PROXY protocol header")
	// ErrInvalidHeader is wrapped by every parse error of a stream that does
	// start with a PROXY signature but is malformed, truncated or oversized.
	ErrInvalidHeader = errors.New("proxyproto: invalid PROXY protocol header")
)

// Command is the PROXY protocol command.
type Command uint8

const (
	// CmdLocal is a v2 LOCAL header (health check from the proxy itself);
	// the real peer address must be used.
	CmdLocal Command = iota
	// CmdProxy carries (or, for v1 UNKNOWN / v2 UNSPEC, omits) the original
	// connection endpoints.
	CmdProxy
)

// Header is a parsed PROXY protocol header.
type Header struct {
	Version int
	Command Command
	// Source and Destination are set only for TCP over IPv4/IPv6 PROXY
	// headers; see HasAddrs.
	Source      netip.AddrPort
	Destination netip.AddrPort
}

// HasAddrs reports whether the header carries a client address that should
// replace the peer address of the connection.
func (h Header) HasAddrs() bool {
	return h.Command == CmdProxy && h.Source.IsValid()
}

// ReadHeader reads exactly one PROXY protocol header (v1 or v2) from r.
//
// It issues a new Read only when it needs more bytes to make progress, so it
// never waits for data beyond the end of the header. Bytes that a Read
// returned past the end of the header are handed back as rest and must be
// delivered to the next consumer of the stream before any further reads.
func ReadHeader(r io.Reader) (h Header, rest []byte, err error) {
	p := &headerReader{r: r, buf: make([]byte, 0, 128)}
	if err := p.fill(1); err != nil {
		if errors.Is(err, io.EOF) {
			return Header{}, nil, ErrNoHeader
		}
		return Header{}, nil, err
	}

	var n int
	switch p.buf[0] {
	case v1Prefix[0]:
		h, n, err = p.readV1()
	case v2Sig[0]:
		h, n, err = p.readV2()
	default:
		return Header{}, nil, ErrNoHeader
	}
	if err != nil {
		return Header{}, nil, err
	}
	if n < len(p.buf) {
		rest = p.buf[n:]
	}
	return h, rest, nil
}

type headerReader struct {
	r   io.Reader
	buf []byte
}

// fill reads until at least n bytes are buffered. Each Read may return more
// than requested; the surplus stays in buf.
func (p *headerReader) fill(n int) error {
	if cap(p.buf) < n {
		nb := make([]byte, len(p.buf), n)
		copy(nb, p.buf)
		p.buf = nb
	}
	empty := 0
	for len(p.buf) < n {
		k, err := p.r.Read(p.buf[len(p.buf):cap(p.buf)])
		p.buf = p.buf[:len(p.buf)+k]
		if len(p.buf) >= n {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(p.buf) > 0 {
				return fmt.Errorf("%w: truncated header (%d bytes)", ErrInvalidHeader, len(p.buf))
			}
			return err
		}
		if k == 0 {
			empty++
			if empty >= maxEmptyReads {
				return io.ErrNoProgress
			}
			continue
		}
		empty = 0
	}
	return nil
}

// matchPrefix buffers len(sig) bytes, failing as soon as the bytes received so
// far diverge from sig.
func (p *headerReader) matchPrefix(sig []byte, what string) error {
	for {
		k := min(len(p.buf), len(sig))
		if !bytes.Equal(p.buf[:k], sig[:k]) {
			return fmt.Errorf("%w: bad %s signature", ErrInvalidHeader, what)
		}
		if k == len(sig) {
			return nil
		}
		if err := p.fill(len(p.buf) + 1); err != nil {
			return err
		}
	}
}

func (p *headerReader) readV1() (Header, int, error) {
	if err := p.matchPrefix(v1Prefix, "v1"); err != nil {
		return Header{}, 0, err
	}
	for {
		n := min(len(p.buf), v1MaxLen)
		if i := bytes.IndexByte(p.buf[:n], '\n'); i >= 0 {
			h, err := parseV1Line(p.buf[:i+1])
			if err != nil {
				return Header{}, 0, err
			}
			return h, i + 1, nil
		}
		if n >= v1MaxLen {
			return Header{}, 0, fmt.Errorf("%w: v1 header exceeds %d bytes", ErrInvalidHeader, v1MaxLen)
		}
		if err := p.fill(len(p.buf) + 1); err != nil {
			return Header{}, 0, err
		}
	}
}

// parseV1Line parses a complete v1 line including its CRLF terminator.
func parseV1Line(line []byte) (Header, error) {
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return Header{}, fmt.Errorf("%w: v1 header must end with CRLF", ErrInvalidHeader)
	}
	body := line[:len(line)-2]
	for _, c := range body {
		if c < 0x20 || c > 0x7e {
			return Header{}, fmt.Errorf("%w: v1 header contains a non-printable byte", ErrInvalidHeader)
		}
	}
	fields := strings.Split(string(body), " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return Header{}, fmt.Errorf("%w: malformed v1 header", ErrInvalidHeader)
	}

	h := Header{Version: 1, Command: CmdProxy}
	switch fields[1] {
	case "UNKNOWN":
		// The spec lets the sender append anything after UNKNOWN; the
		// receiver must ignore it and keep the real peer address.
		return h, nil
	case "TCP4", "TCP6":
	default:
		return Header{}, fmt.Errorf("%w: unsupported v1 protocol %q", ErrInvalidHeader, fields[1])
	}
	if len(fields) != 6 {
		return Header{}, fmt.Errorf("%w: v1 %s header must have exactly 6 fields, got %d", ErrInvalidHeader, fields[1], len(fields))
	}
	want4 := fields[1] == "TCP4"
	src, err := parseV1Addr(fields[2], want4)
	if err != nil {
		return Header{}, fmt.Errorf("%w: source address: %v", ErrInvalidHeader, err)
	}
	dst, err := parseV1Addr(fields[3], want4)
	if err != nil {
		return Header{}, fmt.Errorf("%w: destination address: %v", ErrInvalidHeader, err)
	}
	sport, err := parseV1Port(fields[4])
	if err != nil {
		return Header{}, fmt.Errorf("%w: source port: %v", ErrInvalidHeader, err)
	}
	dport, err := parseV1Port(fields[5])
	if err != nil {
		return Header{}, fmt.Errorf("%w: destination port: %v", ErrInvalidHeader, err)
	}
	h.Source = netip.AddrPortFrom(src, sport)
	h.Destination = netip.AddrPortFrom(dst, dport)
	return h, nil
}

func parseV1Addr(s string, want4 bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q: zone not allowed", s)
	}
	if want4 && !a.Is4() {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv4 address", s)
	}
	if !want4 && !a.Is6() {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv6 address", s)
	}
	return a, nil
}

// parseV1Port accepts 0-65535 written in plain decimal: no sign, no leading
// zeros (except "0" itself), at most five digits.
func parseV1Port(s string) (uint16, error) {
	if s == "" || len(s) > 5 {
		return 0, fmt.Errorf("%q: invalid port", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%q: invalid port", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%q: leading zero in port", s)
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%q: port out of range", s)
	}
	return uint16(v), nil
}

const (
	v2CmdLocal = 0x0
	v2CmdProxy = 0x1

	v2FamUnspec = 0x00
	v2FamTCP4   = 0x11
	v2FamTCP6   = 0x21

	v2AddrLenTCP4 = 12 // 2×4 address bytes + 2×2 port bytes
	v2AddrLenTCP6 = 36 // 2×16 address bytes + 2×2 port bytes
)

func (p *headerReader) readV2() (Header, int, error) {
	if err := p.matchPrefix(v2Sig, "v2"); err != nil {
		return Header{}, 0, err
	}
	if err := p.fill(v2FixedLen); err != nil {
		return Header{}, 0, err
	}
	verCmd := p.buf[12]
	fam := p.buf[13]
	length := int(binary.BigEndian.Uint16(p.buf[14:16]))

	if verCmd>>4 != 2 {
		return Header{}, 0, fmt.Errorf("%w: unsupported v2 version %d", ErrInvalidHeader, verCmd>>4)
	}
	cmd := verCmd & 0x0f
	if cmd != v2CmdLocal && cmd != v2CmdProxy {
		return Header{}, 0, fmt.Errorf("%w: unsupported v2 command 0x%x", ErrInvalidHeader, cmd)
	}
	if length > v2MaxPayload {
		return Header{}, 0, fmt.Errorf("%w: v2 payload length %d exceeds %d", ErrInvalidHeader, length, v2MaxPayload)
	}
	total := v2FixedLen + length
	if err := p.fill(total); err != nil {
		return Header{}, 0, err
	}
	payload := p.buf[v2FixedLen:total]

	h := Header{Version: 2}
	if cmd == v2CmdLocal {
		// LOCAL: the proxy speaks for itself; address block (if any) is
		// ignored and the real peer address applies.
		h.Command = CmdLocal
		return h, total, nil
	}
	h.Command = CmdProxy

	switch fam {
	case v2FamUnspec:
		// Unknown family: keep the real peer address.
		return h, total, nil
	case v2FamTCP4:
		if length < v2AddrLenTCP4 {
			return Header{}, 0, fmt.Errorf("%w: v2 TCP4 payload too short (%d bytes)", ErrInvalidHeader, length)
		}
		src := netip.AddrFrom4([4]byte(payload[0:4]))
		dst := netip.AddrFrom4([4]byte(payload[4:8]))
		h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(payload[8:10]))
		h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(payload[10:12]))
	case v2FamTCP6:
		if length < v2AddrLenTCP6 {
			return Header{}, 0, fmt.Errorf("%w: v2 TCP6 payload too short (%d bytes)", ErrInvalidHeader, length)
		}
		src := netip.AddrFrom16([16]byte(payload[0:16]))
		dst := netip.AddrFrom16([16]byte(payload[16:32]))
		h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(payload[32:34]))
		h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(payload[34:36]))
	default:
		return Header{}, 0, fmt.Errorf("%w: unsupported v2 address family/transport 0x%02x", ErrInvalidHeader, fam)
	}
	// Any remaining bytes are TLVs; they are bounded by v2MaxPayload and
	// intentionally ignored.
	return h, total, nil
}
