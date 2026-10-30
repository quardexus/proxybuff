// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
)

func v2Header(verCmd, fam byte, payload []byte) []byte {
	b := append([]byte{}, v2Sig...)
	b = append(b, verCmd, fam, 0, 0)
	binary.BigEndian.PutUint16(b[14:16], uint16(len(payload)))
	return append(b, payload...)
}

func v2TCP4(src, dst [4]byte, sport, dport uint16, tlv []byte) []byte {
	p := append([]byte{}, src[:]...)
	p = append(p, dst[:]...)
	p = binary.BigEndian.AppendUint16(p, sport)
	p = binary.BigEndian.AppendUint16(p, dport)
	p = append(p, tlv...)
	return v2Header(0x21, v2FamTCP4, p)
}

func v2TCP6(src, dst netip.Addr, sport, dport uint16) []byte {
	s, d := src.As16(), dst.As16()
	p := append([]byte{}, s[:]...)
	p = append(p, d[:]...)
	p = binary.BigEndian.AppendUint16(p, sport)
	p = binary.BigEndian.AppendUint16(p, dport)
	return v2Header(0x21, v2FamTCP6, p)
}

func TestReadHeaderValid(t *testing.T) {
	tests := []struct {
		name     string
		in       []byte
		version  int
		cmd      Command
		src, dst string // empty: no addresses
	}{
		{"v1 tcp4", []byte("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n"), 1, CmdProxy, "203.0.113.7:51234", "198.51.100.1:443"},
		{"v1 tcp6", []byte("PROXY TCP6 2001:db8::1 2001:db8::2 65535 0\r\n"), 1, CmdProxy, "[2001:db8::1]:65535", "[2001:db8::2]:0"},
		{"v1 unknown", []byte("PROXY UNKNOWN\r\n"), 1, CmdProxy, "", ""},
		{"v1 exactly 107 bytes", []byte("PROXY UNKNOWN " + strings.Repeat("a", 91) + "\r\n"), 1, CmdProxy, "", ""},
		{"v1 unknown with trailer", []byte("PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"), 1, CmdProxy, "", ""},
		{"v1 max length", []byte("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"), 1, CmdProxy, "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535", "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"},
		{"v2 proxy ipv4", v2TCP4([4]byte{203, 0, 113, 7}, [4]byte{10, 0, 0, 2}, 40000, 443, nil), 2, CmdProxy, "203.0.113.7:40000", "10.0.0.2:443"},
		{"v2 proxy ipv4 with TLV", v2TCP4([4]byte{203, 0, 113, 7}, [4]byte{10, 0, 0, 2}, 40000, 443, []byte{0x01, 0x00, 0x02, 'h', '2'}), 2, CmdProxy, "203.0.113.7:40000", "10.0.0.2:443"},
		{"v2 proxy ipv6", v2TCP6(netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("2001:db8::1"), 1, 2), 2, CmdProxy, "[2001:db8::7]:1", "[2001:db8::1]:2"},
		{"v2 local", v2Header(0x20, v2FamUnspec, nil), 2, CmdLocal, "", ""},
		{"v2 local ignores address block", v2Header(0x20, v2FamTCP4, make([]byte, 12)), 2, CmdLocal, "", ""},
		{"v2 proxy unspec", v2Header(0x21, v2FamUnspec, nil), 2, CmdProxy, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte("\x16\x03\x01 tls-or-http payload")
			in := append(append([]byte{}, tt.in...), payload...)
			for _, mode := range []string{"whole", "onebyte"} {
				var r io.Reader = bytes.NewReader(in)
				if mode == "onebyte" {
					r = iotest.OneByteReader(r)
				}
				h, rest, err := ReadHeader(r)
				if err != nil {
					t.Fatalf("%s: ReadHeader: %v", mode, err)
				}
				if h.Version != tt.version || h.Command != tt.cmd {
					t.Fatalf("%s: got version=%d cmd=%d", mode, h.Version, h.Command)
				}
				if tt.src == "" {
					if h.HasAddrs() {
						t.Fatalf("%s: unexpected addresses %v -> %v", mode, h.Source, h.Destination)
					}
				} else {
					if !h.HasAddrs() || h.Source.String() != tt.src || h.Destination.String() != tt.dst {
						t.Fatalf("%s: got %v -> %v, want %s -> %s", mode, h.Source, h.Destination, tt.src, tt.dst)
					}
				}
				// Whatever ReadHeader over-read plus the rest of the stream
				// must reproduce the payload exactly.
				tail, _ := io.ReadAll(r)
				got := append(append([]byte{}, rest...), tail...)
				if !bytes.Equal(got, payload) {
					t.Fatalf("%s: payload after header = %q, want %q", mode, got, payload)
				}
			}
		})
	}
}

func TestReadHeaderInvalid(t *testing.T) {
	// 14 + 92 + 2 = 108 bytes: one past the v1 limit.
	long := "PROXY UNKNOWN " + strings.Repeat("a", 92) + "\r\n"
	tests := []struct {
		name  string
		in    []byte
		noHdr bool // expect ErrNoHeader rather than ErrInvalidHeader
	}{
		{"empty", nil, true},
		{"plain http", []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), true},
		{"tls client hello", []byte{0x16, 0x03, 0x01, 0x00, 0x05}, true},
		{"lowercase proxy", []byte("proxy TCP4 1.2.3.4 5.6.7.8 1 2\r\n"), true},
		{"P but not PROXY", []byte("POST / HTTP/1.1\r\n\r\n"), false},
		{"v1 LF only", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n"), false},
		{"v1 too few fields", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n"), false},
		{"v1 too many fields", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n"), false},
		{"v1 double space", []byte("PROXY TCP4  1.2.3.4 5.6.7.8 1 2\r\n"), false},
		{"v1 trailing space", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2 \r\n"), false},
		{"v1 tab", []byte("PROXY TCP4 1.2.3.4\t5.6.7.8 1 2\r\n"), false},
		{"v1 unknown proto", []byte("PROXY UDP4 1.2.3.4 5.6.7.8 1 2\r\n"), false},
		{"v1 no proto", []byte("PROXY \r\n"), false},
		{"v1 tcp4 with ipv6", []byte("PROXY TCP4 ::1 ::1 1 2\r\n"), false},
		{"v1 tcp6 with ipv4", []byte("PROXY TCP6 1.2.3.4 5.6.7.8 1 2\r\n"), false},
		{"v1 tcp4 with v4-mapped", []byte("PROXY TCP4 ::ffff:1.2.3.4 5.6.7.8 1 2\r\n"), false},
		{"v1 bad ip", []byte("PROXY TCP4 1.2.3.256 5.6.7.8 1 2\r\n"), false},
		{"v1 ipv4 leading zero", []byte("PROXY TCP4 01.2.3.4 5.6.7.8 1 2\r\n"), false},
		{"v1 hostname", []byte("PROXY TCP4 localhost 5.6.7.8 1 2\r\n"), false},
		{"v1 ipv6 zone", []byte("PROXY TCP6 fe80::1%eth0 ::1 1 2\r\n"), false},
		{"v1 port plus", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 +1 2\r\n"), false},
		{"v1 port minus", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 -1 2\r\n"), false},
		{"v1 port leading zero", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n"), false},
		{"v1 port overflow", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n"), false},
		{"v1 port hex", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 0x10 2\r\n"), false},
		{"v1 port empty", []byte("PROXY TCP4 1.2.3.4 5.6.7.8  2\r\n"), false},
		{"v1 oversized", []byte(long), false},
		{"v1 no terminator within limit", []byte("PROXY UNKNOWN " + strings.Repeat("a", 200)), false},
		{"v1 truncated", []byte("PROXY TCP4 1.2.3.4"), false},
		{"v1 truncated prefix", []byte("PROX"), false},
		{"v1 non-ascii", []byte("PROXY UNKNOWN \xff\r\n"), false},
		{"v2 bad signature", append([]byte("\r\n\r\n\x00\r\nQUIX\n"), 0x21, 0x11, 0, 0), false},
		{"v2 truncated signature", []byte("\r\n\r\n\x00"), false},
		{"v2 truncated fixed header", append(append([]byte{}, v2Sig...), 0x21, 0x11), false},
		{"v2 version 1", v2Header(0x11, v2FamTCP4, make([]byte, 12)), false},
		{"v2 version 3", v2Header(0x31, v2FamTCP4, make([]byte, 12)), false},
		{"v2 bad command", v2Header(0x22, v2FamTCP4, make([]byte, 12)), false},
		{"v2 tcp4 short", v2Header(0x21, v2FamTCP4, make([]byte, 11)), false},
		{"v2 tcp6 short", v2Header(0x21, v2FamTCP6, make([]byte, 35)), false},
		{"v2 udp4", v2Header(0x21, 0x12, make([]byte, 12)), false},
		{"v2 unix", v2Header(0x21, 0x31, make([]byte, 216)), false},
		{"v2 bad family", v2Header(0x21, 0x41, make([]byte, 12)), false},
		{"v2 oversized length", v2Header(0x21, v2FamTCP4, make([]byte, v2MaxPayload+1)), false},
		{"v2 truncated payload", v2Header(0x21, v2FamTCP4, make([]byte, 12))[:20], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []string{"whole", "onebyte"} {
				var r io.Reader = bytes.NewReader(tt.in)
				if mode == "onebyte" {
					r = iotest.OneByteReader(r)
				}
				h, _, err := ReadHeader(r)
				if err == nil {
					t.Fatalf("%s: expected error, got header %+v", mode, h)
				}
				want := ErrInvalidHeader
				if tt.noHdr {
					want = ErrNoHeader
				}
				if !errors.Is(err, want) {
					t.Fatalf("%s: err = %v, want %v", mode, err, want)
				}
			}
		})
	}
}

// strictReader serves data and then fails the test if read again: proves the
// parser does not wait for bytes beyond the header it needs.
type strictReader struct {
	t    *testing.T
	data []byte
}

func (s *strictReader) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		s.t.Fatalf("parser read past the end of the header")
	}
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}

func TestReadHeaderDoesNotOverRead(t *testing.T) {
	for _, in := range [][]byte{
		[]byte("PROXY UNKNOWN\r\n"),
		[]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"),
		v2Header(0x20, v2FamUnspec, nil),
		v2TCP4([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1, 2, nil),
	} {
		h, rest, err := ReadHeader(&strictReader{t: t, data: in})
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(rest) != 0 {
			t.Fatalf("%q: unexpected rest %q", in, rest)
		}
		_ = h
	}
}

func TestReadHeaderStopsOnZeroReads(t *testing.T) {
	r := readerFunc(func(p []byte) (int, error) { return 0, nil })
	if _, _, err := ReadHeader(r); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("err = %v, want io.ErrNoProgress", err)
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestParseAllowList(t *testing.T) {
	al, err := ParseAllowList([]string{"10.0.0.0/8", " 192.168.1.5 ", "2001:db8::/32", "::ffff:172.16.0.0/108", "10.1.2.3/16"})
	if err != nil {
		t.Fatalf("ParseAllowList: %v", err)
	}
	if al.Len() != 5 {
		t.Fatalf("Len = %d", al.Len())
	}
	if got := al.String(); got != "10.0.0.0/8,192.168.1.5/32,2001:db8::/32,172.16.0.0/12,10.1.0.0/16" {
		t.Fatalf("String = %q", got)
	}
	for _, ip := range []string{"10.9.9.9", "192.168.1.5", "2001:db8::42", "172.20.0.1", "::ffff:10.0.0.1"} {
		if !al.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("%s should be contained", ip)
		}
	}
	for _, ip := range []string{"192.168.1.6", "11.0.0.1", "2001:db9::1", "127.0.0.1"} {
		if al.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("%s should not be contained", ip)
		}
	}
	if (AllowList{}).Contains(netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("empty allow list must match nothing")
	}

	for _, bad := range []string{"", "10.0.0.0/33", "300.1.1.1", "example.com", "fe80::1%eth0", "10.0.0.0/", "1.2.3.4/-1", "::/129"} {
		if _, err := ParseAllowList([]string{bad}); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}
