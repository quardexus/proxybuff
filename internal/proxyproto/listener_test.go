// ════════════════════════════════════════════════════════════
//   QUARDEXUS · functional entity
// ════════════════════════════════════════════════════════════
// ProxyBuff · high-load caching reverse proxy with auto-TLS
// SPDX-License-Identifier: Apache-2.0 · © 2026 Quardexus

package proxyproto

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestListener listens on loopback. trusted=true allows 127.0.0.0/8, false
// allows only a documentation range so the loopback peer is untrusted.
func newTestListener(t *testing.T, trusted bool, headerTimeout time.Duration) (*Listener, *logCapture) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	entry := "192.0.2.0/24"
	if trusted {
		entry = "127.0.0.0/8"
	}
	al, err := ParseAllowList([]string{entry})
	if err != nil {
		t.Fatalf("allow list: %v", err)
	}
	l := NewListener(inner, al)
	l.HeaderTimeout = headerTimeout
	lc := &logCapture{}
	l.Logf = lc.logf
	t.Cleanup(func() { _ = l.Close() })
	return l, lc
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCapture) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *logCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.lines)
}

func dial(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type acceptResult struct {
	c   net.Conn
	err error
}

func acceptAsync(l net.Listener) <-chan acceptResult {
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := l.Accept()
		ch <- acceptResult{c, err}
	}()
	return ch
}

func mustAccept(t *testing.T, ch <-chan acceptResult) net.Conn {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("accept: %v", r.err)
		}
		t.Cleanup(func() { _ = r.c.Close() })
		return r.c
	case <-time.After(3 * time.Second):
		t.Fatalf("accept did not return")
		return nil
	}
}

func TestTrustedValidHeaderReplacesRemoteAddr(t *testing.T) {
	cases := map[string][]byte{
		"v1": []byte("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n"),
		"v2": v2TCP4([4]byte{203, 0, 113, 7}, [4]byte{198, 51, 100, 1}, 51234, 443, nil),
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			l, _ := newTestListener(t, true, time.Second)
			ch := acceptAsync(l)
			c := dial(t, l)
			// Header and payload in one segment, so the parser over-reads
			// and must hand the surplus back.
			if _, err := c.Write(append(append([]byte{}, hdr...), "hello world"...)); err != nil {
				t.Fatal(err)
			}
			sc := mustAccept(t, ch)
			if got := sc.RemoteAddr().String(); got != "203.0.113.7:51234" {
				t.Fatalf("RemoteAddr = %s", got)
			}
			buf := make([]byte, len("hello world"))
			_ = sc.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadFull(sc, buf); err != nil {
				t.Fatalf("read payload: %v", err)
			}
			if string(buf) != "hello world" {
				t.Fatalf("payload = %q", buf)
			}
		})
	}
}

func TestTrustedLocalAndUnknownKeepPeerAddr(t *testing.T) {
	for name, hdr := range map[string][]byte{
		"v1 unknown": []byte("PROXY UNKNOWN\r\n"),
		"v2 local":   v2Header(0x20, v2FamUnspec, nil),
	} {
		t.Run(name, func(t *testing.T) {
			l, _ := newTestListener(t, true, time.Second)
			ch := acceptAsync(l)
			c := dial(t, l)
			if _, err := c.Write(append(append([]byte{}, hdr...), 'x')); err != nil {
				t.Fatal(err)
			}
			sc := mustAccept(t, ch)
			if got, want := sc.RemoteAddr().String(), c.LocalAddr().String(); got != want {
				t.Fatalf("RemoteAddr = %s, want real peer %s", got, want)
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(sc, b); err != nil || b[0] != 'x' {
				t.Fatalf("read = %q, %v", b, err)
			}
		})
	}
}

// expectClosed asserts the server side refused the connection: its Read fails
// and the client observes EOF/reset.
func expectClosed(t *testing.T, sc, c net.Conn) {
	t.Helper()
	if _, err := sc.Read(make([]byte, 1)); err == nil {
		t.Fatalf("server read succeeded on rejected connection")
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("client connection not closed by server: %v", err)
	}
}

func TestTrustedWithoutHeaderIsClosed(t *testing.T) {
	l, lc := newTestListener(t, true, time.Second)
	ch := acceptAsync(l)
	c := dial(t, l)
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	sc := mustAccept(t, ch)
	expectClosed(t, sc, c)
	if lc.count() != 1 {
		t.Fatalf("expected one rejection log line, got %d", lc.count())
	}
}

func TestTrustedMalformedHeaderIsClosed(t *testing.T) {
	l, _ := newTestListener(t, true, time.Second)
	ch := acceptAsync(l)
	c := dial(t, l)
	if _, err := c.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 +1 443\r\nGET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	sc := mustAccept(t, ch)
	if got := sc.RemoteAddr().String(); strings.HasPrefix(got, "203.0.113.7") {
		t.Fatalf("malformed header must not set RemoteAddr, got %s", got)
	}
	expectClosed(t, sc, c)
}

func TestTrustedSlowHeaderTimesOut(t *testing.T) {
	l, _ := newTestListener(t, true, 200*time.Millisecond)
	ch := acceptAsync(l)
	c := dial(t, l)
	// Slowloris: a partial header, then silence.
	if _, err := c.Write([]byte("PROXY TCP4 203.0")); err != nil {
		t.Fatal(err)
	}
	sc := mustAccept(t, ch)
	start := time.Now()
	_, err := sc.(*Conn).Header()
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Header err = %v, want timeout", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("header timeout took %v", d)
	}
	expectClosed(t, sc, c)
}

func TestHeaderDeadlineIsClearedAfterHeader(t *testing.T) {
	l, _ := newTestListener(t, true, 150*time.Millisecond)
	ch := acceptAsync(l)
	c := dial(t, l)
	if _, err := c.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 1 2\r\n")); err != nil {
		t.Fatal(err)
	}
	sc := mustAccept(t, ch)
	if _, err := sc.(*Conn).Header(); err != nil {
		t.Fatalf("Header: %v", err)
	}
	go func() {
		time.Sleep(400 * time.Millisecond) // well past HeaderTimeout
		_, _ = c.Write([]byte("late"))
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(sc, buf); err != nil {
		t.Fatalf("read after header deadline: %v", err)
	}
}

func TestCallerReadDeadlineSurvivesHeader(t *testing.T) {
	l, _ := newTestListener(t, true, 5*time.Second)
	ch := acceptAsync(l)
	c := dial(t, l)
	sc := mustAccept(t, ch)
	// Set before the header is read (as net/http may do); it must apply to
	// the stream afterwards and also cap the header wait.
	if err := sc.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("PROXY UNKNOWN\r\n")); err != nil {
		t.Fatal(err)
	}
	// Read in a goroutine with a watchdog: if the caller's deadline were lost
	// the Read would block forever (the client never writes or closes), so
	// fail fast instead of hanging the package until go test's timeout.
	errCh := make(chan error, 1)
	go func() {
		_, err := sc.Read(make([]byte, 1))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("Read err = %v, want caller deadline timeout", err)
		}
	case <-time.After(2 * time.Second):
		_ = sc.Close() // unblock the reader
		t.Fatalf("caller deadline ignored: Read still blocked after 2s")
	}
}

// A connection handed back to net/http must keep io.ReaderFrom so cache hits
// on plain HTTP can use sendfile; it must only write after a valid header.
func TestConnReadFromDelegates(t *testing.T) {
	l, _ := newTestListener(t, true, time.Second)
	ch := acceptAsync(l)
	c := dial(t, l)
	if _, err := c.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n")); err != nil {
		t.Fatal(err)
	}
	sc := mustAccept(t, ch)
	rf, ok := sc.(io.ReaderFrom)
	if !ok {
		t.Fatalf("%T does not implement io.ReaderFrom", sc)
	}
	payload := strings.Repeat("cached-bytes ", 4096)
	n, err := rf.ReadFrom(strings.NewReader(payload))
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("ReadFrom = %d, %v", n, err)
	}
	got := make([]byte, len(payload))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != payload {
		t.Fatalf("client read: %v (match=%v)", err, string(got) == payload)
	}

	// Without a header, ReadFrom must fail and write nothing.
	ch = acceptAsync(l)
	c2 := dial(t, l)
	if _, err := c2.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	sc2 := mustAccept(t, ch)
	if n, err := sc2.(io.ReaderFrom).ReadFrom(strings.NewReader("leak")); err == nil || n != 0 {
		t.Fatalf("ReadFrom on rejected conn = %d, %v; want error", n, err)
	}
}

func TestRejectHintAndWideRanges(t *testing.T) {
	l, lc := newTestListener(t, true, time.Second)
	l.RejectHint = "ACME HTTP-01 needs the header too"
	ch := acceptAsync(l)
	c := dial(t, l)
	_, _ = c.Write([]byte("GET /.well-known/acme-challenge/x HTTP/1.1\r\n\r\n"))
	sc := mustAccept(t, ch)
	_, _ = sc.Read(make([]byte, 1))
	lc.mu.Lock()
	lines := append([]string(nil), lc.lines...)
	lc.mu.Unlock()
	if len(lines) != 1 || !strings.HasSuffix(lines[0], "; ACME HTTP-01 needs the header too") {
		t.Fatalf("log lines = %q, want hint appended", lines)
	}

	al, err := ParseAllowList([]string{"172.18.0.5", "172.18.0.0/16", "2001:db8::1", "2001:db8::/64", "::ffff:10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	wide := al.Wide()
	if len(wide) != 2 || wide[0].String() != "172.18.0.0/16" || wide[1].String() != "2001:db8::/64" {
		t.Fatalf("Wide() = %v", wide)
	}
}

func TestUntrustedSpoofedHeaderIsNotHonored(t *testing.T) {
	l, lc := newTestListener(t, false, time.Second)
	ch := acceptAsync(l)
	c := dial(t, l)
	spoof := "PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n"
	if _, err := c.Write([]byte(spoof)); err != nil {
		t.Fatal(err)
	}
	sc := mustAccept(t, ch)
	if _, ok := sc.(*Conn); ok {
		t.Fatalf("untrusted connection must not be wrapped")
	}
	if got, want := sc.RemoteAddr().String(), c.LocalAddr().String(); got != want {
		t.Fatalf("RemoteAddr = %s, want real peer %s", got, want)
	}
	buf := make([]byte, len(spoof))
	_ = sc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(sc, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != spoof {
		t.Fatalf("untrusted bytes altered: %q", buf)
	}
	if lc.count() != 0 {
		t.Fatalf("untrusted connections must not be logged")
	}
}

func TestSlowTrustedClientDoesNotBlockAccept(t *testing.T) {
	l, _ := newTestListener(t, true, 5*time.Second)
	conns := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()

	slow := dial(t, l) // never sends a header
	_ = slow
	fast := dial(t, l)
	if _, err := fast.Write([]byte("PROXY TCP4 203.0.113.9 198.51.100.1 1000 443\r\nping")); err != nil {
		t.Fatal(err)
	}

	addrs := make(chan string, 2)
	deadline := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case c := <-conns:
			t.Cleanup(func() { _ = c.Close() })
			go func() { addrs <- c.RemoteAddr().String() }() // per-connection goroutine, as net/http does
		case <-deadline:
			t.Fatalf("accept blocked by a slow trusted client (got %d of 2)", i)
		}
	}
	select {
	case a := <-addrs:
		if a != "203.0.113.9:1000" {
			t.Fatalf("first resolved RemoteAddr = %s, want the fast client", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("fast client's header was not processed while the slow one was pending")
	}
}

func TestRejectLogIsRateLimited(t *testing.T) {
	l, lc := newTestListener(t, true, time.Second)
	for i := 0; i < 5; i++ {
		ch := acceptAsync(l)
		c := dial(t, l)
		_, _ = c.Write([]byte("garbage\r\n"))
		sc := mustAccept(t, ch)
		_, _ = sc.Read(make([]byte, 1))
	}
	if n := lc.count(); n != 1 {
		t.Fatalf("log lines = %d, want 1 within the rate-limit window", n)
	}
}

// TestHTTPAndTLSEndToEnd runs real net/http servers on top of the wrapper,
// with the PROXY header preceding plain HTTP and a TLS ClientHello.
func TestHTTPAndTLSEndToEnd(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.RemoteAddr)
	})
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", useTLS), func(t *testing.T) {
			l, _ := newTestListener(t, true, time.Second)
			srv := httptest.NewUnstartedServer(handler)
			_ = srv.Listener.Close()
			srv.Listener = l
			if useTLS {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			t.Cleanup(srv.Close)

			raw := dial(t, l)
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := raw.Write([]byte("PROXY TCP6 2001:db8::77 2001:db8::1 40001 443\r\n")); err != nil {
				t.Fatal(err)
			}
			var conn net.Conn = raw
			if useTLS {
				tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test server cert
				if err := tc.Handshake(); err != nil {
					t.Fatalf("tls handshake: %v", err)
				}
				conn = tc
			}
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != "[2001:db8::77]:40001" {
				t.Fatalf("handler saw RemoteAddr %q", body)
			}
		})
	}
}
