package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server: enough of RFC 5321 + STARTTLS + AUTH PLAIN
// to observe what a client actually put on the wire.
type fakeSMTP struct {
	ln       net.Listener
	cert     tls.Certificate
	implicit bool
	starttls bool // advertise STARTTLS
	mu       sync.Mutex
	authed   string // raw decoded AUTH PLAIN payload
	from     string
	rcpts    []string
	data     string
	sawTLS   bool
	plainDlg string // everything seen before TLS was up
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startFakeSMTP(t *testing.T, implicit, starttls bool) *fakeSMTP {
	t.Helper()
	f := &fakeSMTP{cert: selfSigned(t), implicit: implicit, starttls: starttls}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if implicit {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{f.cert}})
	}
	f.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, isTLS := c.(*tls.Conn)
	r := bufio.NewReader(c)
	w := func(s string) { fmt.Fprintf(c, "%s\r\n", s) }
	w("220 fake ESMTP")
	inData := false
	var data strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.mu.Lock()
		if !isTLS {
			f.plainDlg += line + "\n"
		}
		f.mu.Unlock()
		if inData {
			if line == "." {
				inData = false
				f.mu.Lock()
				f.data = data.String()
				f.mu.Unlock()
				w("250 queued")
				continue
			}
			data.WriteString(line + "\n")
			continue
		}
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			w("250-fake")
			if f.starttls && !isTLS {
				w("250-STARTTLS")
			}
			w("250 AUTH PLAIN")
		case up == "STARTTLS":
			w("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			c, isTLS = tc, true
			r = bufio.NewReader(tc)
			w = func(s string) { fmt.Fprintf(tc, "%s\r\n", s) }
			f.mu.Lock()
			f.sawTLS = true
			f.mu.Unlock()
		case strings.HasPrefix(up, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			f.mu.Lock()
			f.authed = string(raw)
			f.mu.Unlock()
			w("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.mu.Lock()
			f.from = line[len("MAIL FROM:"):]
			f.mu.Unlock()
			w("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			f.mu.Lock()
			f.rcpts = append(f.rcpts, line[len("RCPT TO:"):])
			f.mu.Unlock()
			w("250 ok")
		case up == "DATA":
			inData = true
			w("354 go")
		case up == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func emailCfg(t *testing.T, m map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(m)
	return string(b)
}

var testNote = Notification{Kind: "disk.smart.failing", Severity: SevError, Subject: "node1:/dev/sda", Detail: "SMART health FAILED", Cluster: "lab", Timestamp: time.Unix(1700000000, 0).UTC()}

func TestEmail_ConfigValidation(t *testing.T) {
	cases := map[string]map[string]any{
		"no host":         {"port": 25, "from": "a@b.c", "to": []string{"x@y.z"}},
		"no from":         {"host": "h", "to": []string{"x@y.z"}},
		"no to":           {"host": "h", "from": "a@b.c"},
		"bad from":        {"host": "h", "from": "not an address", "to": []string{"x@y.z"}},
		"bad to":          {"host": "h", "from": "a@b.c", "to": []string{"nope@@"}},
		"bad tls":         {"host": "h", "from": "a@b.c", "to": []string{"x@y.z"}, "tls": "magic"},
		"plain with auth": {"host": "mail.example.com", "from": "a@b.c", "to": []string{"x@y.z"}, "tls": "none", "username": "u", "password": "p"},
		"header inject":   {"host": "h", "from": "a@b.c\r\nBcc: z@z.z", "to": []string{"x@y.z"}},
	}
	for name, c := range cases {
		if _, err := NewTarget("t", "email", emailCfg(t, c)); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
	if _, err := NewTarget("t", "email", emailCfg(t, map[string]any{"host": "h", "from": "a@b.c", "to": []string{"x@y.z"}})); err != nil {
		t.Errorf("minimal valid config rejected: %v", err)
	}
}

func TestEmail_StartTLSWithAuth_VerifiesCertByDefault(t *testing.T) {
	f := startFakeSMTP(t, false, true)
	cfg := map[string]any{"host": "127.0.0.1", "port": f.port(), "from": "lv@example.com", "to": []string{"a@example.com", "b@example.com"},
		"username": "u", "password": "pw"}
	tg, err := NewTarget("mail", "email", emailCfg(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	// Self-signed server cert: verification is ON by default so this must fail,
	// and must fail BEFORE any credential or message leaves the client.
	err = tg.Send(context.Background(), testNote)
	if err == nil {
		t.Fatal("self-signed cert accepted with default settings")
	}
	if strings.Contains(err.Error(), "pw") && strings.Contains(err.Error(), "password") {
		t.Errorf("error leaks credential: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.authed != "" || f.data != "" {
		t.Errorf("credentials/message sent despite failed verification: auth=%q data=%q", f.authed, f.data)
	}
}

func TestEmail_StartTLSWithAuth_Delivers(t *testing.T) {
	f := startFakeSMTP(t, false, true)
	cfg := map[string]any{"host": "127.0.0.1", "port": f.port(), "from": "lv@example.com", "to": []string{"a@example.com", "b@example.com"},
		"username": "u", "password": "pw", "tls_skip_verify": true}
	tg, err := NewTarget("mail", "email", emailCfg(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if err := tg.Send(context.Background(), testNote); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.sawTLS {
		t.Error("no STARTTLS upgrade")
	}
	if f.authed != "\x00u\x00pw" {
		t.Errorf("auth payload %q", f.authed)
	}
	if strings.Contains(f.plainDlg, "AUTH") || strings.Contains(f.plainDlg, "Subject") {
		t.Errorf("secret or content sent before TLS: %q", f.plainDlg)
	}
	if len(f.rcpts) != 2 || !strings.Contains(f.rcpts[0], "a@example.com") || !strings.Contains(f.rcpts[1], "b@example.com") {
		t.Errorf("rcpts %v", f.rcpts)
	}
	if !strings.Contains(f.from, "lv@example.com") {
		t.Errorf("from %q", f.from)
	}
	for _, want := range []string{"Subject: [lab] error: disk.smart.failing node1:/dev/sda", "From: lv@example.com", "To: a@example.com, b@example.com", "SMART health FAILED"} {
		if !strings.Contains(f.data, want) {
			t.Errorf("message missing %q:\n%s", want, f.data)
		}
	}
}

func TestEmail_ImplicitTLS(t *testing.T) {
	f := startFakeSMTP(t, true, false)
	cfg := map[string]any{"host": "127.0.0.1", "port": f.port(), "tls": "implicit", "from": "lv@example.com", "to": []string{"a@example.com"}, "tls_skip_verify": true}
	tg, err := NewTarget("mail", "email", emailCfg(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if err := tg.Send(context.Background(), testNote); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(f.data, "SMART health FAILED") {
		t.Errorf("not delivered: %q", f.data)
	}
}

func TestEmail_StartTLSRequiredButNotOffered(t *testing.T) {
	f := startFakeSMTP(t, false, false) // server does not advertise STARTTLS
	cfg := map[string]any{"host": "127.0.0.1", "port": f.port(), "from": "lv@example.com", "to": []string{"a@example.com"}}
	tg, _ := NewTarget("mail", "email", emailCfg(t, cfg))
	if err := tg.Send(context.Background(), testNote); err == nil {
		t.Fatal("downgraded to plaintext silently")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.data != "" {
		t.Errorf("message sent in the clear: %q", f.data)
	}
}

func TestEmail_ExplicitNoTLS_LoopbackNoAuth(t *testing.T) {
	f := startFakeSMTP(t, false, false)
	cfg := map[string]any{"host": "127.0.0.1", "port": f.port(), "tls": "none", "from": "lv@example.com", "to": []string{"a@example.com"}}
	tg, err := NewTarget("mail", "email", emailCfg(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if err := tg.Send(context.Background(), testNote); err != nil {
		t.Fatal(err)
	}
}

func TestEmail_HeaderInjectionInSubject(t *testing.T) {
	f := startFakeSMTP(t, false, false)
	cfg := map[string]any{"host": "127.0.0.1", "port": f.port(), "tls": "none", "from": "lv@example.com", "to": []string{"a@example.com"}}
	tg, _ := NewTarget("mail", "email", emailCfg(t, cfg))
	n := testNote
	n.Subject = "vm1\r\nBcc: evil@example.com"
	if err := tg.Send(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	head := strings.SplitN(f.data, "\n\n", 2)[0]
	for _, l := range strings.Split(head, "\n") {
		if strings.HasPrefix(strings.ToLower(l), "bcc:") {
			t.Errorf("header injected via subject: %q", head)
		}
	}
}

func TestEmail_RedactConfig(t *testing.T) {
	in := emailCfg(t, map[string]any{"host": "h", "from": "a@b.c", "to": []string{"x@y.z"}, "username": "u", "password": "hunter2"})
	out := RedactConfig("email", in)
	if strings.Contains(out, "hunter2") {
		t.Errorf("password survived redaction: %s", out)
	}
	if !strings.Contains(out, `"host":"h"`) || !strings.Contains(out, "x@y.z") {
		t.Errorf("redaction ate non-secret fields: %s", out)
	}
	// Non-email configs are untouched (existing webhook behaviour).
	w := `{"url":"https://x"}`
	if RedactConfig("webhook", w) != w {
		t.Error("webhook config changed")
	}
}
