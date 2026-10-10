package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// emailConfig is the JSON stored in notification_targets.config for an "email"
// target. The SMTP password lives here, like a webhook URL does for the other
// target types: the table is already a sensitive, replicated, viewer-redacted
// store, so no second secret store is introduced. RedactConfig masks it in
// every list response.
type emailConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port,omitempty"`
	TLS      string   `json:"tls,omitempty"` // starttls (default) | implicit | none
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	// TLSSkipVerify turns certificate verification OFF. Verification is on by
	// default; this exists for lab relays with a self-signed certificate.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`
}

const (
	tlsStartTLS = "starttls"
	tlsImplicit = "implicit"
	tlsNone     = "none"

	// RedactedSecret replaces a stored secret in any config shown to a caller.
	RedactedSecret = "********"
)

// EmailTarget sends the notification as a plain-text email over SMTP.
type EmailTarget struct {
	name string
	cfg  emailConfig
	from *mail.Address
	to   []*mail.Address
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func newEmailTarget(name, configJSON string) (Target, error) {
	var c emailConfig
	if err := json.Unmarshal([]byte(configJSON), &c); err != nil {
		return nil, fmt.Errorf("email target %q: bad config: %w", name, err)
	}
	c.Host = strings.TrimSpace(c.Host)
	if c.Host == "" {
		return nil, fmt.Errorf("email target %q: host required", name)
	}
	if strings.ContainsAny(c.Host, " /\r\n") {
		return nil, fmt.Errorf("email target %q: host must be a bare hostname or IP", name)
	}
	switch c.TLS {
	case "":
		c.TLS = tlsStartTLS
	case tlsStartTLS, tlsImplicit, tlsNone:
	default:
		return nil, fmt.Errorf("email target %q: tls must be starttls, implicit or none", name)
	}
	if c.Port == 0 {
		switch c.TLS {
		case tlsImplicit:
			c.Port = 465
		case tlsNone:
			c.Port = 25
		default:
			c.Port = 587
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, fmt.Errorf("email target %q: port out of range", name)
	}
	if c.Password != "" && c.Username == "" {
		return nil, fmt.Errorf("email target %q: password without username", name)
	}
	if c.Username != "" && c.TLS == tlsNone && !isLoopbackHost(c.Host) {
		return nil, fmt.Errorf("email target %q: refusing to send credentials without TLS to a non-loopback host", name)
	}
	t := &EmailTarget{name: name, cfg: c}
	var err error
	if t.from, err = parseAddr(c.From); err != nil {
		return nil, fmt.Errorf("email target %q: from: %w", name, err)
	}
	if len(c.To) == 0 {
		return nil, fmt.Errorf("email target %q: at least one recipient required", name)
	}
	for _, r := range c.To {
		a, err := parseAddr(r)
		if err != nil {
			return nil, fmt.Errorf("email target %q: to %q: %w", name, r, err)
		}
		t.to = append(t.to, a)
	}
	return t, nil
}

func parseAddr(s string) (*mail.Address, error) {
	if s == "" {
		return nil, fmt.Errorf("required")
	}
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("invalid address")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return nil, fmt.Errorf("invalid address")
	}
	return a, nil
}

func (e *EmailTarget) Name() string { return e.name }

// EmailSubject renders the subject line. Exported for testing.
func EmailSubject(n Notification) string {
	cluster := ""
	if n.Cluster != "" {
		cluster = "[" + n.Cluster + "] "
	}
	s := fmt.Sprintf("%s%s: %s %s", cluster, n.Severity, n.Kind, n.Subject)
	// A subject is attacker-influenced (a VM or host name): never let it end the
	// header line.
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	return mime.QEncoding.Encode("utf-8", s)
}

func (e *EmailTarget) message(n Notification) []byte {
	var toList []string
	for _, a := range e.to {
		toList = append(toList, a.Address)
	}
	ts := n.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	var b strings.Builder
	b.WriteString("From: " + e.from.Address + "\n")
	b.WriteString("To: " + strings.Join(toList, ", ") + "\n")
	b.WriteString("Subject: " + EmailSubject(n) + "\n")
	b.WriteString("Date: " + ts.Format(time.RFC1123Z) + "\n")
	b.WriteString("MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n")
	fmt.Fprintf(&b, "Event:    %s\nSeverity: %s\nSubject:  %s\n", n.Kind, n.Severity, n.Subject)
	if n.Cluster != "" {
		fmt.Fprintf(&b, "Cluster:  %s\n", n.Cluster)
	}
	fmt.Fprintf(&b, "Time:     %s\n\n%s\n", ts.Format(time.RFC3339), n.Detail)
	return []byte(b.String())
}

func (e *EmailTarget) Send(ctx context.Context, n Notification) error {
	c := e.cfg
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.TLSSkipVerify} //nolint:gosec // opt-in lab escape hatch, off by default

	d := &net.Dialer{Timeout: 8 * time.Second}
	var conn net.Conn
	var err error
	if c.TLS == tlsImplicit {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return fmt.Errorf("smtp greeting from %s: %w", addr, err)
	}
	defer cl.Close()
	host, _ := os.Hostname()
	if host == "" || strings.ContainsAny(host, " \r\n") {
		host = "localhost"
	}
	if err := cl.Hello(host); err != nil {
		return fmt.Errorf("smtp EHLO: %w", err)
	}
	if c.TLS == tlsStartTLS {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp server %s does not offer STARTTLS (set tls to \"none\" to send in the clear)", addr)
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp STARTTLS: %w", err)
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("smtp auth as %q: %w", c.Username, err)
		}
	}
	if err := cl.Mail(e.from.Address); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, r := range e.to {
		if err := cl.Rcpt(r.Address); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", r.Address, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(e.message(n)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp end of data: %w", err)
	}
	_ = cl.Quit()
	return nil
}

// RedactConfig returns config with any stored secret masked, for display to a
// caller. Only email targets carry a secret apart from the URL (which existing
// callers already handle by role); other types are returned unchanged. A config
// that does not parse is returned unchanged rather than guessed at.
func RedactConfig(typ, configJSON string) string {
	if typ != "email" {
		return configJSON
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(configJSON), &m); err != nil {
		return configJSON
	}
	if p, ok := m["password"].(string); ok && p != "" {
		m["password"] = RedactedSecret
	}
	out, err := json.Marshal(m)
	if err != nil {
		return configJSON
	}
	return string(out)
}
