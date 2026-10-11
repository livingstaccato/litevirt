// Package acmedns obtains web UI certificates over ACME's DNS-01 challenge.
//
// HTTP-01 (autocert) needs the CA to reach the host on port 80, which a
// hypervisor on a management network usually cannot offer, and it cannot issue
// a wildcard. DNS-01 proves control of the name by publishing a TXT record
// instead, so the host only needs to reach its DNS server and the CA.
//
// A Provider is the small interface a DNS backend implements. RFC2136 (DNS
// UPDATE with a TSIG key) is the generic one: BIND, Knot, PowerDNS, Windows DNS
// and most appliances speak it, so it covers the common case without a
// vendor-specific API client.
package acmedns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Provider publishes and removes the TXT records DNS-01 validation reads.
// fqdn is absolute (trailing dot), e.g. "_acme-challenge.ui.example.com.".
type Provider interface {
	// Present adds a TXT record carrying value at fqdn. Other records at the
	// same name are kept: a certificate for a name and its wildcard needs two.
	Present(ctx context.Context, fqdn, value string) error
	// CleanUp removes exactly the record Present added.
	CleanUp(ctx context.Context, fqdn, value string) error
	// Visible reports whether the provider's server already answers fqdn with
	// value — the propagation check before the CA is asked to look.
	Visible(ctx context.Context, fqdn, value string) (bool, error)
}

// RFC2136 is a Provider that sends TSIG-signed DNS UPDATE messages (RFC 2136,
// RFC 8945) to the zone's primary server.
//
// TSIG is required. An unauthenticated update would let anyone who can reach
// the server write records in the zone, which for a zone that issues
// certificates is the ability to get one.
type RFC2136 struct {
	// Nameserver is host:port of the server that accepts updates.
	Nameserver string
	// Zone is the zone the records live in, absolute (trailing dot).
	Zone string
	// KeyName is the TSIG key name, absolute.
	KeyName string
	// Algorithm is the TSIG algorithm, a dns.Hmac* constant.
	Algorithm string
	// Secret is the base64 TSIG secret. Never logged.
	Secret string
	// TTL of the published record, seconds.
	TTL uint32
	// Net is "udp" or "tcp".
	Net string
	// Timeout bounds each exchange.
	Timeout time.Duration
}

// TSIGAlgorithm maps a configured algorithm name to its dns constant.
func TSIGAlgorithm(name string) (string, error) {
	switch strings.ToLower(strings.TrimSuffix(name, ".")) {
	case "", "hmac-sha256":
		return dns.HmacSHA256, nil
	case "hmac-sha384":
		return dns.HmacSHA384, nil
	case "hmac-sha512":
		return dns.HmacSHA512, nil
	case "hmac-sha224":
		return dns.HmacSHA224, nil
	case "hmac-sha1":
		return dns.HmacSHA1, nil
	}
	return "", fmt.Errorf("unsupported TSIG algorithm %q (want hmac-sha256, hmac-sha384, hmac-sha512, hmac-sha224 or hmac-sha1)", name)
}

// NormalizeNameserver adds the default port 53 to a bare host.
func NormalizeNameserver(ns string) string {
	if _, _, err := net.SplitHostPort(ns); err == nil {
		return ns
	}
	return net.JoinHostPort(strings.Trim(ns, "[]"), "53")
}

func (p *RFC2136) Present(ctx context.Context, fqdn, value string) error {
	return p.update(ctx, fqdn, value, true)
}

func (p *RFC2136) CleanUp(ctx context.Context, fqdn, value string) error {
	return p.update(ctx, fqdn, value, false)
}

func (p *RFC2136) txt(fqdn, value string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(fqdn), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: p.TTL},
		Txt: []string{value},
	}
}

func (p *RFC2136) client() *dns.Client {
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &dns.Client{
		Net:        p.Net,
		Timeout:    timeout,
		TsigSecret: map[string]string{dns.Fqdn(p.KeyName): p.Secret},
	}
}

func (p *RFC2136) update(ctx context.Context, fqdn, value string, add bool) error {
	if p.KeyName == "" || p.Secret == "" {
		return fmt.Errorf("rfc2136: a TSIG key is required")
	}
	if err := p.checkOwner(fqdn); err != nil {
		return err
	}
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(p.Zone))
	rr := []dns.RR{p.txt(fqdn, value)}
	if add {
		m.Insert(rr)
	} else {
		m.Remove(rr)
	}
	m.SetTsig(dns.Fqdn(p.KeyName), p.Algorithm, 300, time.Now().Unix())
	r, _, err := p.client().ExchangeContext(ctx, m, p.Nameserver)
	if err != nil {
		// miekg's errors name the failure (timeout, bad signature), never the
		// secret.
		return fmt.Errorf("rfc2136: update %s at %s: %w", fqdn, p.Nameserver, err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("rfc2136: %s refused the update of %s: %s", p.Nameserver, fqdn, dns.RcodeToString[r.Rcode])
	}
	return nil
}

// checkOwner refuses any name but an _acme-challenge record inside Zone: the
// TSIG key is the authority to edit the zone, and this provider only ever has
// a reason to write challenge records.
func (p *RFC2136) checkOwner(fqdn string) error {
	name := strings.ToLower(dns.Fqdn(fqdn))
	zone := strings.ToLower(dns.Fqdn(p.Zone))
	if !strings.HasPrefix(name, "_acme-challenge.") {
		return fmt.Errorf("rfc2136: refusing to write %s: only _acme-challenge records are written", fqdn)
	}
	if rest := strings.TrimPrefix(name, "_acme-challenge."); rest != zone && !strings.HasSuffix(rest, "."+zone) {
		return fmt.Errorf("rfc2136: refusing to write %s: it is not inside zone %s", fqdn, p.Zone)
	}
	return nil
}

func (p *RFC2136) Visible(ctx context.Context, fqdn, value string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	m.RecursionDesired = false
	c := p.client()
	c.TsigSecret = nil
	r, _, err := c.ExchangeContext(ctx, m, p.Nameserver)
	if err != nil {
		return false, err
	}
	for _, a := range r.Answer {
		if t, ok := a.(*dns.TXT); ok && strings.Join(t.Txt, "") == value {
			return true, nil
		}
	}
	return false, nil
}
