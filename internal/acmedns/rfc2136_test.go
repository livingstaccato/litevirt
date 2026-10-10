package acmedns

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeZone is an authoritative server for one zone that accepts TSIG-signed
// UPDATEs and answers TXT queries from what they wrote.
type fakeZone struct {
	zone, keyName, secret string
	mu                    sync.Mutex
	txt                   map[string][]string // fqdn -> values
	updates               int
	addr                  string
}

func startFakeZone(t *testing.T, zone, keyName, secret string) *fakeZone {
	t.Helper()
	z := &fakeZone{zone: dns.Fqdn(zone), keyName: dns.Fqdn(keyName), secret: secret, txt: map[string][]string{}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	z.addr = pc.LocalAddr().String()
	srv := &dns.Server{
		PacketConn: pc,
		TsigSecret: map[string]string{z.keyName: secret},
		MsgAcceptFunc: func(dh dns.Header) dns.MsgAcceptAction {
			return dns.MsgAccept // UPDATE is refused by the default accept func
		},
		Handler: dns.HandlerFunc(z.serve),
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return z
}

func (z *fakeZone) serve(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	signed := r.IsTsig() != nil
	switch r.Opcode {
	case dns.OpcodeUpdate:
		if !signed || w.TsigStatus() != nil {
			m.Rcode = dns.RcodeNotAuth
			_ = w.WriteMsg(m)
			return
		}
		if len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, z.zone) {
			m.Rcode = dns.RcodeNotZone
			break
		}
		z.mu.Lock()
		z.updates++
		for _, rr := range r.Ns {
			t, ok := rr.(*dns.TXT)
			if !ok {
				continue
			}
			name := strings.ToLower(t.Hdr.Name)
			val := strings.Join(t.Txt, "")
			if t.Hdr.Class == dns.ClassNONE { // RFC 2136 §2.5.4: delete this RR
				kept := z.txt[name][:0]
				for _, v := range z.txt[name] {
					if v != val {
						kept = append(kept, v)
					}
				}
				z.txt[name] = kept
			} else {
				z.txt[name] = append(z.txt[name], val)
			}
		}
		z.mu.Unlock()
	default:
		z.mu.Lock()
		for _, q := range r.Question {
			for _, v := range z.txt[strings.ToLower(q.Name)] {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{v}})
			}
		}
		z.mu.Unlock()
	}
	if signed && w.TsigStatus() == nil {
		m.SetTsig(z.keyName, dns.HmacSHA256, 300, time.Now().Unix())
	}
	_ = w.WriteMsg(m)
}

func testSecret() string {
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

func newProvider(z *fakeZone, secret string) *RFC2136 {
	return &RFC2136{Nameserver: z.addr, Zone: z.zone, KeyName: z.keyName, Algorithm: dns.HmacSHA256,
		Secret: secret, TTL: 60, Net: "udp", Timeout: 2 * time.Second}
}

// The provider publishes and removes exactly the challenge record, with a
// TSIG-signed UPDATE.
//
// Mutation: drop m.SetTsig in update — the server answers NOTAUTH and Present
// fails.
func TestRFC2136_PresentsAndCleansUp(t *testing.T) {
	z := startFakeZone(t, "example.test", "litevirt-acme", testSecret())
	p := newProvider(z, testSecret())
	ctx := context.Background()
	const fqdn = "_acme-challenge.ui.example.test."
	if err := p.Present(ctx, fqdn, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := p.Present(ctx, fqdn, "v2"); err != nil {
		t.Fatal(err)
	}
	if ok, err := p.Visible(ctx, fqdn, "v1"); err != nil || !ok {
		t.Fatalf("v1 not visible: %v %v", ok, err)
	}
	if err := p.CleanUp(ctx, fqdn, "v1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := p.Visible(ctx, fqdn, "v1"); ok {
		t.Fatal("CleanUp left the record")
	}
	if ok, _ := p.Visible(ctx, fqdn, "v2"); !ok {
		t.Fatal("CleanUp removed a record it did not add (a name and its wildcard share one owner name)")
	}
}

// A wrong secret is refused, and the error never carries the secret.
func TestRFC2136_AWrongKeyIsRefused(t *testing.T) {
	z := startFakeZone(t, "example.test", "litevirt-acme", testSecret())
	wrong := base64.StdEncoding.EncodeToString([]byte("not-the-secret-not-the-secret-xx"))
	err := newProvider(z, wrong).Present(context.Background(), "_acme-challenge.ui.example.test.", "v")
	if err == nil {
		t.Fatal("an update signed with the wrong key was accepted")
	}
	if strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), testSecret()) {
		t.Fatalf("the error leaks a TSIG secret: %v", err)
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.updates != 0 {
		t.Fatal("the zone applied an unauthenticated update")
	}
}

func TestRFC2136_RequiresAKey(t *testing.T) {
	p := &RFC2136{Nameserver: "127.0.0.1:1", Zone: "example.test."}
	if err := p.Present(context.Background(), "_acme-challenge.example.test.", "v"); err == nil {
		t.Fatal("an unauthenticated update was attempted")
	}
}

func TestTSIGAlgorithmAndNameserver(t *testing.T) {
	if a, err := TSIGAlgorithm(""); err != nil || a != dns.HmacSHA256 {
		t.Fatalf("default algorithm = %q, %v", a, err)
	}
	if _, err := TSIGAlgorithm("hmac-md5"); err == nil {
		t.Fatal("hmac-md5 accepted")
	}
	if got := NormalizeNameserver("10.0.0.53"); got != "10.0.0.53:53" {
		t.Fatalf("NormalizeNameserver = %s", got)
	}
	if got := NormalizeNameserver("ns1:5353"); got != "ns1:5353" {
		t.Fatalf("NormalizeNameserver = %s", got)
	}
}
