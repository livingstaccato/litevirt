package fence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRedfishFence_VerifiedOnlyAfterOffObserved: a ForceOff the BMC accepts is
// a request, not proof. The fence succeeds — and its row is proof-grade —
// only once a PowerState read after the reset says Off, here after two reads
// that say PoweringOff.
func TestRedfishFence_VerifiedOnlyAfterOffObserved(t *testing.T) {
	shrinkVerifyKnobs(t, 5*time.Second, 20*time.Millisecond)
	b := newFakeBMC(t)
	b.afterOff = []string{"PoweringOff", "PoweringOff"}

	r := Execute(context.Background(), b.host(b.config()))
	if !r.Success || r.Method != "redfish" {
		t.Fatalf("fence = %+v, want a redfish success", r)
	}
	if !r.ProvedOff() {
		t.Errorf("a redfish fence observed Off is not proof-grade: %+v", r)
	}
	if got := b.resetCalls(); len(got) != 1 || got[0] != "node-1:ForceOff" {
		t.Errorf("resets = %v, want exactly one ForceOff", got)
	}
	if b.state("node-1") != "Off" {
		t.Errorf("system is %q after the fence", b.state("node-1"))
	}
	if !strings.Contains(r.Detail, "PowerState Off observed") {
		t.Errorf("detail %q does not say the power-off was observed", r.Detail)
	}
}

// TestRedfishFence_NeverOffIsAFailure: a BMC that accepts ForceOff while the
// system goes on reading On (or PoweringOff, the transitional state) has not
// fenced anything. The fence fails, its row is not proof-grade, and the detail
// says what the BMC last reported.
func TestRedfishFence_NeverOffIsAFailure(t *testing.T) {
	for _, stuck := range []string{"On", "PoweringOff", ""} {
		t.Run("stuck-"+stuck, func(t *testing.T) {
			shrinkVerifyKnobs(t, 300*time.Millisecond, 20*time.Millisecond)
			b := newFakeBMC(t)
			b.afterOff = []string{stuck}
			b.neverOff = true

			r := Execute(context.Background(), b.host(b.config()))
			if r.Success || r.ProvedOff() {
				t.Fatalf("a system that never read Off was fenced: %+v", r)
			}
			if r.Method != "redfish" {
				t.Errorf("method = %q, want redfish", r.Method)
			}
			if !strings.Contains(r.Detail, "not confirmed") || !strings.Contains(r.Detail, `PowerState "`+stuck+`"`) {
				t.Errorf("detail %q does not name the unconfirmed state %q", r.Detail, stuck)
			}
			if got := b.resetCalls(); len(got) != 1 {
				t.Errorf("resets = %v, want one ForceOff", got)
			}
		})
	}
}

// TestRedfishFence_AlreadyOff: a ForceOff is ALWAYS sent, as ipmi always
// sends chassis power off — a PowerState read is never a substitute for the
// command. A system already Off whose BMC accepts the reset, and one whose BMC
// refuses a ForceOff of an off system (409), are both verified by a read of
// Off afterwards. A re-fence of a host a verified fence already powered off
// must succeed, or the successor's recovery strands.
func TestRedfishFence_AlreadyOff(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		shrinkVerifyKnobs(t, 2*time.Second, 20*time.Millisecond)
		b := newFakeBMC(t)
		b.systems["node-1"] = "Off"
		if refuse {
			b.resetStatus = http.StatusConflict
		}
		r := Execute(context.Background(), b.host(b.config()))
		if !r.Success || !r.ProvedOff() {
			t.Fatalf("refuse=%v: fence of an off system = %+v, want a verified success", refuse, r)
		}
		if got := b.resetCalls(); len(got) != 1 || got[0] != "node-1:ForceOff" {
			t.Errorf("refuse=%v: resets = %v, want the ForceOff sent anyway", refuse, got)
		}
	}
}

// TestRedfishFence_RefusalIsToleratedOnlyWhenAlreadyOff: a refused ForceOff
// of a system that read On is a failed fence, even when the system reads Off
// afterwards — nothing the fence did powered it off, and a stale Off is the
// very reading the command exists to override.
func TestRedfishFence_RefusalIsToleratedOnlyWhenAlreadyOff(t *testing.T) {
	shrinkVerifyKnobs(t, 2*time.Second, 20*time.Millisecond)
	b := newFakeBMC(t)
	b.resetStatus = http.StatusConflict
	b.stateAfterRefusal = "Off"
	r := Execute(context.Background(), b.host(b.config()))
	if r.Success || r.ProvedOff() {
		t.Fatalf("a refused ForceOff of a system that read On fenced: %+v", r)
	}
	if !strings.Contains(r.Detail, "HTTP 409") {
		t.Errorf("detail %q does not carry the refusal", r.Detail)
	}
}

// TestRedfishFence_ResetRefusedFails: a reset the BMC refuses is a failed
// fence, with the BMC's status and reason in the detail and nothing verified.
func TestRedfishFence_ResetRefusedFails(t *testing.T) {
	shrinkVerifyKnobs(t, 300*time.Millisecond, 20*time.Millisecond)
	b := newFakeBMC(t)
	b.resetStatus = http.StatusInternalServerError
	b.resetBody = `{"error":"power controller busy"}`

	r := Execute(context.Background(), b.host(b.config()))
	if r.Success {
		t.Fatalf("a refused reset fenced: %+v", r)
	}
	if !strings.Contains(r.Detail, "HTTP 500") || !strings.Contains(r.Detail, "power controller busy") {
		t.Errorf("detail %q lacks the BMC's status and reason", r.Detail)
	}
}

// TestRedfishFence_PasswordNeverInDetail: fencing_log.detail is replicated and
// operator-readable. A BMC error that echoes the password must not put it
// there.
func TestRedfishFence_PasswordNeverInDetail(t *testing.T) {
	b := newFakeBMC(t)
	b.resetStatus = http.StatusBadRequest
	b.pass = `p"w/d&é 1`
	b.resetBody = `{"error":"rejected for user admin password ` + b.pass + ` json \"` + strings.ReplaceAll(b.pass, `"`, `\"`) +
		`\" query ` + url.QueryEscape(b.pass) + ` path ` + url.PathEscape(b.pass) + `"}`

	r := Execute(context.Background(), b.host(b.config()))
	if r.Success {
		t.Fatalf("fence succeeded: %+v", r)
	}
	for _, form := range []string{b.pass, strings.ReplaceAll(b.pass, `"`, `\"`), url.QueryEscape(b.pass), url.PathEscape(b.pass)} {
		if strings.Contains(r.Detail, form) {
			t.Errorf("detail carries the BMC password as %q: %q", form, r.Detail)
		}
	}
}

// TestRedfishFence_TLSIsVerified: the BMC's certificate is checked against the
// configured CA bundle, or the system roots when none is configured. A
// certificate neither vouches for is refused before any request — the login
// and its password included — reaches the server.
func TestRedfishFence_TLSIsVerified(t *testing.T) {
	b := newFakeBMC(t)
	// Every httptest TLS server shares one built-in certificate, so the wrong
	// CA has to be minted here.
	otherCA := selfSignedPEM(t)

	for name, ca := range map[string]string{"system-roots": "", "wrong-ca": otherCA} {
		t.Run(name, func(t *testing.T) {
			cfg := b.config()
			cfg.CACert = ca
			r := Execute(context.Background(), b.host(cfg))
			if r.Success {
				t.Fatalf("fenced through an unverified certificate: %+v", r)
			}
			if !strings.Contains(r.Detail, "certificate") {
				t.Errorf("detail %q does not name the certificate failure", r.Detail)
			}
		})
	}
	if reqs := b.requestLog(); len(reqs) != 0 {
		t.Errorf("requests reached the BMC over an unverified connection: %v", reqs)
	}
	if got := b.resetCalls(); len(got) != 0 {
		t.Errorf("resets = %v", got)
	}
}

// TestRedfishFence_SessionAuth: session auth (the default) logs in once, sends
// the token on every later request, never basic auth, and deletes its session
// afterwards.
func TestRedfishFence_SessionAuth(t *testing.T) {
	shrinkVerifyKnobs(t, 2*time.Second, 20*time.Millisecond)
	b := newFakeBMC(t)
	r := Execute(context.Background(), b.host(b.config()))
	if !r.Success {
		t.Fatalf("fence = %+v", r)
	}
	logins, logouts, open := b.sessions()
	if logins != 1 || logouts != 1 || open != 0 {
		t.Errorf("logins=%d logouts=%d open=%d, want 1/1/0", logins, logouts, open)
	}
	for _, req := range b.requestLog() {
		if strings.HasSuffix(req, " basic") {
			t.Errorf("session auth sent basic auth: %s", req)
		}
		if strings.Contains(req, "/Systems") && !strings.HasSuffix(req, " token") {
			t.Errorf("a system request without the session token: %s", req)
		}
	}
}

// TestRedfishFence_BasicAuth: basic auth sends credentials on every request
// and never opens a session.
func TestRedfishFence_BasicAuth(t *testing.T) {
	shrinkVerifyKnobs(t, 2*time.Second, 20*time.Millisecond)
	b := newFakeBMC(t)
	cfg := b.config()
	cfg.Auth = RedfishAuthBasic
	r := Execute(context.Background(), b.host(cfg))
	if !r.Success {
		t.Fatalf("fence = %+v", r)
	}
	if logins, _, _ := b.sessions(); logins != 0 {
		t.Errorf("basic auth opened %d session(s)", logins)
	}
	for _, req := range b.requestLog() {
		if strings.Contains(req, "/Systems") && !strings.HasSuffix(req, " basic") {
			t.Errorf("a system request without basic auth: %s", req)
		}
	}
}

// TestRedfishFence_WrongPasswordFails: a login the BMC refuses is a failed
// fence, and nothing is reset.
func TestRedfishFence_WrongPasswordFails(t *testing.T) {
	for _, auth := range []string{RedfishAuthSession, RedfishAuthBasic} {
		t.Run(auth, func(t *testing.T) {
			b := newFakeBMC(t)
			cfg := b.config()
			cfg.Auth = auth
			cfg.Pass = "wrong"
			r := Execute(context.Background(), b.host(cfg))
			if r.Success || !strings.Contains(r.Detail, "HTTP 401") {
				t.Fatalf("fence with a wrong password = %+v, want an HTTP 401 failure", r)
			}
			if got := b.resetCalls(); len(got) != 0 {
				t.Errorf("resets = %v", got)
			}
		})
	}
}

// TestRedfishFence_SystemSelection: with no system id the BMC must expose
// exactly one ComputerSystem; with several, the fence refuses rather than
// guess, and a configured id picks its own system and no other.
func TestRedfishFence_SystemSelection(t *testing.T) {
	shrinkVerifyKnobs(t, 2*time.Second, 20*time.Millisecond)
	b := newFakeBMC(t, "node-1", "node-2")

	r := Execute(context.Background(), b.host(b.config()))
	if r.Success || !strings.Contains(r.Detail, "2 ComputerSystems") {
		t.Fatalf("fence with two systems and no id = %+v, want a refusal naming both", r)
	}
	if got := b.resetCalls(); len(got) != 0 {
		t.Fatalf("an ambiguous fence reset %v", got)
	}

	cfg := b.config()
	cfg.SystemID = "node-2"
	r = Execute(context.Background(), b.host(cfg))
	if !r.Success {
		t.Fatalf("fence of node-2 = %+v", r)
	}
	if got := b.resetCalls(); len(got) != 1 || got[0] != "node-2:ForceOff" {
		t.Errorf("resets = %v, want node-2:ForceOff only", got)
	}
	if b.state("node-1") != "On" {
		t.Errorf("node-1 is %q; a fence of node-2 touched it", b.state("node-1"))
	}

	cfg.SystemID = "node-9"
	if r := Execute(context.Background(), b.host(cfg)); r.Success || !strings.Contains(r.Detail, `no ComputerSystem "node-9"`) {
		t.Errorf("fence of a missing system = %+v", r)
	}
}

// TestRedfishFence_ForceOffNotOffered: a system whose reset action does not
// offer ForceOff is refused, not reset with something gentler.
func TestRedfishFence_ForceOffNotOffered(t *testing.T) {
	b := newFakeBMC(t)
	b.allowable = []string{"On", "GracefulShutdown", "GracefulRestart"}
	r := Execute(context.Background(), b.host(b.config()))
	if r.Success || !strings.Contains(r.Detail, "does not offer ResetType ForceOff") {
		t.Fatalf("fence = %+v, want a refusal", r)
	}
	if got := b.resetCalls(); len(got) != 0 {
		t.Errorf("resets = %v", got)
	}
}

// TestRedfishFence_CredentialsStayOnTheEndpoint: a reference to another host,
// and a redirect anywhere, are not followed — either would hand that host the
// BMC credentials.
func TestRedfishFence_CredentialsStayOnTheEndpoint(t *testing.T) {
	var foreign atomic.Int32
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreign.Add(1)
		w.WriteHeader(204)
	}))
	t.Cleanup(elsewhere.Close)

	t.Run("foreign-member", func(t *testing.T) {
		b := newFakeBMC(t)
		b.memberRef["node-1"] = elsewhere.URL + "/redfish/v1/Systems/node-1"
		r := Execute(context.Background(), b.host(b.config()))
		if r.Success || !strings.Contains(r.Detail, "another host") {
			t.Fatalf("fence = %+v, want a refusal of the foreign reference", r)
		}
	})
	t.Run("redirect", func(t *testing.T) {
		shrinkVerifyKnobs(t, 300*time.Millisecond, 20*time.Millisecond)
		b := newFakeBMC(t)
		b.redirectTo = elsewhere.URL + "/redfish/v1/Systems/node-1/Actions/ComputerSystem.Reset"
		r := Execute(context.Background(), b.host(b.config()))
		if r.Success {
			t.Fatalf("a redirected reset fenced: %+v", r)
		}
	})
	if n := foreign.Load(); n != 0 {
		t.Errorf("%d request(s) went to another host", n)
	}
}

// TestRedfishFence_HungBMCIsBounded: a BMC that accepts the reset and never
// answers costs one request timeout, not the caller's whole budget, and is a
// failed fence.
func TestRedfishFence_HungBMCIsBounded(t *testing.T) {
	b := newFakeBMC(t)
	b.hangReset = time.Minute
	start := time.Now()
	r := Execute(context.Background(), b.host(b.config()))
	took := time.Since(start)
	if r.Success {
		t.Fatalf("a hung reset fenced: %+v", r)
	}
	if took > redfishSendTimeout+redfishLogoutTimeout+time.Second {
		t.Errorf("a hung BMC held the fence for %v", took)
	}
}

// TestRedfishFence_HonoursCancelledContext: the fence runs inside a failover
// cycle bounded by the lease; a cancelled context ends it — and still logs its
// session out, on a detached deadline, so BMCs that cap concurrent sessions
// are not locked out of the next fence.
func TestRedfishFence_HonoursCancelledContext(t *testing.T) {
	b := newFakeBMC(t)
	b.afterOff = []string{"On"}
	b.neverOff = true
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := Execute(ctx, b.host(b.config()))
	if r.Success {
		t.Fatalf("fence = %+v", r)
	}
	if took := time.Since(start); took > 2*time.Second+redfishLogoutTimeout {
		t.Errorf("fence ran %v past a 300ms context", took)
	}
	if logins, logouts, open := b.sessions(); logins != 1 || logouts != 1 || open != 0 {
		t.Errorf("a fence cut short left its session: logins=%d logouts=%d open=%d", logins, logouts, open)
	}
}

// TestRedfishFence_LogoutWithoutLocation: a BMC that answers the login with no
// Location header names the session in its body; the fence logs out of it.
func TestRedfishFence_LogoutWithoutLocation(t *testing.T) {
	shrinkVerifyKnobs(t, 2*time.Second, 20*time.Millisecond)
	b := newFakeBMC(t)
	b.noLocation = true
	if r := Execute(context.Background(), b.host(b.config())); !r.Success {
		t.Fatalf("fence = %+v", r)
	}
	if _, logouts, open := b.sessions(); logouts != 1 || open != 0 {
		t.Errorf("logouts=%d open=%d, want the session deleted", logouts, open)
	}
}

// TestRedfishFence_SystemBodyIDMustMatch: the configured system id is checked
// against the Id the system's own body reports, not only its URI: a BMC that
// aliases member URIs must not get another machine powered off.
func TestRedfishFence_SystemBodyIDMustMatch(t *testing.T) {
	b := newFakeBMC(t, "node-1", "node-2")
	b.bodyID["node-2"] = "node-1"
	cfg := b.config()
	cfg.SystemID = "node-2"
	r := Execute(context.Background(), b.host(cfg))
	if r.Success || !strings.Contains(r.Detail, `names itself "node-1"`) {
		t.Fatalf("fence of an aliased system = %+v, want a refusal", r)
	}
	if got := b.resetCalls(); len(got) != 0 {
		t.Errorf("resets = %v, want none", got)
	}
	if err := RedfishPowerOn(context.Background(), cfg); err == nil {
		t.Error("power on of an aliased system was allowed")
	}
}

// TestRedfishFence_NotConfigured: a host set to redfish with no endpoint fails
// its fence, as an ipmi host with no address does.
func TestRedfishFence_NotConfigured(t *testing.T) {
	r := Execute(context.Background(), HostConfig{Name: "h", FenceStrategy: "redfish"})
	if r.Success || r.Method != "redfish" {
		t.Fatalf("fence = %+v, want a redfish failure", r)
	}
}

// TestRedfish_BudgetFitsTheIPMIBudget: the coordinator's lease floor is
// derived from WorstCasePowerOff, which counts ipmitool's per-call budget. A
// Redfish fence must fit the same figure, or a slow but successful power-off
// is cut off mid-verification and strands the host's workloads.
func TestRedfish_BudgetFitsTheIPMIBudget(t *testing.T) {
	if redfishSendTimeout+redfishLogoutTimeout > ipmitoolPerCallTimeout {
		t.Errorf("redfish send %v + logout %v exceeds the per-call budget %v WorstCasePowerOff counts",
			redfishSendTimeout, redfishLogoutTimeout, ipmitoolPerCallTimeout)
	}
	if redfishRequestTimeout > redfishSendTimeout {
		t.Errorf("one request (%v) may outlast the whole send phase (%v)", redfishRequestTimeout, redfishSendTimeout)
	}
}

// TestRedfishPowerOnAndState: the operator's way back after a fence.
func TestRedfishPowerOnAndState(t *testing.T) {
	b := newFakeBMC(t)
	b.systems["node-1"] = "Off"
	ctx := context.Background()
	if st, err := RedfishPowerState(ctx, b.config()); err != nil || st != "Off" {
		t.Fatalf("state = %q, %v; want Off", st, err)
	}
	if err := RedfishPowerOn(ctx, b.config()); err != nil {
		t.Fatalf("power on: %v", err)
	}
	if got := b.resetCalls(); len(got) != 1 || got[0] != "node-1:On" {
		t.Errorf("resets = %v, want node-1:On", got)
	}
	if st, err := RedfishPowerState(ctx, b.config()); err != nil || st != "On" {
		t.Errorf("state after power on = %q, %v", st, err)
	}
}

// TestValidateRedfishConfig: a configuration a fence could not use, or could
// only use by sending the password in clear, is refused when it is set.
func TestValidateRedfishConfig(t *testing.T) {
	ok := []RedfishConfig{
		{},
		{Endpoint: "https://10.0.0.5"},
		{Endpoint: "https://bmc.example:8000/", Auth: "basic", SystemID: "System.Embedded.1"},
	}
	for _, c := range ok {
		if err := ValidateRedfishConfig(c); err != nil {
			t.Errorf("ValidateRedfishConfig(%+v) = %v, want ok", c, err)
		}
	}
	bad := map[string]RedfishConfig{
		"http":       {Endpoint: "http://10.0.0.5"},
		"no-scheme":  {Endpoint: "10.0.0.5:8000"},
		"userinfo":   {Endpoint: "https://admin:pw@10.0.0.5"},
		"path":       {Endpoint: "https://10.0.0.5/redfish/v1"},
		"query":      {Endpoint: "https://10.0.0.5?x=1"},
		"auth":       {Endpoint: "https://10.0.0.5", Auth: "digest"},
		"system-id":  {Endpoint: "https://10.0.0.5", SystemID: "../Managers/1"},
		"ca-not-pem": {Endpoint: "https://10.0.0.5", CACert: "not a certificate"},
	}
	for name, c := range bad {
		if err := ValidateRedfishConfig(c); err == nil {
			t.Errorf("%s: ValidateRedfishConfig(%+v) accepted it", name, c)
		}
	}
}

// TestAssurance_Redfish: a redfish fence that succeeded is verified — it
// observed the power-off — and proof-grade; one that failed is failed.
func TestAssurance_Redfish(t *testing.T) {
	if got := Assurance("redfish", LogFenced); got != AssuranceVerified {
		t.Errorf("Assurance(redfish, fenced) = %q, want verified", got)
	}
	if got := Assurance("redfish", LogPartial); got != AssuranceFailed {
		t.Errorf("Assurance(redfish, partial) = %q, want failed", got)
	}
	if !ProofGrade("redfish", LogFenced) || ProofGrade("redfish", LogPartial) {
		t.Error("ProofGrade(redfish) wrong")
	}
}

// selfSignedPEM mints a CA certificate that has signed nothing the fake BMC
// presents.
func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "not-the-bmc-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
