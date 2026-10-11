package fence

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBMC is a Redfish service over real TLS (httptest.NewTLSServer): a
// service root, a SessionService, a Systems collection and, per system, a
// PowerState and a ComputerSystem.Reset action. Its power model is scripted:
// after a ForceOff a system reads offAfter[i] for each successive read and
// then Off (or, with neverOff, never Off).
type fakeBMC struct {
	t   *testing.T
	srv *httptest.Server

	user, pass string

	mu sync.Mutex
	// systems maps an Id to its current PowerState.
	systems map[string]string
	order   []string
	// afterOff is the sequence of PowerState values read after a ForceOff,
	// before the system reads Off.
	afterOff []string
	reads    map[string]int // reads since the last ForceOff, per system
	offAt    map[string]bool
	neverOff bool

	resets      []string // "<id>:<ResetType>"
	logins      int
	logouts     int
	tokens      map[string]bool
	requests    []string // "<METHOD> <path> <auth>"
	resetStatus int      // non-zero: the reset answers with this status
	resetBody   string
	hangReset   time.Duration
	allowable   []string
	// memberRef overrides a system's @odata.id in the collection.
	memberRef map[string]string
	// resetTarget overrides the reset action target.
	resetTarget string
	// redirectTo makes the reset answer 307 to this URL.
	redirectTo string
}

func newFakeBMC(t *testing.T, ids ...string) *fakeBMC {
	t.Helper()
	if len(ids) == 0 {
		ids = []string{"node-1"}
	}
	b := &fakeBMC{
		t: t, user: "admin", pass: "bmc-s3cret",
		systems: map[string]string{}, reads: map[string]int{}, offAt: map[string]bool{},
		tokens: map[string]bool{}, memberRef: map[string]string{},
	}
	for _, id := range ids {
		b.systems[id] = "On"
		b.order = append(b.order, id)
	}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(b.serve))
	t.Cleanup(b.srv.Close)
	return b
}

// caPEM is the PEM of the server's self-signed certificate, which is its own
// CA: a RedfishConfig.CACert that makes the TLS verification pass.
func (b *fakeBMC) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.srv.Certificate().Raw}))
}

func (b *fakeBMC) config() RedfishConfig {
	return RedfishConfig{Endpoint: b.srv.URL, User: b.user, Pass: b.pass, CACert: b.caPEM()}
}

func (b *fakeBMC) host(cfg RedfishConfig) HostConfig {
	return HostConfig{Name: "kvm-test", FenceStrategy: "redfish", Redfish: cfg}
}

func (b *fakeBMC) state(id string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.systems[id]
}

func (b *fakeBMC) resetCalls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.resets...)
}

func (b *fakeBMC) sessions() (logins, logouts, open int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.logins, b.logouts, len(b.tokens)
}

func (b *fakeBMC) requestLog() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.requests...)
}

func (b *fakeBMC) authOK(r *http.Request) (string, bool) {
	if u, p, ok := r.BasicAuth(); ok {
		return "basic", u == b.user && p == b.pass
	}
	if tok := r.Header.Get("X-Auth-Token"); tok != "" {
		b.mu.Lock()
		defer b.mu.Unlock()
		return "token", b.tokens[tok]
	}
	return "none", false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (b *fakeBMC) serve(w http.ResponseWriter, r *http.Request) {
	kind, ok := b.authOK(r)
	b.mu.Lock()
	b.requests = append(b.requests, r.Method+" "+r.URL.Path+" "+kind)
	b.mu.Unlock()

	p := strings.TrimSuffix(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && p == "/redfish/v1":
		writeJSON(w, 200, map[string]any{
			"@odata.id": "/redfish/v1/",
			"Systems":   map[string]string{"@odata.id": "/redfish/v1/Systems"},
			"Links":     map[string]any{"Sessions": map[string]string{"@odata.id": "/redfish/v1/SessionService/Sessions"}},
		})
		return
	case r.Method == http.MethodPost && p == "/redfish/v1/SessionService/Sessions":
		var body struct{ UserName, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.UserName != b.user || body.Password != b.pass {
			writeJSON(w, 401, map[string]string{"error": "bad credentials"})
			return
		}
		b.mu.Lock()
		b.logins++
		tok := base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
		b.tokens[tok] = true
		b.mu.Unlock()
		w.Header().Set("X-Auth-Token", tok)
		w.Header().Set("Location", "/redfish/v1/SessionService/Sessions/"+tok)
		writeJSON(w, 201, map[string]string{"Id": tok})
		return
	}
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	switch {
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/redfish/v1/SessionService/Sessions/"):
		tok := strings.TrimPrefix(p, "/redfish/v1/SessionService/Sessions/")
		b.mu.Lock()
		delete(b.tokens, tok)
		b.logouts++
		b.mu.Unlock()
		w.WriteHeader(204)
		return
	case r.Method == http.MethodGet && p == "/redfish/v1/Systems":
		var members []map[string]string
		b.mu.Lock()
		for _, id := range b.order {
			ref := "/redfish/v1/Systems/" + id
			if o, ok := b.memberRef[id]; ok {
				ref = o
			}
			members = append(members, map[string]string{"@odata.id": ref})
		}
		b.mu.Unlock()
		writeJSON(w, 200, map[string]any{"Members": members, "Members@odata.count": len(members)})
		return
	}
	rest, found := strings.CutPrefix(p, "/redfish/v1/Systems/")
	if !found {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	id, action, _ := strings.Cut(rest, "/")
	b.mu.Lock()
	cur, known := b.systems[id]
	b.mu.Unlock()
	if !known {
		writeJSON(w, 404, map[string]string{"error": "no such system"})
		return
	}
	switch {
	case r.Method == http.MethodGet && action == "":
		b.mu.Lock()
		if b.offAt[id] {
			n := b.reads[id]
			b.reads[id]++
			switch {
			case n < len(b.afterOff):
				b.systems[id] = b.afterOff[n]
			case b.neverOff:
				// stays whatever afterOff last said, or On
			default:
				b.systems[id] = "Off"
			}
		}
		cur = b.systems[id]
		target := "/redfish/v1/Systems/" + id + "/Actions/ComputerSystem.Reset"
		if b.resetTarget != "" {
			target = b.resetTarget
		}
		reset := map[string]any{"target": target}
		if len(b.allowable) > 0 {
			reset["ResetType@Redfish.AllowableValues"] = b.allowable
		}
		b.mu.Unlock()
		writeJSON(w, 200, map[string]any{
			"@odata.id": "/redfish/v1/Systems/" + id, "Id": id, "PowerState": cur,
			"Actions": map[string]any{"#ComputerSystem.Reset": reset},
		})
	case r.Method == http.MethodPost && action == "Actions/ComputerSystem.Reset":
		var body struct{ ResetType string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		b.mu.Lock()
		hang, st, sb, redir := b.hangReset, b.resetStatus, b.resetBody, b.redirectTo
		b.resets = append(b.resets, id+":"+body.ResetType)
		b.mu.Unlock()
		if redir != "" {
			http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
			return
		}
		if hang > 0 {
			select {
			case <-r.Context().Done():
			case <-time.After(hang):
			}
			return
		}
		if st != 0 {
			w.WriteHeader(st)
			_, _ = w.Write([]byte(sb))
			return
		}
		b.mu.Lock()
		switch body.ResetType {
		case "ForceOff":
			b.offAt[id] = true
			b.reads[id] = 0
			if len(b.afterOff) == 0 && b.neverOff {
				b.systems[id] = "On"
			}
		case "On":
			b.offAt[id] = false
			b.systems[id] = "On"
		}
		b.mu.Unlock()
		w.WriteHeader(204)
	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}
