package storage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeISCSIAdm is an iscsiadm that keeps a session table and a node-record
// table, and records every call. Logging in to a target that has a node
// record opens a session; one with no record fails as iscsiadm does ("No
// records found", exit 21) until a discovery adds it.
type fakeISCSIAdm struct {
	mu        sync.Mutex
	sessions  []string // "portal target" as `iscsiadm -m session` prints them
	records   map[string]bool
	discovers map[string]string // portal -> target a sendtargets discovery finds
	loginErr  string            // non-empty: every login fails with this output
	pending   bool              // a login is in progress in iscsid: "already present", no session listed
	listErr   string            // non-empty: `-m session` fails with this output
	staleTag  bool              // a stale-tag record beside the good one: the login opens the session and exits 19
	calls     [][]string
}

func newFakeISCSIAdm() *fakeISCSIAdm {
	return &fakeISCSIAdm{records: map[string]bool{}, discovers: map[string]string{}}
}

func (f *fakeISCSIAdm) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	if name != "iscsiadm" {
		return nil, errors.New("not iscsiadm")
	}
	a := strings.Join(args, " ")
	switch {
	case a == "-m session":
		if f.listErr != "" {
			return []byte(f.listErr), exitErr(1)
		}
		if len(f.sessions) == 0 {
			return []byte("iscsiadm: No active sessions."), exitErr(21)
		}
		var b strings.Builder
		for i, s := range f.sessions {
			p, t, _ := strings.Cut(s, " ")
			b.WriteString("tcp: [" + string(rune('1'+i)) + "] " + p + ",1 " + t + " (non-flash)\n")
		}
		return []byte(b.String()), nil
	case strings.HasPrefix(a, "-m discovery"):
		portal := argAfter(args, "-p")
		if t, ok := f.discovers[portal]; ok {
			f.records[portal+" "+t] = true
			return []byte(portal + ",1 " + t), nil
		}
		return []byte("iscsiadm: cannot make connection to " + portal), exitErr(4)
	case strings.HasPrefix(a, "-m node -o new"):
		f.records[argAfter(args, "-p")+" "+argAfter(args, "-T")] = true
		return []byte("New iSCSI node [tcp:[hw=,ip=,net_if=,iscsi_if=default] " + argAfter(args, "-p") + "," + argAfter(args, "-T") + "] added"), nil
	case strings.HasPrefix(a, "-m node") && strings.HasSuffix(a, "--login"):
		portal, target := argAfter(args, "-p"), argAfter(args, "-T")
		if f.pending {
			return []byte("iscsiadm: default: 1 session requested, but 1 already present."), exitErr(15)
		}
		if f.loginErr != "" {
			return []byte(f.loginErr), exitErr(8)
		}
		if !f.records[portal+" "+target] {
			return []byte("iscsiadm: No records found"), exitErr(21)
		}
		for _, s := range f.sessions {
			if s == portal+" "+target {
				return []byte("iscsiadm: default: 1 session requested, but 1 already present."), exitErr(15)
			}
		}
		f.sessions = append(f.sessions, portal+" "+target)
		if f.staleTag {
			return []byte("Login to [iface: default, target: " + target + ", portal: " + portal + ",2] successful.\n" +
				"iscsiadm: Could not login to [iface: default, target: " + target + ", portal: " + portal + ",1].\n" +
				"iscsiadm: initiator reported error (19 - encountered non-retryable iSCSI login failure)"), exitErr(19)
		}
		return []byte("Login to [iface: default, target: " + target + ", portal: " + portal + "] successful."), nil
	}
	return []byte("unexpected"), errors.New("unexpected iscsiadm call: " + a)
}

func argAfter(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeISCSIAdm) count(sub string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			n++
		}
	}
	return n
}

// mutating reports any call that would rewrite or delete a node record, or
// change its settings (node.startup, CHAP): litevirt must never make one on
// a re-login.
func (f *fakeISCSIAdm) mutating() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var bad []string
	for _, c := range f.calls {
		j := strings.Join(c, " ")
		for _, w := range []string{"-o update", "-o delete", "--op=update", "--op=delete", "-n ", "node.startup", "auth", "--logout"} {
			if strings.Contains(j, w) {
				bad = append(bad, j)
				break
			}
		}
		// A discovery without "-o new" updates the records it finds from
		// iscsid.conf and deletes the ones it does not.
		if strings.Contains(j, "-m discovery") && !strings.Contains(j, "-o new") {
			bad = append(bad, j)
		}
	}
	return bad
}

const tgt = "iqn.2003-01.org.example:store"

func TestEnsureISCSISession_PresentDoesNothing(t *testing.T) {
	f := newFakeISCSIAdm()
	f.records["10.0.0.5:3260 "+tgt] = true
	f.sessions = []string{"10.0.0.5:3260 " + tgt}
	in, err := ensureISCSISession(context.Background(), f.run, tgt, "10.0.0.5:3260")
	if err != nil || in {
		t.Fatalf("present session: loggedIn=%v err=%v, want false, nil", in, err)
	}
	if n := f.count("--login"); n != 0 {
		t.Fatalf("%d logins with the session present, want 0", n)
	}
}

// The case the lab hit: after a reboot the node record is there (startup =
// manual), the session is not. litevirt logs in through the operator's record
// and changes nothing in it.
func TestEnsureISCSISession_MissingLogsInThroughTheExistingRecord(t *testing.T) {
	f := newFakeISCSIAdm()
	f.records["10.0.0.5:3260 "+tgt] = true
	in, err := ensureISCSISession(context.Background(), f.run, tgt, "10.0.0.5:3260")
	if err != nil || !in {
		t.Fatalf("missing session: loggedIn=%v err=%v, want true, nil", in, err)
	}
	if n := f.count("-m node -T " + tgt + " -p 10.0.0.5:3260 --login"); n != 1 {
		t.Fatalf("%d logins, want 1; calls %v", n, f.calls)
	}
	if n := f.count("-m discovery"); n != 0 {
		t.Fatalf("discovery run with the record present: %v", f.calls)
	}
	if bad := f.mutating(); len(bad) > 0 {
		t.Fatalf("calls that rewrite node records: %v", bad)
	}
}

// A portal spelled without a port, or a session to the target through another
// portal, is not this pool's session.
func TestEnsureISCSISession_MatchesTheSessionByPortal(t *testing.T) {
	f := newFakeISCSIAdm()
	f.records["10.0.0.5:3260 "+tgt] = true
	f.sessions = []string{"10.0.0.6:3260 " + tgt}
	if in, err := ensureISCSISession(context.Background(), f.run, tgt, "10.0.0.5:3260"); err != nil || !in {
		t.Fatalf("session through another portal only: loggedIn=%v err=%v, want a login", in, err)
	}

	g := newFakeISCSIAdm()
	g.sessions = []string{"10.0.0.5:3260 " + strings.ToUpper(tgt)}
	if in, err := ensureISCSISession(context.Background(), g.run, tgt, "10.0.0.5"); err != nil || in {
		t.Fatalf("pool portal without a port, session on :3260: loggedIn=%v err=%v, want it found", in, err)
	}
}

// No record at all (a host that never ran discovery for the portal): this
// target's record alone is created (-o new), then the login. No discovery: a
// sendtargets discovery would add a record for every target the portal
// advertises, which a node.startup = automatic default logs in at boot.
func TestEnsureISCSISession_NoRecordCreatesThisTargetsRecordOnly(t *testing.T) {
	f := newFakeISCSIAdm()
	f.discovers["10.0.0.5:3260"] = tgt
	f.records["10.0.0.5:3260 iqn.2003-01.org.example:other"] = true // the operator's, untouched
	in, err := ensureISCSISession(context.Background(), f.run, tgt, "10.0.0.5:3260")
	if err != nil || !in {
		t.Fatalf("no record: loggedIn=%v err=%v, want true, nil", in, err)
	}
	if n := f.count("-m node -o new -T " + tgt + " -p 10.0.0.5:3260"); n != 1 {
		t.Fatalf("want one add-only record of this target; calls %v", f.calls)
	}
	if n := f.count("-m discovery"); n != 0 {
		t.Fatalf("discovery run: %v", f.calls)
	}
	if bad := f.mutating(); len(bad) > 0 {
		t.Fatalf("calls that rewrite node records: %v", bad)
	}
}

// "already present" while no session is listed is a login still in progress
// in iscsid (an earlier, timed-out iscsiadm's): not a session.
func TestEnsureISCSISession_AlreadyPresentWithoutASessionIsNotUp(t *testing.T) {
	f := newFakeISCSIAdm()
	f.records["10.0.0.5:3260 "+tgt] = true
	f.pending = true
	if _, err := ensureISCSISession(context.Background(), f.run, tgt, "10.0.0.5:3260"); err == nil ||
		!strings.Contains(err.Error(), "in progress") {
		t.Fatalf("pending login: err=%v, want it reported as no session yet", err)
	}
}

func TestEnsureISCSISession_LoginFailureIsTheReason(t *testing.T) {
	f := newFakeISCSIAdm()
	f.records["10.0.0.5:3260 "+tgt] = true
	f.loginErr = "iscsiadm: Could not login to [iface: default, target: " + tgt + ", portal: 10.0.0.5,3260].\niscsiadm: initiator reported error (24 - iSCSI login failed due to authorization failure)"
	_, err := ensureISCSISession(context.Background(), f.run, tgt, "10.0.0.5:3260")
	if err == nil || !strings.Contains(err.Error(), "authorization failure") || !strings.Contains(err.Error(), tgt) {
		t.Fatalf("login failure: err=%v, want the reason and the target", err)
	}
}

func TestEnsureISCSISession_ListFailureIsAnError(t *testing.T) {
	f := newFakeISCSIAdm()
	f.listErr = "iscsiadm: could not connect to iscsid"
	if _, err := ensureISCSISession(context.Background(), f.run, tgt, "10.0.0.5:3260"); err == nil ||
		!strings.Contains(err.Error(), "iscsid") {
		t.Fatalf("list failure: err=%v, want it reported", err)
	}
	if n := f.count("--login"); n != 0 {
		t.Fatalf("logged in without knowing the sessions: %v", f.calls)
	}
}

// EnsureISCSISession takes the pool's stored target and portal, the driver's
// default portal when none is stored.
func TestEnsureISCSISession_FromPoolConfig(t *testing.T) {
	f := newFakeISCSIAdm()
	f.records["127.0.0.1 "+tgt] = true
	defer OverrideISCSICommandForTest(f.run)()
	if in, err := EnsureISCSISession(context.Background(), Config{Driver: "iscsi", Source: tgt}); err != nil || !in {
		t.Fatalf("default portal: loggedIn=%v err=%v", in, err)
	}
	if _, err := EnsureISCSISession(context.Background(), Config{Driver: "nfs", Source: "x:/y"}); err == nil {
		t.Fatal("an nfs pool has no iSCSI session; want an error")
	}
}

// A stale-tag record beside the good one (an add-only discovery leaves it):
// the login opens the session through the good one and exits 19 for the
// stale one. The session is listed, so the pool has its session; reporting
// it missing would degrade the pool for one pass.
func TestEnsureISCSISession_LoginErrorWithTheSessionListedIsUp(t *testing.T) {
	f := newFakeISCSIAdm()
	f.records["10.0.0.5:3260 "+tgt] = true
	f.staleTag = true
	in, err := ensureISCSISession(context.Background(), f.run, tgt, "10.0.0.5:3260")
	if err != nil || !in {
		t.Fatalf("login with a stale-tag record: loggedIn=%v err=%v, want true, nil", in, err)
	}
}
