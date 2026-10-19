package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordISCSIAdm is an iscsiadm whose node records are files in a node
// database directory laid out as open-iscsi lays it out
// (<db>/<target>/<ip>,<port>,<tpgt>/default), each holding the record's
// settings. A record made by a discovery or `-o new` takes iscsid.conf's
// settings (conf); a plain sendtargets discovery rewrites every record the
// portal returns from conf and deletes the ones it does not, as iscsiadm
// does. A login goes through every record of the target at the portal and
// succeeds through one whose credentials the target accepts and whose portal
// group tag is the target's current one.
type recordISCSIAdm struct {
	mu        sync.Mutex
	db        string
	conf      map[string]string        // iscsid.conf: the settings a new or rewritten record gets
	adverts   map[string][]iscsiAdvert // portal (ip:port) -> what a sendtargets discovery returns
	accept    map[string]string        // target -> the "user:password" it accepts
	tpgt      map[string]int           // target -> the portal group tag it answers with
	sessions  map[string]bool          // "portal target"
	timeout   bool                     // every login times out: the portal stopped answering mid-login
	terse     bool                     // a refused login prints no reason, only its exit status says why
	logoutErr string                   // set: every logout fails with this output
	hook      func(args []string)      // runs before each call, outside mu: the test's scheduler
	calls     []string
}

type iscsiAdvert struct {
	target string
	tpgt   int
}

const (
	prepTarget = "iqn.2003-01.org.example:san"
	prepOther  = "iqn.2003-01.org.example:other"
	authUser   = "node.session.auth.username"
	authPass   = "node.session.auth.password"
)

// exitErr is the error a real iscsiadm's exit status gives: an
// *exec.ExitError, as realCmd returns it.
func exitErr(code int) error {
	if e, ok := exitErrs.Load(code); ok {
		return e.(error)
	}
	err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run()
	exitErrs.Store(code, err)
	return err
}

var exitErrs sync.Map

func newRecordISCSIAdm(t *testing.T) *recordISCSIAdm {
	t.Helper()
	f := &recordISCSIAdm{
		db:       t.TempDir(),
		conf:     map[string]string{authUser: "conf", authPass: "conf-secret", "node.startup": "manual"},
		adverts:  map[string][]iscsiAdvert{},
		accept:   map[string]string{},
		tpgt:     map[string]int{},
		sessions: map[string]bool{},
	}
	prev := iscsiNodeDBDirs
	iscsiNodeDBDirs = []string{f.db}
	t.Cleanup(func() { iscsiNodeDBDirs = prev })
	return f
}

// fakePortal is how iscsiadm reads a -p argument: ip[:port], port 3260.
func fakePortal(p string) string {
	if !strings.Contains(p, ":") {
		return p + ":3260"
	}
	return p
}

func (f *recordISCSIAdm) recDir(target, portal string, tpgt int) string {
	return filepath.Join(f.db, target, strings.Replace(fakePortal(portal), ":", ",", 1)+","+strconv.Itoa(tpgt))
}

// setRecord writes a record as an operator would leave it.
func (f *recordISCSIAdm) setRecord(t *testing.T, target, portal string, tpgt int, settings map[string]string) {
	t.Helper()
	if err := f.writeRec(target, portal, tpgt, settings); err != nil {
		t.Fatal(err)
	}
}

func (f *recordISCSIAdm) writeRec(target, portal string, tpgt int, settings map[string]string) error {
	dir := f.recDir(target, portal, tpgt)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + " = " + settings[k] + "\n")
	}
	return os.WriteFile(filepath.Join(dir, "default"), []byte(b.String()), 0o600)
}

type fakeRec struct {
	tpgt     int
	settings map[string]string
	raw      string
}

// recs are the target's records at the portal.
func (f *recordISCSIAdm) recs(target, portal string) []fakeRec {
	pfx := strings.Replace(fakePortal(portal), ":", ",", 1) + ","
	ents, _ := os.ReadDir(filepath.Join(f.db, target))
	var out []fakeRec
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), pfx) {
			continue
		}
		tp, _ := strconv.Atoi(strings.TrimPrefix(e.Name(), pfx))
		raw, err := os.ReadFile(filepath.Join(f.db, target, e.Name(), "default"))
		if err != nil {
			continue
		}
		s := map[string]string{}
		for _, l := range strings.Split(string(raw), "\n") {
			if k, v, ok := strings.Cut(l, " = "); ok {
				s[k] = v
			}
		}
		out = append(out, fakeRec{tpgt: tp, settings: s, raw: string(raw)})
	}
	return out
}

// recordFile is the raw content of one record, "" when there is none.
func (f *recordISCSIAdm) recordFile(target, portal string, tpgt int) string {
	b, err := os.ReadFile(filepath.Join(f.recDir(target, portal, tpgt), "default"))
	if err != nil {
		return ""
	}
	return string(b)
}

func (f *recordISCSIAdm) run(_ context.Context, name string, args ...string) ([]byte, error) {
	if f.hook != nil {
		f.hook(args)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a := strings.Join(args, " ")
	f.calls = append(f.calls, a)
	if name != "iscsiadm" {
		return nil, errors.New("not iscsiadm")
	}
	at := func(flag string) string { return argAfter(args, flag) }
	var ops []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-o" {
			ops = append(ops, args[i+1])
		}
	}
	has := func(op string) bool {
		for _, o := range ops {
			if o == op {
				return true
			}
		}
		return false
	}
	switch {
	case a == "-m session":
		if len(f.sessions) == 0 {
			return []byte("iscsiadm: No active sessions."), exitErr(21)
		}
		var b strings.Builder
		for s := range f.sessions {
			p, tg, _ := strings.Cut(s, " ")
			b.WriteString("tcp: [1] " + p + ",1 " + tg + " (non-flash)\n")
		}
		return []byte(b.String()), nil

	case strings.HasPrefix(a, "-m discovery"):
		portal := fakePortal(at("-p"))
		adv, ok := f.adverts[portal]
		if !ok {
			return []byte("iscsiadm: cannot make connection to " + portal + ": No route to host"), exitErr(4)
		}
		plain := len(ops) == 0 // new, update and delete
		var out strings.Builder
		returned := map[string]bool{}
		for _, ad := range adv {
			returned[ad.target+"|"+strconv.Itoa(ad.tpgt)] = true
			exists := f.recordFile(ad.target, portal, ad.tpgt) != ""
			if (!exists && (plain || has("new"))) || (exists && (plain || has("update"))) {
				if err := f.writeRec(ad.target, portal, ad.tpgt, f.conf); err != nil {
					return []byte(err.Error()), exitErr(1)
				}
			}
			fmt.Fprintf(&out, "%s,%d %s\n", portal, ad.tpgt, ad.target)
		}
		if plain || has("delete") {
			tents, _ := os.ReadDir(f.db)
			for _, te := range tents {
				for _, r := range f.recs(te.Name(), portal) {
					if !returned[te.Name()+"|"+strconv.Itoa(r.tpgt)] {
						_ = os.RemoveAll(f.recDir(te.Name(), portal, r.tpgt))
					}
				}
			}
		}
		return []byte(out.String()), nil

	case strings.HasPrefix(a, "-m node") && strings.HasSuffix(a, "--logout"):
		target, portal := at("-T"), fakePortal(at("-p"))
		key := portal + " " + target
		if f.logoutErr != "" {
			return []byte(f.logoutErr), exitErr(8)
		}
		if !f.sessions[key] {
			return []byte("iscsiadm: No matching sessions found"), exitErr(21)
		}
		delete(f.sessions, key)
		return []byte("Logout of [sid: 1, target: " + target + ", portal: " + portal + "] successful."), nil

	case strings.HasPrefix(a, "-m node") && has("delete"):
		target, portal := at("-T"), at("-p")
		rs := f.recs(target, portal)
		if len(rs) == 0 {
			return []byte("iscsiadm: No records found"), exitErr(21)
		}
		if f.sessions[fakePortal(portal)+" "+target] {
			return []byte("iscsiadm: This command will remove the record [iface: default, target: " + target +
				", portal: " + portal + "], but a session is using it. Logout session then rerun command to remove record."), exitErr(1)
		}
		for _, r := range rs {
			_ = os.RemoveAll(f.recDir(target, portal, r.tpgt))
		}
		if ents, _ := os.ReadDir(filepath.Join(f.db, target)); len(ents) == 0 {
			_ = os.Remove(filepath.Join(f.db, target))
		}
		return nil, nil

	case strings.HasPrefix(a, "-m node") && has("new"):
		target, portal := at("-T"), at("-p")
		if len(f.recs(target, portal)) == 0 {
			if err := f.writeRec(target, portal, -1, f.conf); err != nil {
				return []byte(err.Error()), exitErr(1)
			}
		}
		return []byte("New iSCSI node added"), nil

	case strings.HasPrefix(a, "-m node") && strings.HasSuffix(a, "--login"):
		target, portal := at("-T"), fakePortal(at("-p"))
		key := portal + " " + target
		rs := f.recs(target, portal)
		if len(rs) == 0 {
			return []byte("iscsiadm: No records found"), exitErr(21)
		}
		if f.sessions[key] {
			return []byte("iscsiadm: default: 1 session requested, but 1 already present."), exitErr(15)
		}
		if f.timeout {
			return []byte("iscsiadm: initiator reported error (8 - connection timed out)"), exitErr(8)
		}
		var out strings.Builder
		var last error
		for _, r := range rs {
			switch {
			case r.tpgt != -1 && r.tpgt != f.tpgt[target]:
				fmt.Fprintf(&out, "iscsiadm: Could not login to [iface: default, target: %s, portal: %s,%d].\n"+
					"iscsiadm: initiator reported error (19 - encountered non-retryable iSCSI login failure)\n", target, portal, r.tpgt)
				last = exitErr(19)
				if f.terse {
					out.Reset()
					out.WriteString("iscsiadm: Could not log into all portals\n")
				}
			case r.settings[authUser]+":"+r.settings[authPass] != f.accept[target]:
				fmt.Fprintf(&out, "iscsiadm: Could not login to [iface: default, target: %s, portal: %s,%d].\n"+
					"iscsiadm: initiator reported error (24 - iSCSI login failed due to authorization failure)\n", target, portal, r.tpgt)
				last = exitErr(24)
				if f.terse {
					out.Reset()
					out.WriteString("iscsiadm: Could not log into all portals\n")
				}
			default:
				f.sessions[key] = true
				fmt.Fprintf(&out, "Login to [iface: default, target: %s, portal: %s,%d] successful.\n", target, portal, r.tpgt)
			}
		}
		return []byte(out.String()), last
	}
	return []byte("unexpected"), errors.New("unexpected iscsiadm call: " + a)
}

func (f *recordISCSIAdm) plainDiscoveries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var bad []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "-m discovery") && !strings.Contains(c, "-o new") {
			bad = append(bad, c)
		}
	}
	return bad
}

func (f *recordISCSIAdm) prepare(portal string) error {
	d := &iscsiDriver{target: prepTarget, opts: map[string]string{"portal": portal, "lun": "1"}, run: f.run}
	return d.Prepare(context.Background())
}

// operatorRecord is a record whose CHAP was set by hand, with node.startup
// changed too: the settings a plain discovery resets to iscsid.conf's.
var operatorRecord = map[string]string{authUser: "op", authPass: "op-secret", "node.startup": "automatic"}

// An existing record's settings survive a pool create's (and a disk
// create's) Prepare: the login goes through the record as it is.
//
// On main this fails twice over: the plain discovery rewrote the record from
// iscsid.conf, and the login then failed authorization.
func TestISCSIPrepare_KeepsAnExistingRecordsCHAP(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:op-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	before := f.recordFile(prepTarget, "10.0.0.5:3260", 1)

	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare: %v; calls %v", err, f.calls)
	}
	if after := f.recordFile(prepTarget, "10.0.0.5:3260", 1); after != before {
		t.Fatalf("the record changed:\nbefore %q\nafter  %q", before, after)
	}
	if bad := f.plainDiscoveries(); len(bad) > 0 {
		t.Fatalf("a discovery that rewrites records ran: %v", bad)
	}
	if !f.sessions["10.0.0.5:3260 "+prepTarget] {
		t.Fatal("no session")
	}
}

// A target with no record yet is still discovered and logged in to, and the
// discovery is add-only: another target's record on the same portal keeps
// the operator's settings.
//
// On main the new target worked, and the other target's record was rewritten
// from iscsid.conf.
func TestISCSIPrepare_NewTargetIsDiscoveredAddOnly(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}, {prepOther, 1}}
	f.tpgt[prepTarget], f.tpgt[prepOther] = 1, 1
	f.accept[prepTarget] = "conf:conf-secret"
	f.setRecord(t, prepOther, "10.0.0.5:3260", 1, operatorRecord)
	other := f.recordFile(prepOther, "10.0.0.5:3260", 1)

	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare: %v; calls %v", err, f.calls)
	}
	if !f.sessions["10.0.0.5:3260 "+prepTarget] {
		t.Fatalf("no session to the new target; calls %v", f.calls)
	}
	if got := f.recordFile(prepTarget, "10.0.0.5:3260", 1); !strings.Contains(got, authUser+" = conf") {
		t.Fatalf("the new target's record %q, want iscsid.conf's settings", got)
	}
	if after := f.recordFile(prepOther, "10.0.0.5:3260", 1); after != other {
		t.Fatalf("another target's record changed:\nbefore %q\nafter  %q", other, after)
	}
	if bad := f.plainDiscoveries(); len(bad) > 0 {
		t.Fatalf("a discovery that rewrites records ran: %v", bad)
	}
}

// A pool on a new portal of a target (the array moved it) logs in through a
// record the add-only discovery makes; the record of the old portal, with
// the operator's settings, is left alone. Main allowed it.
func TestISCSIPrepare_ChangedPortalStillLogsIn(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.6:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "conf:conf-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	old := f.recordFile(prepTarget, "10.0.0.5:3260", 1)

	if err := f.prepare("10.0.0.6:3260"); err != nil {
		t.Fatalf("Prepare on the new portal: %v; calls %v", err, f.calls)
	}
	if !f.sessions["10.0.0.6:3260 "+prepTarget] {
		t.Fatalf("no session through the new portal; calls %v", f.calls)
	}
	if after := f.recordFile(prepTarget, "10.0.0.5:3260", 1); after != old {
		t.Fatalf("the old portal's record changed:\nbefore %q\nafter  %q", old, after)
	}
}

// The target answers on its portal with a new portal group tag (the array was
// reconfigured): the record's tag is stale and its login fails. Main's plain
// discovery deleted the stale record and made one with the new tag. The
// add-only discovery adds the new-tag record beside it, the login through it
// opens the session, and the stale record is left as it was.
func TestISCSIPrepare_ChangedPortalGroupTagStillLogsIn(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 2}}
	f.tpgt[prepTarget] = 2
	f.accept[prepTarget] = "conf:conf-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, map[string]string{authUser: "conf", authPass: "conf-secret", "node.startup": "automatic"})
	stale := f.recordFile(prepTarget, "10.0.0.5:3260", 1)

	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare: %v; calls %v", err, f.calls)
	}
	if !f.sessions["10.0.0.5:3260 "+prepTarget] {
		t.Fatalf("no session; calls %v", f.calls)
	}
	if bad := f.plainDiscoveries(); len(bad) > 0 {
		t.Fatalf("a discovery that rewrites records ran: %v", bad)
	}
	// The session through the new-tag record is enough: the stale record,
	// which the target refused, is not refreshed.
	if after := f.recordFile(prepTarget, "10.0.0.5:3260", 1); after != stale {
		t.Fatalf("the old-tag record changed:\nbefore %q\nafter  %q", stale, after)
	}
}

// A login that fails without the target refusing it (the portal stopped
// answering mid-login) says nothing about the record's settings: the create
// fails, as on main, and the record is not refreshed.
func TestISCSIPrepare_TransientLoginFailureLeavesTheRecord(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:op-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	before := f.recordFile(prepTarget, "10.0.0.5:3260", 1)
	f.timeout = true

	if err := f.prepare("10.0.0.5:3260"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("Prepare: err=%v, want the login's timeout", err)
	}
	if after := f.recordFile(prepTarget, "10.0.0.5:3260", 1); after != before {
		t.Fatalf("the record changed:\nbefore %q\nafter  %q", before, after)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, "-o delete") {
			t.Fatalf("the record was deleted for a refresh: %v", f.calls)
		}
	}
}

// CHAP rotated in iscsid.conf: the record still holds the old credentials,
// which iscsid.conf gave it when it was made, and the target now refuses
// them. Main's plain discovery rewrote the record from iscsid.conf and the
// create succeeded; it still does. Only this target's record at this portal
// is refreshed, and only because the target refused it.
//
// A naive add-only Prepare (no refresh) refuses this create.
func TestISCSIPrepare_RotatedCHAPInIscsidConfStillLogsIn(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}, {prepOther, 1}}
	f.tpgt[prepTarget], f.tpgt[prepOther] = 1, 1
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, map[string]string{authUser: "conf", authPass: "old-secret", "node.startup": "manual"})
	f.setRecord(t, prepOther, "10.0.0.5:3260", 1, operatorRecord)
	other := f.recordFile(prepOther, "10.0.0.5:3260", 1)
	f.accept[prepTarget] = "conf:conf-secret" // the rotated secret, in iscsid.conf

	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare after a CHAP rotation in iscsid.conf: %v; calls %v", err, f.calls)
	}
	if !f.sessions["10.0.0.5:3260 "+prepTarget] {
		t.Fatalf("no session; calls %v", f.calls)
	}
	if got := f.recordFile(prepTarget, "10.0.0.5:3260", 1); !strings.Contains(got, authPass+" = conf-secret") {
		t.Fatalf("the refused record %q, want it refreshed from iscsid.conf", got)
	}
	if after := f.recordFile(prepOther, "10.0.0.5:3260", 1); after != other {
		t.Fatalf("another target's record changed:\nbefore %q\nafter  %q", other, after)
	}
	if bad := f.plainDiscoveries(); len(bad) > 0 {
		t.Fatalf("a discovery that rewrites every record of the portal ran: %v", bad)
	}
}

// The target refuses the record's credentials and iscsid.conf's too: the
// create fails, as on main, and the record is put back exactly as it was.
// Main left it rewritten from iscsid.conf, the operator's CHAP gone.
func TestISCSIPrepare_RefusedRefreshPutsTheRecordBack(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:rotated-on-the-array"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	before := f.recordFile(prepTarget, "10.0.0.5:3260", 1)

	err := f.prepare("10.0.0.5:3260")
	if err == nil || !strings.Contains(err.Error(), "authorization failure") {
		t.Fatalf("Prepare: err=%v, want the authorization failure", err)
	}
	if strings.Contains(err.Error(), "op-secret") || strings.Contains(err.Error(), "conf-secret") {
		t.Fatalf("a secret in the error: %v", err)
	}
	if after := f.recordFile(prepTarget, "10.0.0.5:3260", 1); after != before {
		t.Fatalf("the record was not put back:\nbefore %q\nafter  %q", before, after)
	}
	if f.sessions["10.0.0.5:3260 "+prepTarget] {
		t.Fatal("a session, with every login refused")
	}
}

// When the record cannot be saved (the node database is not where litevirt
// looks), a refused record is still refreshed, as main did, so the create
// main allowed still succeeds; it is the one record of this target at this
// portal, not every record of the portal.
func TestISCSIPrepare_UnsavedRecordIsStillRefreshed(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}, {prepOther, 1}}
	f.tpgt[prepTarget], f.tpgt[prepOther] = 1, 1
	f.accept[prepTarget] = "conf:conf-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	f.setRecord(t, prepOther, "10.0.0.5:3260", 1, operatorRecord)
	other := f.recordFile(prepOther, "10.0.0.5:3260", 1)
	iscsiNodeDBDirs = []string{t.TempDir()}

	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare: %v; calls %v", err, f.calls)
	}
	if !f.sessions["10.0.0.5:3260 "+prepTarget] {
		t.Fatalf("no session; calls %v", f.calls)
	}
	if after := f.recordFile(prepOther, "10.0.0.5:3260", 1); after != other {
		t.Fatalf("another target's record changed:\nbefore %q\nafter  %q", other, after)
	}
	if bad := f.plainDiscoveries(); len(bad) > 0 {
		t.Fatalf("a discovery that rewrites every record of the portal ran: %v", bad)
	}
}

// A session that is already up is success, as on main, and nothing is
// written.
func TestISCSIPrepare_SessionAlreadyUp(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:op-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	before := f.recordFile(prepTarget, "10.0.0.5:3260", 1)
	f.sessions["10.0.0.5:3260 "+prepTarget] = true

	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if after := f.recordFile(prepTarget, "10.0.0.5:3260", 1); after != before {
		t.Fatalf("the record changed:\nbefore %q\nafter  %q", before, after)
	}
}

// A portal that does not answer fails the create, as on main.
func TestISCSIPrepare_UnreachablePortalFails(t *testing.T) {
	f := newRecordISCSIAdm(t)
	if err := f.prepare("10.0.0.9:3260"); err == nil || !strings.Contains(err.Error(), "No route to host") {
		t.Fatalf("Prepare: err=%v, want the discovery's failure", err)
	}
}

// A pool with no portal option uses the driver's default, as on main.
func TestISCSIPrepare_DefaultPortal(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["127.0.0.1:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "conf:conf-secret"
	d := &iscsiDriver{target: prepTarget, opts: map[string]string{}, run: f.run}
	if err := d.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v; calls %v", err, f.calls)
	}
	if !f.sessions["127.0.0.1:3260 "+prepTarget] {
		t.Fatalf("no session through the default portal; calls %v", f.calls)
	}
}

// A refusal is recognised by iscsiadm's exit status alone, when its output
// names no reason (wording differs between open-iscsi versions).
func TestISCSIPrepare_RefusalByExitStatusAlone(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.terse = true
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, map[string]string{authUser: "conf", authPass: "old-secret", "node.startup": "manual"})
	f.accept[prepTarget] = "conf:conf-secret"

	if err := f.prepare("10.0.0.5:3260"); err != nil {
		t.Fatalf("Prepare after a CHAP rotation in iscsid.conf, terse iscsiadm: %v; calls %v", err, f.calls)
	}
	if !f.sessions["10.0.0.5:3260 "+prepTarget] {
		t.Fatalf("no session; calls %v", f.calls)
	}
}

// Two disk creates on two pools of one target (one LUN each, the usual
// layout) refresh the same record at once, and the target refuses both
// refreshes. The operator's record must come back: the refreshes are
// serialised, so neither saves the other's half-done refresh as "the
// record" and puts that back last.
//
// The schedule: A pauses just before its post-refresh login; B then runs up
// to just after its own delete and pauses; A finishes (puts the record
// back); B finishes. Unserialised, B saved A's iscsid.conf record and puts
// that back over the operator's.
func TestISCSIPrepare_ConcurrentRefusedRefreshesKeepTheRecord(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:rotated-on-the-array"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	before := f.recordFile(prepTarget, "10.0.0.5:3260", 1)

	// A spells the portal with its port, B without: the same record, and
	// the hook can tell the two apart.
	startB, bDeleted, aDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var aLogins int
	var bSawDelete bool
	var once sync.Once
	wait := func(ch chan struct{}) {
		select {
		case <-ch:
		case <-time.After(time.Second): // serialised: the other side cannot get there
		}
	}
	f.hook = func(args []string) {
		a := strings.Join(args, " ")
		switch argAfter(args, "-p") {
		case "10.0.0.5:3260":
			if strings.HasSuffix(a, "--login") {
				aLogins++
				if aLogins == 3 {
					close(startB)
					wait(bDeleted)
				}
			}
		case "10.0.0.5":
			if strings.Contains(a, "-o delete") {
				bSawDelete = true
			} else if bSawDelete && strings.HasPrefix(a, "-m discovery") {
				once.Do(func() { close(bDeleted) })
				wait(aDone)
			}
		}
	}

	bErr := make(chan error, 1)
	go func() {
		<-startB
		d := &iscsiDriver{target: prepTarget, opts: map[string]string{"portal": "10.0.0.5", "lun": "2"}, run: f.run}
		bErr <- d.Prepare(context.Background())
	}()
	aErr := f.prepare("10.0.0.5:3260")
	close(aDone)
	if aErr == nil {
		t.Fatal("A: Prepare succeeded with every login refused")
	}
	select {
	case err := <-bErr:
		if err == nil {
			t.Fatal("B: Prepare succeeded with every login refused")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("B never finished")
	}
	if after := f.recordFile(prepTarget, "10.0.0.5:3260", 1); after != before {
		t.Fatalf("the operator's record was lost to two concurrent refreshes:\nbefore %q\nafter  %q", before, after)
	}
}

// The put-back covers what the refresh deleted, this target's records at
// this portal, and nothing else: a record of the target at another portal
// that changed meanwhile keeps the change; a record added at this portal
// meanwhile is removed; the put-back file keeps its mode and leaves no
// temporary file behind.
func TestISCSIPrepare_PutBackIsScopedToThePortal(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:rotated-on-the-array"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)
	f.setRecord(t, prepTarget, "10.0.1.5:3260", 1, operatorRecord)
	recFile := filepath.Join(f.recDir(prepTarget, "10.0.0.5:3260", 1), "default")
	if err := os.Chmod(recFile, 0o640); err != nil {
		t.Fatal(err)
	}
	before := f.recordFile(prepTarget, "10.0.0.5:3260", 1)
	changed := map[string]string{authUser: "op", authPass: "op-secret", "node.startup": "onboot"}

	var deleted, injected bool
	f.hook = func(args []string) {
		a := strings.Join(args, " ")
		if strings.Contains(a, "-o delete") {
			deleted = true
		}
		if deleted && !injected && strings.HasSuffix(a, "--login") {
			injected = true
			// Meanwhile: the operator updates the other portal's record,
			// and a record of this portal appears (tag -1, as -m node -o
			// new makes it).
			if err := f.writeRec(prepTarget, "10.0.1.5:3260", 1, changed); err != nil {
				t.Error(err)
			}
			if err := f.writeRec(prepTarget, "10.0.0.5:3260", -1, f.conf); err != nil {
				t.Error(err)
			}
		}
	}
	other := func() string { return f.recordFile(prepTarget, "10.0.1.5:3260", 1) }

	if err := f.prepare("10.0.0.5:3260"); err == nil || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("Prepare: err=%v, want the refusal and the put-back", err)
	}
	if !injected {
		t.Fatalf("the schedule never ran; calls %v", f.calls)
	}
	if after := f.recordFile(prepTarget, "10.0.0.5:3260", 1); after != before {
		t.Fatalf("the record was not put back:\nbefore %q\nafter  %q", before, after)
	}
	if got := other(); !strings.Contains(got, "node.startup = onboot") {
		t.Fatalf("the other portal's record %q lost the change made meanwhile", got)
	}
	if got := f.recordFile(prepTarget, "10.0.0.5:3260", -1); got != "" {
		t.Fatalf("a record added at this portal during the refresh survived the put-back: %q", got)
	}
	if st, err := os.Stat(recFile); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("put-back file mode: %v %v, want 0640", st, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(recFile))
	for _, e := range ents {
		if e.Name() != "default" {
			t.Fatalf("left behind in the record directory: %s", e.Name())
		}
	}
	dbEnts, _ := os.ReadDir(f.db)
	for _, e := range dbEnts {
		if !e.IsDir() {
			t.Fatalf("left behind in the node database: %s", e.Name())
		}
	}
}

// The re-login takes the same per-target lock as Prepare: it does not log in
// while a Prepare of the target is running (a refresh may have the record
// deleted at that moment), and logs in once it is done.
func TestLoginISCSISession_WaitsForAPrepareOfTheTarget(t *testing.T) {
	f := newRecordISCSIAdm(t)
	f.adverts["10.0.0.5:3260"] = []iscsiAdvert{{prepTarget, 1}}
	f.tpgt[prepTarget] = 1
	f.accept[prepTarget] = "op:op-secret"
	f.setRecord(t, prepTarget, "10.0.0.5:3260", 1, operatorRecord)

	aIn, release := make(chan struct{}), make(chan struct{})
	var bLoggedIn sync.WaitGroup
	var bLogins atomic.Int32
	f.hook = func(args []string) {
		if !strings.HasSuffix(strings.Join(args, " "), "--login") {
			return
		}
		if argAfter(args, "-p") == "10.0.0.5:3260" {
			close(aIn)
			<-release
			return
		}
		bLogins.Add(1)
	}
	aErr := make(chan error, 1)
	go func() { aErr <- f.prepare("10.0.0.5:3260") }()
	<-aIn
	bErr := make(chan error, 1)
	bLoggedIn.Add(1)
	go func() {
		defer bLoggedIn.Done()
		_, err := ensureISCSISession(context.Background(), f.run, prepTarget, "10.0.0.5")
		bErr <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if n := bLogins.Load(); n != 0 {
		t.Fatalf("the re-login logged in %d time(s) while a Prepare of the target ran", n)
	}
	close(release)
	if err := <-aErr; err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	bLoggedIn.Wait()
	if err := <-bErr; err != nil {
		t.Fatalf("re-login after the Prepare: %v", err)
	}
}
