package fwmig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	tUUID    = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	tCreated = "2026-10-15T10:00:00Z"
	tAttempt = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
	tHashA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tHashB   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var tSince = time.Date(2026, 10, 15, 10, 1, 2, 0, time.UTC)

func tBinding() Binding { return Binding{UUID: tUUID, CreatedAt: tCreated, Attempt: tAttempt} }

func tMarker(phase Phase) Marker {
	m := Marker{
		VM: "vm1", Binding: tBinding(), Target: "node-2", Route: RouteStorageCopy,
		Phase: phase, TPM: true, UEFI: true,
		SrcPermallSHA256: tHashA, SrcNvramSHA256: tHashB,
		SrcStopReason: StopReasonMigrated,
		CreatedStubs:  []string{"/var/lib/litevirt/disks/vm1-root.qcow2"},
		Since:         tSince, Detail: "detail",
	}
	if phase.Parked() {
		m.ParkedFrom = PhaseMigrating
	}
	return m
}

func tHold(state HoldState, nm NvramMaterialised) Hold {
	return Hold{
		VM: "vm1", Binding: tBinding(), Source: "node-1", Since: tSince,
		State: state, TPM: true, UEFI: true, NvramMaterialised: nm,
		NvramT0SHA256: tHashB, SwtpmAbsentAtPrepare: true,
		VerifiedPermallSHA256: tHashA,
	}
}

func tOwed() OwedDiscard {
	return OwedDiscard{
		VM: "vm1", Binding: tBinding(), Target: "node-2",
		CreatedStubs: []string{"/var/lib/litevirt/disks/vm1-data.qcow2"},
		Since:        tSince,
	}
}

// The phases, hold states and tri-state values, verbatim from spec §4.
var (
	specProgressPhases = []string{"preparing", "prepared", "migrating", "cutover", "verified", "committed", "released", "cleaning"}
	specParkedPhases   = []string{"target_unreachable", "source_state_missing", "source_state_suspect", "target_ran", "nvram_unconfirmed", "discard_pending", "source_paused"}
	specHoldStates     = []string{"prepared", "verified", "resuming", "released_unconfirmed", "mismatch"}
	specTriState       = []string{"pending", "done", "no"}
)

func fileKeys(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sorted(s ...string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestFwmig_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)

	// Every phase round-trips, and the file carries exactly the spec's
	// field names.
	for _, p := range append(append([]string{}, specProgressPhases...), specParkedPhases...) {
		m := tMarker(Phase(p))
		if err := r.PutMarker(m); err != nil {
			t.Fatalf("put marker %s: %v", p, err)
		}
		got, ok, err := r.GetMarker("vm1")
		if err != nil || !ok {
			t.Fatalf("get marker %s: ok=%v err=%v", p, ok, err)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("marker %s round trip:\n got %+v\nwant %+v", p, got, m)
		}
	}
	wantMarkerKeys := sorted("vm", "uuid", "created_at", "attempt", "target", "route", "phase", "tpm", "uefi",
		"src_permall_sha256", "src_nvram_sha256", "src_stop_reason", "created_stubs", "since", "detail", "parked_from")
	if got := fileKeys(t, filepath.Join(dir, InflightDir, "vm1.json")); !reflect.DeepEqual(got, wantMarkerKeys) {
		t.Fatalf("marker keys %v, want %v", got, wantMarkerKeys)
	}

	// Every hold state with every tri-state value round-trips, and the three
	// values stay three.
	for _, s := range specHoldStates {
		for _, nm := range specTriState {
			h := tHold(HoldState(s), NvramMaterialised(nm))
			if err := r.PutHold(h); err != nil {
				t.Fatalf("put hold %s/%s: %v", s, nm, err)
			}
			got, ok, err := r.GetHold("vm1")
			if err != nil || !ok {
				t.Fatalf("get hold %s/%s: ok=%v err=%v", s, nm, ok, err)
			}
			if !reflect.DeepEqual(got, h) {
				t.Fatalf("hold %s/%s round trip:\n got %+v\nwant %+v", s, nm, got, h)
			}
			var raw map[string]any
			b, _ := os.ReadFile(filepath.Join(dir, HoldDir, "vm1.json"))
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Fatal(err)
			}
			if raw["nvram_materialised"] != nm {
				t.Fatalf("nvram_materialised on disk = %#v, want %q", raw["nvram_materialised"], nm)
			}
		}
	}
	wantHoldKeys := sorted("vm", "uuid", "created_at", "attempt", "source", "since", "state", "tpm", "uefi",
		"nvram_materialised", "nvram_t0_sha256", "swtpm_absent_at_prepare", "verified_permall_sha256")
	if got := fileKeys(t, filepath.Join(dir, HoldDir, "vm1.json")); !reflect.DeepEqual(got, wantHoldKeys) {
		t.Fatalf("hold keys %v, want %v", got, wantHoldKeys)
	}

	// The owed-discard record, keyed by vm and attempt.
	o := tOwed()
	if err := r.PutOwedDiscard(o); err != nil {
		t.Fatal(err)
	}
	gotO, ok, err := r.GetOwedDiscard("vm1", tAttempt)
	if err != nil || !ok || !reflect.DeepEqual(gotO, o) {
		t.Fatalf("owed discard round trip: ok=%v err=%v got %+v", ok, err, gotO)
	}
	wantOwedKeys := sorted("vm", "uuid", "created_at", "attempt", "target", "created_stubs", "since")
	if got := fileKeys(t, filepath.Join(dir, DiscardOwedDir, "vm1-"+tAttempt+".json")); !reflect.DeepEqual(got, wantOwedKeys) {
		t.Fatalf("owed keys %v, want %v", got, wantOwedKeys)
	}

	// Lists.
	m2 := tMarker(PhasePrepared)
	m2.VM = "vm0"
	if err := r.PutMarker(m2); err != nil {
		t.Fatal(err)
	}
	ms, err := r.ListMarkers()
	if err != nil || len(ms) != 2 || ms[0].VM != "vm0" || ms[1].VM != "vm1" {
		t.Fatalf("ListMarkers = %+v, %v", ms, err)
	}
	hs, err := r.ListHolds()
	if err != nil || len(hs) != 1 || hs[0].VM != "vm1" {
		t.Fatalf("ListHolds = %+v, %v", hs, err)
	}
	os2 := tOwed()
	os2.Attempt = "1a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
	if err := r.PutOwedDiscard(os2); err != nil {
		t.Fatal(err)
	}
	ow, err := r.ListOwedDiscards()
	if err != nil || len(ow) != 2 {
		t.Fatalf("ListOwedDiscards = %+v, %v", ow, err)
	}

	// Removal; absent is success, and a get after it reports none.
	for _, f := range []func() error{
		func() error { return r.RemoveMarker("vm1") },
		func() error { return r.RemoveHold("vm1") },
		func() error { return r.RemoveOwedDiscard("vm1", tAttempt) },
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
		if err := f(); err != nil {
			t.Fatalf("second remove: %v", err)
		}
	}
	if _, ok, err := r.GetMarker("vm1"); ok || err != nil {
		t.Fatalf("marker after remove: ok=%v err=%v", ok, err)
	}
	if _, ok, err := r.GetHold("vm1"); ok || err != nil {
		t.Fatalf("hold after remove: ok=%v err=%v", ok, err)
	}
	if _, ok, err := r.GetOwedDiscard("vm1", tAttempt); ok || err != nil {
		t.Fatalf("owed after remove: ok=%v err=%v", ok, err)
	}
	// An empty data dir lists nothing.
	empty := New(t.TempDir())
	if ms, err := empty.ListMarkers(); err != nil || len(ms) != 0 {
		t.Fatalf("empty list: %v %v", ms, err)
	}
}

func TestFwmig_RecordModes(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)
	if err := r.PutHold(tHold(HoldPrepared, NvramPending)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, HoldDir))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("hold dir mode %v, %v", st.Mode().Perm(), err)
	}
	st, err = os.Stat(filepath.Join(dir, HoldDir, "vm1.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("hold file mode %v, %v", st.Mode().Perm(), err)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, HoldDir))
	if len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
}

// recFS is the real filesystem with every mutating call logged and any one
// of them made to fail.
type recFS struct {
	osFS
	root string // the data dir: its fsync is logged as "sync-parent"
	ops  []string
	fail string // op name to fail
}

var errInjected = errors.New("injected")

func (f *recFS) do(op string) error {
	f.ops = append(f.ops, op)
	if f.fail == op {
		return errInjected
	}
	return nil
}

func (f *recFS) CreateTemp(dir, pattern string) (tempFile, error) {
	if err := f.do("create"); err != nil {
		return nil, err
	}
	tf, err := f.osFS.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return &recFile{tempFile: tf, fs: f}, nil
}

func (f *recFS) Rename(o, n string) error {
	if err := f.do("rename"); err != nil {
		return err
	}
	return f.osFS.Rename(o, n)
}

func (f *recFS) Remove(p string) error {
	if strings.Contains(filepath.Base(p), ".tmp-") {
		f.ops = append(f.ops, "remove-temp")
		return f.osFS.Remove(p)
	}
	if err := f.do("remove"); err != nil {
		return err
	}
	return f.osFS.Remove(p)
}

func (f *recFS) MkdirAll(d string, perm os.FileMode) error {
	if err := f.do("mkdir"); err != nil {
		return err
	}
	return f.osFS.MkdirAll(d, perm)
}

func (f *recFS) SyncDir(d string) error {
	op := "sync-dir"
	if f.root != "" && filepath.Clean(d) == filepath.Clean(f.root) {
		op = "sync-parent"
	}
	if err := f.do(op); err != nil {
		return err
	}
	return f.osFS.SyncDir(d)
}

type recFile struct {
	tempFile
	fs *recFS
}

func (f *recFile) Write(b []byte) (int, error) {
	if err := f.fs.do("write"); err != nil {
		return 0, err
	}
	return f.tempFile.Write(b)
}

func (f *recFile) Sync() error {
	if err := f.fs.do("sync-file"); err != nil {
		return err
	}
	return f.tempFile.Sync()
}

func (f *recFile) Close() error {
	f.fs.ops = append(f.fs.ops, "close")
	return f.tempFile.Close()
}

func indexOf(ops []string, op string) int {
	for i, o := range ops {
		if o == op {
			return i
		}
	}
	return -1
}

// The write is temp → fsync → rename → directory fsync, and a failure at any
// step reports an error and leaves the previous record in place.
func TestFwmig_Fsync(t *testing.T) {
	dir := t.TempDir()
	fs := &recFS{root: dir}
	r := newWithFS(dir, fs)

	if err := r.PutMarker(tMarker(PhasePreparing)); err != nil {
		t.Fatal(err)
	}
	w, sf, rn, sd := indexOf(fs.ops, "write"), indexOf(fs.ops, "sync-file"), indexOf(fs.ops, "rename"), indexOf(fs.ops, "sync-dir")
	if w < 0 || sf < 0 || rn < 0 || sd < 0 || !(w < sf && sf < rn && rn < sd) {
		t.Fatalf("put order %v: want write < sync-file < rename < sync-dir", fs.ops)
	}
	if last := fs.ops[len(fs.ops)-1]; last != "sync-dir" {
		t.Fatalf("put ends with %q, want the directory fsync last: %v", last, fs.ops)
	}

	for _, step := range []string{"write", "sync-file", "rename", "sync-dir"} {
		fs.ops, fs.fail = nil, step
		next := tMarker(PhaseMigrating)
		err := r.PutMarker(next)
		if !errors.Is(err, errInjected) {
			t.Fatalf("%s failure: put returned %v, want the injected error", step, err)
		}
		fs.fail = ""
		got, ok, gerr := r.GetMarker("vm1")
		if gerr != nil || !ok {
			t.Fatalf("%s failure: get: ok=%v err=%v", step, ok, gerr)
		}
		if step != "sync-dir" && got.Phase != PhasePreparing {
			t.Fatalf("%s failure replaced the record: phase %s", step, got.Phase)
		}
		ents, _ := os.ReadDir(filepath.Join(dir, InflightDir))
		if len(ents) != 1 {
			t.Fatalf("%s failure left a temp file: %v", step, ents)
		}
		// Restore the original for the next step.
		if err := r.PutMarker(tMarker(PhasePreparing)); err != nil {
			t.Fatal(err)
		}
	}

	// Removal is durable too: remove, then directory fsync.
	fs.ops = nil
	if err := r.RemoveMarker("vm1"); err != nil {
		t.Fatal(err)
	}
	if rm, sd := indexOf(fs.ops, "remove"), indexOf(fs.ops, "sync-dir"); rm < 0 || sd < rm {
		t.Fatalf("remove order %v: want remove < sync-dir", fs.ops)
	}
	if err := r.PutHold(tHold(HoldPrepared, NvramPending)); err != nil {
		t.Fatal(err)
	}
	fs.ops, fs.fail = nil, "sync-dir"
	if err := r.RemoveHold("vm1"); !errors.Is(err, errInjected) {
		t.Fatalf("remove with failing dir fsync: %v", err)
	}
	fs.fail = ""

	// The hold and owed-discard writers take the same path.
	for name, put := range map[string]func() error{
		"hold": func() error { return r.PutHold(tHold(HoldResuming, NvramDone)) },
		"owed": func() error { return r.PutOwedDiscard(tOwed()) },
	} {
		fs.ops = nil
		if err := put(); err != nil {
			t.Fatal(err)
		}
		sf, rn, sd := indexOf(fs.ops, "sync-file"), indexOf(fs.ops, "rename"), indexOf(fs.ops, "sync-dir")
		if sf < 0 || rn < 0 || sd < 0 || !(sf < rn && rn < sd) {
			t.Fatalf("%s order %v", name, fs.ops)
		}
	}
}

func TestFwmig_IncarnationMismatch(t *testing.T) {
	b := tBinding()
	if !b.Matches(b) || !b.SameIncarnation(b) {
		t.Fatal("a binding must match itself")
	}
	cases := []struct {
		name          string
		o             Binding
		sameInc, same bool
	}{
		{"other created_at", Binding{UUID: tUUID, CreatedAt: "2026-10-15T11:00:00Z", Attempt: tAttempt}, false, false},
		{"other uuid", Binding{UUID: "11111111-2222-4333-8444-555555555555", CreatedAt: tCreated, Attempt: tAttempt}, false, false},
		{"other attempt", Binding{UUID: tUUID, CreatedAt: tCreated, Attempt: "other"}, true, false},
		{"empty created_at", Binding{UUID: tUUID, Attempt: tAttempt}, false, false},
		{"uuid case differs", Binding{UUID: strings.ToUpper(tUUID), CreatedAt: tCreated, Attempt: tAttempt}, true, true},
	}
	for _, c := range cases {
		if got := b.SameIncarnation(c.o); got != c.sameInc {
			t.Errorf("%s: SameIncarnation = %v, want %v", c.name, got, c.sameInc)
		}
		if got := b.Matches(c.o); got != c.same {
			t.Errorf("%s: Matches = %v, want %v", c.name, got, c.same)
		}
	}

	// Through the records: a hold read back is bound to what was written,
	// not to a recreated VM of the same name and uuid.
	r := New(t.TempDir())
	if err := r.PutHold(tHold(HoldPrepared, NvramPending)); err != nil {
		t.Fatal(err)
	}
	h, _, _ := r.GetHold("vm1")
	recreated := Binding{UUID: tUUID, CreatedAt: "2026-10-16T09:00:00Z", Attempt: tAttempt}
	if h.Matches(recreated) {
		t.Fatal("a hold matched a recreated incarnation (created_at ignored)")
	}
	if !h.Matches(tBinding()) {
		t.Fatal("a hold did not match its own attempt")
	}
	m := tMarker(PhaseCutover)
	if m.Matches(recreated) || !m.Matches(tBinding()) {
		t.Fatal("marker binding")
	}
	o := tOwed()
	if o.Matches(recreated) || !o.Matches(tBinding()) {
		t.Fatal("owed binding")
	}
}

func TestFwmig_BadName(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)
	for _, vm := range []string{"", "..", "../x", "a/b", ".", "x y"} {
		m := tMarker(PhasePreparing)
		m.VM = vm
		if err := r.PutMarker(m); err == nil {
			t.Errorf("marker for vm %q accepted", vm)
		}
		h := tHold(HoldPrepared, NvramPending)
		h.VM = vm
		if err := r.PutHold(h); err == nil {
			t.Errorf("hold for vm %q accepted", vm)
		}
		if _, _, err := r.GetMarker(vm); err == nil {
			t.Errorf("GetMarker(%q) accepted", vm)
		}
		if err := r.RemoveHold(vm); err == nil {
			t.Errorf("RemoveHold(%q) accepted", vm)
		}
	}
	for _, at := range []string{"", "..", "a/b", "../../etc", "not-a-uuid", tAttempt + "x"} {
		o := tOwed()
		o.Attempt = at
		if err := r.PutOwedDiscard(o); err == nil {
			t.Errorf("owed discard with attempt %q accepted", at)
		}
		if _, err := r.RetainedPath("vm1", at); err == nil {
			t.Errorf("RetainedPath attempt %q accepted", at)
		}
		if _, err := r.QuarantinePath("vm1", at); err == nil {
			t.Errorf("QuarantinePath attempt %q accepted", at)
		}
	}
	for _, u := range []string{"", "not-a-uuid", "../" + tUUID} {
		m := tMarker(PhasePreparing)
		m.UUID = u
		if err := r.PutMarker(m); err == nil {
			t.Errorf("marker with uuid %q accepted", u)
		}
	}
	// Nothing reached the disk.
	for _, d := range []string{InflightDir, HoldDir, DiscardOwedDir} {
		ents, _ := os.ReadDir(filepath.Join(dir, d))
		if len(ents) != 0 {
			t.Fatalf("%s holds %v after refused writes", d, ents)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "x.json")); err == nil {
		t.Fatal("a traversal escaped the data dir")
	}

	// A file whose name does not match the record inside is refused.
	if err := r.PutMarker(tMarker(PhasePreparing)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, InflightDir, "vm1.json"), filepath.Join(dir, InflightDir, "vm2.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.GetMarker("vm2"); err == nil {
		t.Fatal("marker vm2.json naming vm1 accepted")
	}
	if _, err := r.ListMarkers(); err == nil {
		t.Fatal("ListMarkers accepted a misnamed record")
	}
	if err := r.PutOwedDiscard(tOwed()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, DiscardOwedDir, "vm1-"+tAttempt+".json"), filepath.Join(dir, DiscardOwedDir, "vm1-other.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ListOwedDiscards(); err == nil {
		t.Fatal("ListOwedDiscards accepted a misnamed record")
	}

	// Path builders.
	p, err := r.RetainedPath("vm1", tAttempt)
	if err != nil || p != filepath.Join(dir, RetainedDir, "vm1-"+tAttempt+".tar") {
		t.Fatalf("RetainedPath = %q, %v", p, err)
	}
	p, err = r.QuarantinePath("vm1", tAttempt)
	if err != nil || p != filepath.Join(dir, QuarantineDir, "vm1-"+tAttempt) {
		t.Fatalf("QuarantinePath = %q, %v", p, err)
	}
	if _, _, err := New("").GetMarker("vm1"); err == nil {
		t.Fatal("no data dir accepted")
	}
}

func writeRaw(t *testing.T, dir, sub, name string, body map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sub, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func rawOf(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A phase this build does not know is refused, on read and on write: a
// record that cannot be read must not read as "no move".
func TestFwmig_UnknownPhaseRefused(t *testing.T) {
	for _, p := range []string{"", "discard_owed", "Prepared", "done", "parked"} {
		dir := t.TempDir()
		r := New(dir)
		if err := r.PutMarker(tMarker(Phase(p))); err == nil {
			t.Errorf("put phase %q accepted", p)
		}
		raw := rawOf(t, tMarker(PhasePreparing))
		raw["phase"] = p
		writeRaw(t, dir, InflightDir, "vm1.json", raw)
		_, ok, err := r.GetMarker("vm1")
		if err == nil {
			t.Errorf("read phase %q accepted (ok=%v)", p, ok)
		}
		if _, err := r.ListMarkers(); err == nil {
			t.Errorf("list with phase %q accepted", p)
		}
	}
	// The spec's sets, no more and no fewer.
	for _, p := range specProgressPhases {
		if !Phase(p).Valid() || Phase(p).Parked() {
			t.Errorf("progress phase %q: valid=%v parked=%v", p, Phase(p).Valid(), Phase(p).Parked())
		}
	}
	for _, p := range specParkedPhases {
		if !Phase(p).Valid() || !Phase(p).Parked() {
			t.Errorf("parked phase %q: valid=%v parked=%v", p, Phase(p).Valid(), Phase(p).Parked())
		}
	}
	if got, want := len(AllPhases()), len(specProgressPhases)+len(specParkedPhases); got != want {
		t.Errorf("AllPhases has %d, want %d", got, want)
	}
}

func TestFwmig_UnknownHoldStateRefused(t *testing.T) {
	for _, s := range []string{"", "released", "held", "Verified"} {
		dir := t.TempDir()
		r := New(dir)
		if err := r.PutHold(tHold(HoldState(s), NvramPending)); err == nil {
			t.Errorf("put state %q accepted", s)
		}
		raw := rawOf(t, tHold(HoldPrepared, NvramPending))
		raw["state"] = s
		writeRaw(t, dir, HoldDir, "vm1.json", raw)
		if _, _, err := r.GetHold("vm1"); err == nil {
			t.Errorf("read state %q accepted", s)
		}
	}
	for _, s := range specHoldStates {
		if !HoldState(s).Valid() {
			t.Errorf("hold state %q not valid", s)
		}
	}
	if got := len(AllHoldStates()); got != len(specHoldStates) {
		t.Errorf("AllHoldStates has %d, want %d", got, len(specHoldStates))
	}
}

// nvram_materialised is three values, never a bool: rule D deletes the
// NVRAM only when it is not "no", and a "pending" the daemon crashed in must
// not read as either "done" or "no".
func TestFwmig_NvramMaterialisedTriState(t *testing.T) {
	for _, bad := range []any{true, false, nil, "", "yes", "Done", 1} {
		dir := t.TempDir()
		r := New(dir)
		raw := rawOf(t, tHold(HoldPrepared, NvramPending))
		if bad == nil {
			delete(raw, "nvram_materialised")
		} else {
			raw["nvram_materialised"] = bad
		}
		writeRaw(t, dir, HoldDir, "vm1.json", raw)
		if h, _, err := r.GetHold("vm1"); err == nil {
			t.Errorf("nvram_materialised %#v accepted as %q", bad, h.NvramMaterialised)
		}
	}
	for _, bad := range []NvramMaterialised{"", "yes", "true"} {
		if err := New(t.TempDir()).PutHold(tHold(HoldPrepared, bad)); err == nil {
			t.Errorf("put nvram_materialised %q accepted", bad)
		}
	}
	seen := map[NvramMaterialised]bool{}
	for _, v := range specTriState {
		nm := NvramMaterialised(v)
		if !nm.Valid() {
			t.Errorf("%q not valid", v)
		}
		seen[nm] = true
	}
	if len(seen) != 3 || NvramPending == NvramDone || NvramDone == NvramNo || NvramPending == NvramNo {
		t.Fatal("tri-state collapsed")
	}
	// A VM without UEFI has nothing to materialise.
	h := tHold(HoldPrepared, NvramPending)
	h.UEFI = false
	if err := New(t.TempDir()).PutHold(h); err == nil {
		t.Error("non-UEFI hold with nvram_materialised=pending accepted")
	}
	h.NvramMaterialised = NvramNo
	h.NvramT0SHA256 = ""
	if err := New(t.TempDir()).PutHold(h); err != nil {
		t.Errorf("non-UEFI hold with nvram_materialised=no: %v", err)
	}
}

func TestFwmig_Validation(t *testing.T) {
	r := New(t.TempDir())
	badMarkers := map[string]func(*Marker){
		"no target":            func(m *Marker) { m.Target = "" },
		"bad target":           func(m *Marker) { m.Target = "a/b" },
		"no route":             func(m *Marker) { m.Route = "" },
		"unknown route":        func(m *Marker) { m.Route = "rdma" },
		"no created_at":        func(m *Marker) { m.CreatedAt = "" },
		"no attempt":           func(m *Marker) { m.Attempt = "" },
		"zero since":           func(m *Marker) { m.Since = time.Time{} },
		"neither tpm nor uefi": func(m *Marker) { m.TPM, m.UEFI = false, false },
		"short hash":           func(m *Marker) { m.SrcPermallSHA256 = "abc" },
		"upper hash":           func(m *Marker) { m.SrcNvramSHA256 = strings.ToUpper(tHashB) },
		"relative stub":        func(m *Marker) { m.CreatedStubs = []string{"disks/x.qcow2"} },
		"unclean stub":         func(m *Marker) { m.CreatedStubs = []string{"/a/../b"} },
		"empty stub":           func(m *Marker) { m.CreatedStubs = []string{""} },
		"parked without from":  func(m *Marker) { m.Phase, m.ParkedFrom = PhaseTargetRan, "" },
		"parked from parked":   func(m *Marker) { m.Phase, m.ParkedFrom = PhaseTargetRan, PhaseTargetUnreachable },
		"parked from unknown":  func(m *Marker) { m.Phase, m.ParkedFrom = PhaseTargetRan, "nowhere" },
		"progress with from":   func(m *Marker) { m.Phase, m.ParkedFrom = PhaseCutover, PhaseMigrating },
	}
	for name, mut := range badMarkers {
		m := tMarker(PhaseMigrating)
		mut(&m)
		if err := r.PutMarker(m); err == nil {
			t.Errorf("marker %s accepted", name)
		}
	}
	okMarkers := map[string]func(*Marker){
		"empty hashes and reason": func(m *Marker) { m.SrcPermallSHA256, m.SrcNvramSHA256, m.SrcStopReason = "", "", "" },
		"no stubs":                func(m *Marker) { m.CreatedStubs = nil },
		"tpm only":                func(m *Marker) { m.UEFI = false },
		"uefi only":               func(m *Marker) { m.TPM = false },
		"tunnelled":               func(m *Marker) { m.Route = RouteTunnelled },
		"migration network":       func(m *Marker) { m.Route = RouteMigrationNetwork },
		"other stop reason":       func(m *Marker) { m.SrcStopReason = "crashed" },
	}
	for name, mut := range okMarkers {
		m := tMarker(PhaseMigrating)
		mut(&m)
		if err := r.PutMarker(m); err != nil {
			t.Errorf("marker %s refused: %v", name, err)
		}
	}
	badHolds := map[string]func(*Hold){
		"no source":            func(h *Hold) { h.Source = "" },
		"zero since":           func(h *Hold) { h.Since = time.Time{} },
		"neither tpm nor uefi": func(h *Hold) { h.TPM, h.UEFI = false, false },
		"bad t0 hash":          func(h *Hold) { h.NvramT0SHA256 = "xyz" },
		"bad verified hash":    func(h *Hold) { h.VerifiedPermallSHA256 = tHashA + "00" },
		"no created_at":        func(h *Hold) { h.CreatedAt = "" },
	}
	for name, mut := range badHolds {
		h := tHold(HoldVerified, NvramDone)
		mut(&h)
		if err := r.PutHold(h); err == nil {
			t.Errorf("hold %s accepted", name)
		}
	}
	badOwed := map[string]func(*OwedDiscard){
		"no target":     func(o *OwedDiscard) { o.Target = "" },
		"zero since":    func(o *OwedDiscard) { o.Since = time.Time{} },
		"relative stub": func(o *OwedDiscard) { o.CreatedStubs = []string{"x"} },
		"bad uuid":      func(o *OwedDiscard) { o.UUID = "x" },
	}
	for name, mut := range badOwed {
		o := tOwed()
		mut(&o)
		if err := r.PutOwedDiscard(o); err == nil {
			t.Errorf("owed %s accepted", name)
		}
	}
}

// A record with a field this build does not know, or trailing data, or a
// corrupt body, is an error — never "no record".
func TestFwmig_StrictDecode(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)
	raw := rawOf(t, tHold(HoldPrepared, NvramPending))
	raw["future_field"] = 1
	writeRaw(t, dir, HoldDir, "vm1.json", raw)
	if _, ok, err := r.GetHold("vm1"); err == nil {
		t.Fatalf("unknown field accepted (ok=%v)", ok)
	}
	if err := os.WriteFile(filepath.Join(dir, HoldDir, "vm1.json"), []byte(`{"vm":"vm1"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := r.GetHold("vm1"); err == nil || ok {
		t.Fatalf("truncated record: ok=%v err=%v", ok, err)
	}
	if _, err := r.ListHolds(); err == nil {
		t.Fatal("ListHolds skipped a corrupt record")
	}
	b, _ := json.Marshal(tHold(HoldPrepared, NvramPending))
	if err := os.WriteFile(filepath.Join(dir, HoldDir, "vm1.json"), append(b, []byte(`{}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.GetHold("vm1"); err == nil {
		t.Fatal("trailing data accepted")
	}
	// A temp file left by a crash is not a record.
	if err := os.WriteFile(filepath.Join(dir, HoldDir, "vm1.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, HoldDir, "vm9.json.tmp-123"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hs, err := r.ListHolds(); err != nil || len(hs) != 1 {
		t.Fatalf("ListHolds with a stray temp file = %v, %v", hs, err)
	}
}

// uefi = hasNvram AND (secure_boot OR tpm) (spec §4).
func TestFwmig_UEFIRule(t *testing.T) {
	for _, c := range []struct{ nvram, sb, tpm, want bool }{
		{false, false, false, false},
		{false, true, true, false},
		{true, false, false, false},
		{true, true, false, true},
		{true, false, true, true},
		{true, true, true, true},
	} {
		if got := UEFI(c.nvram, c.sb, c.tpm); got != c.want {
			t.Errorf("UEFI(%v,%v,%v) = %v, want %v", c.nvram, c.sb, c.tpm, got, c.want)
		}
	}
}

// The partition pauser may resume a marked source only before cutover
// (spec §5.1): preparing, prepared, migrating, or a parked phase reached from
// those, source_paused excepted.
func TestFwmig_BeforeCutover(t *testing.T) {
	want := map[Phase]bool{PhasePreparing: true, PhasePrepared: true, PhaseMigrating: true}
	for _, p := range AllPhases() {
		if p.Parked() {
			continue
		}
		m := tMarker(p)
		if got := m.BeforeCutover(); got != want[p] {
			t.Errorf("%s: BeforeCutover = %v, want %v", p, got, want[p])
		}
		for _, parked := range AllPhases() {
			if !parked.Parked() {
				continue
			}
			pm := tMarker(parked)
			pm.ParkedFrom = p
			w := want[p] && parked != PhaseSourcePaused
			if got := pm.BeforeCutover(); got != w {
				t.Errorf("%s from %s: BeforeCutover = %v, want %v", parked, p, got, w)
			}
		}
	}
}

// A record directory created by a write is itself made durable: the data
// dir is fsynced after the mkdir, before the record is written, and only
// when the directory was new.
func TestFwmig_NewRecordDirIsDurable(t *testing.T) {
	dir := t.TempDir()
	fs := &recFS{root: dir}
	r := newWithFS(dir, fs)
	if err := r.PutHold(tHold(HoldPrepared, NvramPending)); err != nil {
		t.Fatal(err)
	}
	mk, sp, cr := indexOf(fs.ops, "mkdir"), indexOf(fs.ops, "sync-parent"), indexOf(fs.ops, "create")
	if mk < 0 || sp < 0 || !(mk < sp && sp < cr) {
		t.Fatalf("first write %v: want mkdir < sync-parent < create", fs.ops)
	}
	fs.ops = nil
	if err := r.PutHold(tHold(HoldVerified, NvramDone)); err != nil {
		t.Fatal(err)
	}
	if indexOf(fs.ops, "sync-parent") >= 0 {
		t.Fatalf("second write synced the parent again: %v", fs.ops)
	}
	// A failing parent fsync is reported and writes no record.
	dir2 := t.TempDir()
	fs2 := &recFS{root: dir2, fail: "sync-parent"}
	if err := newWithFS(dir2, fs2).PutMarker(tMarker(PhasePreparing)); !errors.Is(err, errInjected) {
		t.Fatalf("put with failing parent fsync: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir2, InflightDir, "vm1.json")); err == nil {
		t.Fatal("record written after the parent fsync failed")
	}
}

// A binding-checked read returns a foreign record WITH a distinct error: it
// is neither absent nor this caller's, and it still names what is there.
func TestFwmig_ReadForBinding(t *testing.T) {
	r := New(t.TempDir())
	mine := tBinding()
	recreated := Binding{UUID: tUUID, CreatedAt: "2026-10-16T09:00:00Z", Attempt: tAttempt}
	otherAttempt := Binding{UUID: tUUID, CreatedAt: tCreated, Attempt: "2a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"}

	// Absent: not ok, no error.
	if _, ok, err := r.GetHoldFor("vm1", mine); ok || err != nil {
		t.Fatalf("absent hold: ok=%v err=%v", ok, err)
	}
	if _, ok, err := r.GetMarkerFor("vm1", mine); ok || err != nil {
		t.Fatalf("absent marker: ok=%v err=%v", ok, err)
	}
	if _, ok, err := r.GetOwedDiscardFor("vm1", mine); ok || err != nil {
		t.Fatalf("absent owed: ok=%v err=%v", ok, err)
	}

	if err := r.PutHold(tHold(HoldPrepared, NvramPending)); err != nil {
		t.Fatal(err)
	}
	if err := r.PutMarker(tMarker(PhaseMigrating)); err != nil {
		t.Fatal(err)
	}
	if err := r.PutOwedDiscard(tOwed()); err != nil {
		t.Fatal(err)
	}

	// Mine.
	if h, ok, err := r.GetHoldFor("vm1", mine); !ok || err != nil || h.State != HoldPrepared {
		t.Fatalf("own hold: ok=%v err=%v", ok, err)
	}
	if _, ok, err := r.GetMarkerFor("vm1", mine); !ok || err != nil {
		t.Fatalf("own marker: ok=%v err=%v", ok, err)
	}
	if _, ok, err := r.GetOwedDiscardFor("vm1", mine); !ok || err != nil {
		t.Fatalf("own owed: ok=%v err=%v", ok, err)
	}

	// Another incarnation: present, the record returned, ErrOtherIncarnation.
	h, ok, err := r.GetHoldFor("vm1", recreated)
	if !ok || !errors.Is(err, ErrOtherIncarnation) || errors.Is(err, ErrOtherAttempt) || h.Attempt != tAttempt {
		t.Fatalf("hold for a recreated VM: ok=%v err=%v rec=%+v", ok, err, h)
	}
	m, ok, err := r.GetMarkerFor("vm1", recreated)
	if !ok || !errors.Is(err, ErrOtherIncarnation) || m.Phase != PhaseMigrating {
		t.Fatalf("marker for a recreated VM: ok=%v err=%v", ok, err)
	}
	o, ok, err := r.GetOwedDiscardFor("vm1", recreated)
	if !ok || !errors.Is(err, ErrOtherIncarnation) || o.Target != "node-2" {
		t.Fatalf("owed for a recreated VM: ok=%v err=%v", ok, err)
	}
	other := Binding{UUID: "11111111-2222-4333-8444-555555555555", CreatedAt: tCreated, Attempt: tAttempt}
	if _, ok, err := r.GetHoldFor("vm1", other); !ok || !errors.Is(err, ErrOtherIncarnation) {
		t.Fatalf("hold for another uuid: ok=%v err=%v", ok, err)
	}

	// Same incarnation, another attempt: present, ErrOtherAttempt.
	if _, ok, err := r.GetHoldFor("vm1", otherAttempt); !ok || !errors.Is(err, ErrOtherAttempt) || errors.Is(err, ErrOtherIncarnation) {
		t.Fatalf("hold for another attempt: ok=%v err=%v", ok, err)
	}
	if _, ok, err := r.GetMarkerFor("vm1", otherAttempt); !ok || !errors.Is(err, ErrOtherAttempt) {
		t.Fatalf("marker for another attempt: ok=%v err=%v", ok, err)
	}
	// The owed record is keyed by attempt: another attempt has none.
	if _, ok, err := r.GetOwedDiscardFor("vm1", otherAttempt); ok || err != nil {
		t.Fatalf("owed for another attempt: ok=%v err=%v", ok, err)
	}
	// A caller that checks only err refuses: a foreign record is never "mine".
	if _, _, err := r.GetHoldFor("vm1", Binding{}); err == nil {
		t.Fatal("an empty binding matched a hold")
	}
}

// Every key the spec lists is required: a missing key is a decode error,
// never a zero value (swtpm_absent_at_prepare=false is meaningful).
func TestFwmig_RequiredKeys(t *testing.T) {
	type kind struct {
		sub, file string
		rec       any
		get       func(r *Records) error
	}
	kinds := []kind{
		{InflightDir, "vm1.json", tMarker(PhaseTargetRan), func(r *Records) error { _, _, err := r.GetMarker("vm1"); return err }},
		{HoldDir, "vm1.json", tHold(HoldPrepared, NvramPending), func(r *Records) error { _, _, err := r.GetHold("vm1"); return err }},
		{DiscardOwedDir, "vm1-" + tAttempt + ".json", tOwed(), func(r *Records) error { _, _, err := r.GetOwedDiscard("vm1", tAttempt); return err }},
	}
	for _, k := range kinds {
		full := rawOf(t, k.rec)
		for key := range full {
			for _, how := range []string{"missing", "null"} {
				if how == "null" && key == "created_stubs" {
					continue // a nil list encodes as null
				}
				dir := t.TempDir()
				raw := rawOf(t, k.rec)
				if how == "missing" {
					delete(raw, key)
				} else {
					raw[key] = nil
				}
				writeRaw(t, dir, k.sub, k.file, raw)
				if err := k.get(New(dir)); err == nil {
					t.Errorf("%s: %s %s accepted", k.sub, key, how)
				}
			}
		}
		// The complete record reads.
		dir := t.TempDir()
		writeRaw(t, dir, k.sub, k.file, full)
		if err := k.get(New(dir)); err != nil {
			t.Errorf("%s complete: %v", k.sub, err)
		}
	}
	// A nil stub list round-trips.
	r := New(t.TempDir())
	m := tMarker(PhasePreparing)
	m.CreatedStubs = nil
	if err := r.PutMarker(m); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.GetMarker("vm1"); err != nil {
		t.Fatalf("nil stubs: %v", err)
	}
}

// Parking a parked marker keeps the progress phase it was first parked from.
func TestFwmig_ParkCarriesProgressPhase(t *testing.T) {
	m := tMarker(PhaseCutover)
	p1, err := m.Park(PhaseTargetUnreachable)
	if err != nil || p1.Phase != PhaseTargetUnreachable || p1.ParkedFrom != PhaseCutover {
		t.Fatalf("park from cutover: %+v %v", p1, err)
	}
	p2, err := p1.Park(PhaseTargetRan)
	if err != nil || p2.Phase != PhaseTargetRan || p2.ParkedFrom != PhaseCutover {
		t.Fatalf("park from parked: phase %s from %s, %v", p2.Phase, p2.ParkedFrom, err)
	}
	r := New(t.TempDir())
	if err := r.PutMarker(p2); err != nil {
		t.Fatalf("parked-to-parked marker refused: %v", err)
	}
	if p1.Phase != PhaseTargetUnreachable {
		t.Fatal("Park modified its receiver")
	}
	// A pre-cutover park stays pre-cutover through a second park.
	pre, _ := tMarker(PhasePrepared).Park(PhaseTargetUnreachable)
	pre2, err := pre.Park(PhaseDiscardPending)
	if err != nil || !pre2.BeforeCutover() {
		t.Fatalf("pre-cutover park lost: %+v %v", pre2, err)
	}
	for _, bad := range []Phase{PhaseCommitted, "", "nowhere"} {
		if _, err := m.Park(bad); err == nil {
			t.Errorf("Park(%q) accepted", bad)
		}
	}
	broken := tMarker(PhaseTargetRan)
	broken.ParkedFrom = ""
	if _, err := broken.Park(PhaseDiscardPending); err == nil {
		t.Error("parking a parked marker with no parked_from accepted")
	}
}

// Temp files left by a crash are swept; records, other files and the
// quarantine are never touched.
func TestFwmig_SweepsStaleTemps(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)
	odd := tMarker(PhasePreparing)
	odd.VM = "x.json.tmp-1" // a legal VM name that looks like a temp
	for _, put := range []func() error{
		func() error { return r.PutMarker(tMarker(PhasePreparing)) },
		func() error { return r.PutMarker(odd) },
		func() error { return r.PutHold(tHold(HoldPrepared, NvramPending)) },
		func() error { return r.PutOwedDiscard(tOwed()) },
	} {
		if err := put(); err != nil {
			t.Fatal(err)
		}
	}
	var stale []string
	for _, sub := range []string{InflightDir, HoldDir, DiscardOwedDir} {
		p := filepath.Join(dir, sub, "vm7.json.tmp-123456")
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		stale = append(stale, p)
	}
	keep := []string{
		filepath.Join(dir, QuarantineDir, "vm1-"+tAttempt, "vm1.json.tmp-99"),
		filepath.Join(dir, InflightDir, "notes.txt"),
	}
	for _, p := range keep {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if ms, err := r.ListMarkers(); err != nil || len(ms) != 2 {
		t.Fatalf("ListMarkers = %v, %v", ms, err)
	}
	if _, err := os.Stat(stale[0]); err == nil {
		t.Error("ListMarkers left a stale temp")
	}
	if err := r.SweepTemps(); err != nil {
		t.Fatal(err)
	}
	for _, p := range stale {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("stale temp %s survived", p)
		}
	}
	for _, p := range keep {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s removed: %v", p, err)
		}
	}
	if _, ok, err := r.GetMarker("x.json.tmp-1"); !ok || err != nil {
		t.Fatalf("record of a temp-like VM name swept: ok=%v err=%v", ok, err)
	}
	if hs, err := r.ListHolds(); err != nil || len(hs) != 1 {
		t.Fatalf("hold swept: %v %v", hs, err)
	}
	if ow, err := r.ListOwedDiscards(); err != nil || len(ow) != 1 {
		t.Fatalf("owed swept: %v %v", ow, err)
	}
	// No record dirs at all: nothing to sweep, no error.
	if err := New(t.TempDir()).SweepTemps(); err != nil {
		t.Fatal(err)
	}
}

// A hold the operator's D-5 --adopt-target-copy took to verified records who,
// when, from which state, why and the target's hashes (spec §17 D-5, the hold
// transition). The record is optional: a hold a move wrote, without it, reads
// as before; one with it round-trips; an adoption missing who or when, or
// naming an unknown state, does not read.
//
// Mutation: require the adoption key; drop the adoption check — red.
func TestFwmig_HoldAdoption(t *testing.T) {
	r := New(t.TempDir())
	h := tHold(HoldVerified, NvramDone)
	if err := r.PutHold(h); err != nil {
		t.Fatal(err)
	}
	if got := fileKeys(t, filepath.Join(r.dataDir, HoldDir, "vm1.json")); reflect.DeepEqual(got, nil) || contains(got, "adoption") {
		t.Fatalf("a move's hold carries %v; want no adoption key", got)
	}
	if _, _, err := r.GetHold("vm1"); err != nil {
		t.Fatalf("a hold without an adoption: %v", err)
	}
	h.Adoption = &HoldAdoption{By: "alice", At: tSince, From: HoldMismatch, Reason: "the source host was lost",
		PermallSHA256: tHashA, NvramSHA256: tHashB}
	if err := r.PutHold(h); err != nil {
		t.Fatal(err)
	}
	got, ok, err := r.GetHold("vm1")
	if err != nil || !ok || !reflect.DeepEqual(got, h) {
		t.Fatalf("adopted hold round trip: %+v ok=%v err=%v", got, ok, err)
	}
	for name, a := range map[string]HoldAdoption{
		"no_by":      {At: tSince, From: HoldPrepared},
		"no_at":      {By: "alice", From: HoldPrepared},
		"bad_from":   {By: "alice", At: tSince, From: "running"},
		"bad_hashes": {By: "alice", At: tSince, From: HoldPrepared, PermallSHA256: "x"},
	} {
		a := a
		h.Adoption = &a
		if err := r.PutHold(h); err == nil {
			t.Errorf("%s: an invalid adoption was written", name)
		}
	}
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}
