// Package fwmig holds the durable records of a live firmware (vTPM / Secure
// Boot) migration: the source marker, the target hold and the owed-discard
// record (spec §4).
//
// A record is a file under the daemon's data directory, never replicated: it
// is a statement about this host's own runtime that must survive a restart.
// Each is written temp → fsync → rename → directory fsync, and is bound to the
// VM's incarnation (spec uuid = domain uuid, plus the row's created_at) and to
// the attempt.
//
// Reading is strict. A record that does not parse, names a phase, state or
// value this build does not know, carries a field it does not know, or does
// not match the file it is in is an error — never "no record", since a record
// that reads as absent is a move nothing protects.
package fwmig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/safename"
)

// Record directories under the data directory (spec §4).
const (
	InflightDir    = "fwmig-inflight"     // source marker, <vm>.json
	DiscardOwedDir = "fwmig-discard-owed" // owed discard, <vm>-<attempt>.json
	HoldDir        = "fwmig-hold"         // target hold, <vm>.json
	RetainedDir    = "fwmig-retained"     // retained bundle, <vm>-<attempt>.tar
	QuarantineDir  = "fwmig-quarantine"   // quarantine, <vm>-<attempt>/
)

// Phase is a source marker's phase.
type Phase string

// Progress phases, in order; the marker is removed after cleaning.
const (
	PhasePreparing Phase = "preparing"
	PhasePrepared  Phase = "prepared"
	PhaseMigrating Phase = "migrating"
	PhaseCutover   Phase = "cutover"
	PhaseVerified  Phase = "verified"
	PhaseCommitted Phase = "committed"
	PhaseReleased  Phase = "released"
	PhaseCleaning  Phase = "cleaning"
)

// Parked phases: the marker is kept and a condition raised.
const (
	PhaseTargetUnreachable  Phase = "target_unreachable"
	PhaseSourceStateMissing Phase = "source_state_missing"
	PhaseSourceStateSuspect Phase = "source_state_suspect"
	PhaseTargetRan          Phase = "target_ran"
	PhaseNvramUnconfirmed   Phase = "nvram_unconfirmed"
	PhaseDiscardPending     Phase = "discard_pending"
	PhaseSourcePaused       Phase = "source_paused"
)

var progressPhases = []Phase{PhasePreparing, PhasePrepared, PhaseMigrating, PhaseCutover,
	PhaseVerified, PhaseCommitted, PhaseReleased, PhaseCleaning}

var parkedPhases = []Phase{PhaseTargetUnreachable, PhaseSourceStateMissing, PhaseSourceStateSuspect,
	PhaseTargetRan, PhaseNvramUnconfirmed, PhaseDiscardPending, PhaseSourcePaused}

// AllPhases lists every phase this build knows: the progress phases in order,
// then the parked ones.
func AllPhases() []Phase {
	return append(append([]Phase(nil), progressPhases...), parkedPhases...)
}

func phaseIn(p Phase, set []Phase) bool {
	for _, q := range set {
		if p == q {
			return true
		}
	}
	return false
}

// Valid reports whether p is a phase this build knows.
func (p Phase) Valid() bool { return phaseIn(p, progressPhases) || phaseIn(p, parkedPhases) }

// Parked reports whether p is a parked phase.
func (p Phase) Parked() bool { return phaseIn(p, parkedPhases) }

// HoldState is a target hold's state.
type HoldState string

const (
	HoldPrepared            HoldState = "prepared"
	HoldVerified            HoldState = "verified"
	HoldResuming            HoldState = "resuming" // written and fsynced BEFORE the resume
	HoldReleasedUnconfirmed HoldState = "released_unconfirmed"
	HoldMismatch            HoldState = "mismatch"
)

var holdStates = []HoldState{HoldPrepared, HoldVerified, HoldResuming, HoldReleasedUnconfirmed, HoldMismatch}

// AllHoldStates lists every hold state this build knows.
func AllHoldStates() []HoldState { return append([]HoldState(nil), holdStates...) }

// Valid reports whether s is a hold state this build knows.
func (s HoldState) Valid() bool {
	for _, q := range holdStates {
		if s == q {
			return true
		}
	}
	return false
}

// NvramMaterialised is the hold's three-valued record of the target NVRAM
// Prepare materialises. It is never a bool: "pending" (the hold was written,
// the materialisation may or may not have happened) is neither "done" nor
// "no".
type NvramMaterialised string

const (
	NvramPending NvramMaterialised = "pending"
	NvramDone    NvramMaterialised = "done"
	NvramNo      NvramMaterialised = "no"
)

// Valid reports whether v is one of the three values.
func (v NvramMaterialised) Valid() bool {
	return v == NvramPending || v == NvramDone || v == NvramNo
}

// UnmarshalJSON accepts only a JSON string naming one of the three values.
func (v *NvramMaterialised) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("nvram_materialised: want one of pending, done, no: %w", err)
	}
	if !NvramMaterialised(s).Valid() {
		return fmt.Errorf("nvram_materialised %q: want one of pending, done, no", s)
	}
	*v = NvramMaterialised(s)
	return nil
}

// Route is the marker's migration route (spec §3.3).
type Route string

const (
	RouteStorageCopy      Route = "storage_copy"      // host-local disks copied with the memory
	RouteTunnelled        Route = "tunnelled"         // memory only, through libvirtd
	RouteMigrationNetwork Route = "migration_network" // memory only, Direct+TLS over migration.network
)

// Valid reports whether r is a route this build knows.
func (r Route) Valid() bool {
	return r == RouteStorageCopy || r == RouteTunnelled || r == RouteMigrationNetwork
}

// StopReasonMigrated is the source domain's stop reason after a completed
// migration; any other src_stop_reason is a source host reboot or crash.
const StopReasonMigrated = "migrated"

// UEFI is the record's uefi flag: the firmware keeps an NVRAM file (Firmware
// is uefi or empty) AND (secure_boot OR tpm). Each side derives it from its
// own row and firmware resolution.
func UEFI(hasNvram, secureBoot, tpm bool) bool { return hasNvram && (secureBoot || tpm) }

// Binding is what a record is bound to: the VM's incarnation and the attempt.
type Binding struct {
	UUID      string `json:"uuid"`       // spec uuid = domain uuid
	CreatedAt string `json:"created_at"` // the incarnation's row created_at
	Attempt   string `json:"attempt"`
}

// SameIncarnation reports whether o names the same incarnation as b: the same
// uuid and the same row created_at. A VM deleted and recreated under its
// name and uuid is another incarnation.
func (b Binding) SameIncarnation(o Binding) bool {
	return b.UUID != "" && strings.EqualFold(b.UUID, o.UUID) && b.CreatedAt != "" && b.CreatedAt == o.CreatedAt
}

// ErrOtherIncarnation: the record names another incarnation of the VM (uuid
// or created_at differ). ErrOtherAttempt: the same incarnation, another
// attempt. Either way the record is present and is not the caller's; it
// still vetoes what a record vetoes.
var (
	ErrOtherIncarnation = errors.New("fwmig: record names another incarnation")
	ErrOtherAttempt     = errors.New("fwmig: record names another attempt")
)

// check is nil when b is o's binding, else ErrOtherIncarnation or
// ErrOtherAttempt wrapped with both bindings.
func (b Binding) check(o Binding) error {
	switch {
	case !b.SameIncarnation(o):
		return fmt.Errorf("%w: record uuid %s created_at %s attempt %s, asked for uuid %s created_at %s",
			ErrOtherIncarnation, b.UUID, b.CreatedAt, b.Attempt, o.UUID, o.CreatedAt)
	case !b.Matches(o):
		return fmt.Errorf("%w: record attempt %s, asked for %s", ErrOtherAttempt, b.Attempt, o.Attempt)
	}
	return nil
}

// Matches reports whether o names the same incarnation and the same attempt.
func (b Binding) Matches(o Binding) bool {
	return b.SameIncarnation(o) && b.Attempt != "" && b.Attempt == o.Attempt
}

// Marker is the source marker, <dataDir>/fwmig-inflight/<vm>.json.
type Marker struct {
	VM string `json:"vm"`
	Binding
	Target           string    `json:"target"`
	Route            Route     `json:"route"`
	Phase            Phase     `json:"phase"`
	TPM              bool      `json:"tpm"`
	UEFI             bool      `json:"uefi"`
	SrcPermallSHA256 string    `json:"src_permall_sha256"`
	SrcNvramSHA256   string    `json:"src_nvram_sha256"`
	SrcStopReason    string    `json:"src_stop_reason"`
	CreatedStubs     []string  `json:"created_stubs"` // what EnsureDisks reported creating (§6.1 step 4)
	Since            time.Time `json:"since"`
	Detail           string    `json:"detail"`
	// ParkedFrom is the progress phase a parked marker was parked from; empty
	// when Phase is not parked. A parked marker parked again keeps the
	// original progress phase: use Park.
	ParkedFrom Phase `json:"parked_from"`
}

// Park returns m moved to the parked phase p. ParkedFrom is m's phase when m
// is in progress, and m's own ParkedFrom when m is already parked, so a
// parked-to-parked move keeps the progress phase the move stopped at.
func (m Marker) Park(p Phase) (Marker, error) {
	if !p.Parked() {
		return Marker{}, fmt.Errorf("marker %s: %q is not a parked phase", m.VM, p)
	}
	from := m.Phase
	if m.Phase.Parked() {
		from = m.ParkedFrom
	}
	if !phaseIn(from, progressPhases) {
		return Marker{}, fmt.Errorf("marker %s: cannot park %s: no progress phase to park from (%q)", m.VM, m.Phase, from)
	}
	if p == PhaseSourcePaused && !preCutover(from) {
		return Marker{}, fmt.Errorf("marker %s: cannot park source_paused from %s, after cutover", m.VM, from)
	}
	m.Phase, m.ParkedFrom = p, from
	return m, nil
}

// BeforeCutover reports whether the marker is before cutover: preparing,
// prepared or migrating, or a parked phase reached from one of those,
// source_paused excepted (spec §5.1). For migrating the caller must still
// check that the source domain is active.
func (m Marker) BeforeCutover() bool {
	if m.Phase.Parked() {
		return m.Phase != PhaseSourcePaused && preCutover(m.ParkedFrom)
	}
	return preCutover(m.Phase)
}

// preCutover: the progress phases before cutover, while the source's copy is
// the current one.
func preCutover(p Phase) bool {
	return p == PhasePreparing || p == PhasePrepared || p == PhaseMigrating
}

// Validate checks every field's domain.
func (m Marker) Validate() error {
	if err := validateCommon(m.VM, m.Binding, m.Since); err != nil {
		return err
	}
	if err := validateHost("target", m.Target); err != nil {
		return err
	}
	if !m.Route.Valid() {
		return fmt.Errorf("marker %s: unknown route %q", m.VM, m.Route)
	}
	if !m.Phase.Valid() {
		return fmt.Errorf("marker %s: unknown phase %q", m.VM, m.Phase)
	}
	if m.Phase.Parked() {
		if !phaseIn(m.ParkedFrom, progressPhases) {
			return fmt.Errorf("marker %s: parked phase %s from %q, want a progress phase", m.VM, m.Phase, m.ParkedFrom)
		}
		// source_paused is the M1p park: the source paused before cutover,
		// its copy current. From cutover on the target's copy is current, and
		// a source_paused marker there would let the D-5 resume run a second
		// copy (one copy of a VM at every moment).
		if m.Phase == PhaseSourcePaused && !preCutover(m.ParkedFrom) {
			return fmt.Errorf("marker %s: source_paused parked from %s, after cutover", m.VM, m.ParkedFrom)
		}
	} else if m.ParkedFrom != "" {
		return fmt.Errorf("marker %s: parked_from %q on unparked phase %s", m.VM, m.ParkedFrom, m.Phase)
	}
	if !m.TPM && !m.UEFI {
		return fmt.Errorf("marker %s: neither tpm nor uefi", m.VM)
	}
	if err := validateHash("src_permall_sha256", m.SrcPermallSHA256); err != nil {
		return err
	}
	if err := validateHash("src_nvram_sha256", m.SrcNvramSHA256); err != nil {
		return err
	}
	return validateStubs(m.CreatedStubs)
}

// Hold is the target hold, <dataDir>/fwmig-hold/<vm>.json.
type Hold struct {
	VM string `json:"vm"`
	Binding
	Source                string            `json:"source"`
	Since                 time.Time         `json:"since"`
	State                 HoldState         `json:"state"`
	TPM                   bool              `json:"tpm"`
	UEFI                  bool              `json:"uefi"`
	NvramMaterialised     NvramMaterialised `json:"nvram_materialised"`
	NvramT0SHA256         string            `json:"nvram_t0_sha256"`
	SwtpmAbsentAtPrepare  bool              `json:"swtpm_absent_at_prepare"`
	VerifiedPermallSHA256 string            `json:"verified_permall_sha256"`
}

// Validate checks every field's domain.
func (h Hold) Validate() error {
	if err := validateCommon(h.VM, h.Binding, h.Since); err != nil {
		return err
	}
	if err := validateHost("source", h.Source); err != nil {
		return err
	}
	if !h.State.Valid() {
		return fmt.Errorf("hold %s: unknown state %q", h.VM, h.State)
	}
	if !h.TPM && !h.UEFI {
		return fmt.Errorf("hold %s: neither tpm nor uefi", h.VM)
	}
	if !h.NvramMaterialised.Valid() {
		return fmt.Errorf("hold %s: nvram_materialised %q, want pending, done or no", h.VM, h.NvramMaterialised)
	}
	if !h.UEFI && h.NvramMaterialised != NvramNo {
		return fmt.Errorf("hold %s: nvram_materialised %s without uefi", h.VM, h.NvramMaterialised)
	}
	if err := validateHash("nvram_t0_sha256", h.NvramT0SHA256); err != nil {
		return err
	}
	return validateHash("verified_permall_sha256", h.VerifiedPermallSHA256)
}

// OwedDiscard is the record of a DISCARD the source still owes a fenced
// target, <dataDir>/fwmig-discard-owed/<vm>-<attempt>.json. It is NOT a
// marker: it vetoes nothing (spec §7 fence resolution).
type OwedDiscard struct {
	VM string `json:"vm"`
	Binding
	Target       string    `json:"target"`
	CreatedStubs []string  `json:"created_stubs"`
	Since        time.Time `json:"since"`
}

// Validate checks every field's domain.
func (o OwedDiscard) Validate() error {
	if err := validateCommon(o.VM, o.Binding, o.Since); err != nil {
		return err
	}
	if err := validateHost("target", o.Target); err != nil {
		return err
	}
	return validateStubs(o.CreatedStubs)
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// validateAttempt: an attempt id is a UUID. It is one path component of the
// owed-discard, retained and quarantine names, and its fixed length is what
// keeps <vm>-<attempt> unambiguous for a VM name that contains '-'.
func validateAttempt(a string) error {
	if !uuidRe.MatchString(a) {
		return fmt.Errorf("attempt %q is not a UUID", a)
	}
	return nil
}

func validateCommon(vm string, b Binding, since time.Time) error {
	if err := safename.ValidateVMName(vm); err != nil {
		return err
	}
	if !uuidRe.MatchString(b.UUID) {
		return fmt.Errorf("vm %s: uuid %q is not a UUID", vm, b.UUID)
	}
	if b.CreatedAt == "" {
		return fmt.Errorf("vm %s: no created_at", vm)
	}
	if err := validateAttempt(b.Attempt); err != nil {
		return fmt.Errorf("vm %s: %w", vm, err)
	}
	if since.IsZero() {
		return fmt.Errorf("vm %s: no since", vm)
	}
	return nil
}

func validateHost(field, h string) error {
	if err := safename.ValidateName(h); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func validateHash(field, h string) error {
	if h != "" && !hashRe.MatchString(h) {
		return fmt.Errorf("%s %q is not a lowercase hex sha256", field, h)
	}
	return nil
}

func validateStubs(stubs []string) error {
	for _, p := range stubs {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("created_stubs: %q is not a clean absolute path", p)
		}
	}
	return nil
}

// tempFile and fileSystem are the filesystem calls a write makes; tests
// substitute them to observe the order and inject failures.
type tempFile interface {
	Name() string
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type fileSystem interface {
	MkdirAll(dir string, perm os.FileMode) error
	CreateTemp(dir, pattern string) (tempFile, error)
	Rename(oldpath, newpath string) error
	Remove(path string) error
	SyncDir(dir string) error
	ReadFile(path string) ([]byte, error)
	ReadDir(dir string) ([]os.DirEntry, error)
}

type osFS struct{}

func (osFS) MkdirAll(dir string, perm os.FileMode) error { return os.MkdirAll(dir, perm) }
func (osFS) CreateTemp(dir, pattern string) (tempFile, error) {
	return os.CreateTemp(dir, pattern) // mode 0600
}
func (osFS) Rename(o, n string) error                { return os.Rename(o, n) }
func (osFS) Remove(p string) error                   { return os.Remove(p) }
func (osFS) ReadFile(p string) ([]byte, error)       { return os.ReadFile(p) }
func (osFS) ReadDir(d string) ([]os.DirEntry, error) { return os.ReadDir(d) }
func (osFS) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Records reads and writes one host's records under its data directory.
type Records struct {
	dataDir string
	fs      fileSystem
}

// New returns the records under dataDir.
func New(dataDir string) *Records { return newWithFS(dataDir, osFS{}) }

func newWithFS(dataDir string, fs fileSystem) *Records {
	return &Records{dataDir: dataDir, fs: fs}
}

func (r *Records) root() (string, error) {
	if r.dataDir == "" {
		return "", errors.New("fwmig: no data directory")
	}
	return r.dataDir, nil
}

func (r *Records) vmPath(sub, vm string) (string, error) {
	root, err := r.root()
	if err != nil {
		return "", err
	}
	if err := safename.ValidateVMName(vm); err != nil {
		return "", err
	}
	return filepath.Join(root, sub, vm+".json"), nil
}

func (r *Records) attemptName(vm, attempt string) (string, string, error) {
	root, err := r.root()
	if err != nil {
		return "", "", err
	}
	if err := safename.ValidateVMName(vm); err != nil {
		return "", "", err
	}
	if err := validateAttempt(attempt); err != nil {
		return "", "", err
	}
	return root, vm + "-" + attempt, nil
}

// RetainedPath is the retained bundle's path, <dataDir>/fwmig-retained/<vm>-<attempt>.tar.
func (r *Records) RetainedPath(vm, attempt string) (string, error) {
	root, base, err := r.attemptName(vm, attempt)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, RetainedDir, base+".tar"), nil
}

// QuarantinePath is the attempt's quarantine directory, <dataDir>/fwmig-quarantine/<vm>-<attempt>.
func (r *Records) QuarantinePath(vm, attempt string) (string, error) {
	root, base, err := r.attemptName(vm, attempt)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, QuarantineDir, base), nil
}

func (r *Records) owedPath(vm, attempt string) (string, error) {
	root, base, err := r.attemptName(vm, attempt)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, DiscardOwedDir, base+".json"), nil
}

// tempMu serialises a write's temp file (create to rename) against the
// sweep, so a sweep never removes a temp a write in this process still owns:
// any temp it sees belongs to a write that died with its process.
var tempMu sync.Mutex

// put writes v to path durably: temp file, fsync, rename, directory fsync. A
// record directory the write creates is made durable too (its parent is
// fsynced) before the record goes in it.
func (r *Records) put(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tempMu.Lock()
	defer tempMu.Unlock()
	_, statErr := os.Stat(dir)
	if err := r.fs.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if errors.Is(statErr, os.ErrNotExist) {
		if err := r.fs.SyncDir(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	tmp, err := r.fs.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = r.fs.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := r.fs.Rename(tmp.Name(), path); err != nil {
		return err
	}
	renamed = true
	return r.fs.SyncDir(dir)
}

// remove drops path durably; absent is success.
func (r *Records) remove(path string) error {
	if err := r.fs.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return r.fs.SyncDir(filepath.Dir(path))
}

// get reads path strictly into v; ok is false only when the file is absent.
func (r *Records) get(path string, v interface{ Validate() error }) (bool, error) {
	b, err := r.fs.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return false, fmt.Errorf("fwmig: corrupt record %s: %w", path, err)
	}
	if dec.More() {
		return false, fmt.Errorf("fwmig: corrupt record %s: trailing data", path)
	}
	if err := requireKeys(b, v); err != nil {
		return false, fmt.Errorf("fwmig: corrupt record %s: %w", path, err)
	}
	if err := v.Validate(); err != nil {
		return false, fmt.Errorf("fwmig: invalid record %s: %w", path, err)
	}
	return true, nil
}

// nullableKeys may be JSON null: a nil list encodes as null.
var nullableKeys = map[string]bool{"created_stubs": true}

// requireKeys fails unless the object b carries every key of v's type,
// non-null: a missing key must not decode as a zero value
// (swtpm_absent_at_prepare=false is a statement, not a default).
func requireKeys(b []byte, v any) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	for _, k := range jsonKeys(reflect.TypeOf(v).Elem()) {
		raw, ok := obj[k]
		if !ok {
			return fmt.Errorf("missing key %q", k)
		}
		if !nullableKeys[k] && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("key %q is null", k)
		}
	}
	return nil
}

// jsonKeys lists t's JSON keys, flattening embedded structs.
func jsonKeys(t reflect.Type) []string {
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			keys = append(keys, jsonKeys(f.Type)...)
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys = append(keys, name)
		}
	}
	return keys
}

// isTemp reports whether name is a write's temp file: <record>.json.tmp-<digits>.
// A record of a VM whose name looks like one still ends in .json.
func isTemp(name string) bool {
	i := strings.LastIndex(name, ".json.tmp-")
	if i <= 0 {
		return false
	}
	rest := name[i+len(".json.tmp-"):]
	if rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// sweepDir removes the temp files a crashed write left in one record
// directory. It touches nothing else.
func (r *Records) sweepDir(dir string) error {
	tempMu.Lock()
	defer tempMu.Unlock()
	ents, err := r.fs.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.Type().IsRegular() && isTemp(e.Name()) {
			if err := r.fs.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// SweepTemps removes the temp files crashed writes left in the marker, hold
// and owed-discard directories. It never reads fwmig-quarantine/ or
// fwmig-retained/. Every List does the same for its own directory.
func (r *Records) SweepTemps() error {
	root, err := r.root()
	if err != nil {
		return err
	}
	for _, sub := range []string{InflightDir, HoldDir, DiscardOwedDir} {
		if err := r.sweepDir(filepath.Join(root, sub)); err != nil {
			return err
		}
	}
	return nil
}

// list returns the names of the record files in sub, sorted, after sweeping
// its stale temp files.
func (r *Records) list(sub string) (string, []string, error) {
	root, err := r.root()
	if err != nil {
		return "", nil, err
	}
	dir := filepath.Join(root, sub)
	if err := r.sweepDir(dir); err != nil {
		return "", nil, err
	}
	ents, err := r.fs.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return dir, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return dir, names, nil
}

// PutMarker writes m durably, replacing any marker for m.VM.
func (r *Records) PutMarker(m Marker) error {
	if err := m.Validate(); err != nil {
		return err
	}
	p, err := r.vmPath(InflightDir, m.VM)
	if err != nil {
		return err
	}
	return r.put(p, m)
}

// GetMarkerFor reads vm's marker for the caller's binding. ok is true
// whenever a marker exists; a marker of another incarnation or attempt is
// returned with ErrOtherIncarnation or ErrOtherAttempt. It is still a marker
// and still vetoes.
func (r *Records) GetMarkerFor(vm string, b Binding) (Marker, bool, error) {
	m, ok, err := r.GetMarker(vm)
	if err != nil || !ok {
		return m, ok, err
	}
	return m, true, m.Binding.check(b)
}

// GetMarker reads vm's marker; ok is false when there is none. It does NOT
// check the binding: callers acting for one attempt use GetMarkerFor.
func (r *Records) GetMarker(vm string) (Marker, bool, error) {
	p, err := r.vmPath(InflightDir, vm)
	if err != nil {
		return Marker{}, false, err
	}
	return r.readMarker(p, vm)
}

func (r *Records) readMarker(p, vm string) (Marker, bool, error) {
	var m Marker
	ok, err := r.get(p, &m)
	if err != nil || !ok {
		return Marker{}, false, err
	}
	if m.VM != vm {
		return Marker{}, false, fmt.Errorf("fwmig: marker %s names vm %q", p, m.VM)
	}
	return m, true, nil
}

// RemoveMarker drops vm's marker durably; absent is success.
func (r *Records) RemoveMarker(vm string) error {
	p, err := r.vmPath(InflightDir, vm)
	if err != nil {
		return err
	}
	return r.remove(p)
}

// ListMarkers is every marker, sorted by VM. One that does not read is an
// error, not a skip.
func (r *Records) ListMarkers() ([]Marker, error) {
	dir, names, err := r.list(InflightDir)
	if err != nil {
		return nil, err
	}
	var out []Marker
	for _, n := range names {
		m, ok, err := r.readMarker(filepath.Join(dir, n), strings.TrimSuffix(n, ".json"))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// PutHold writes h durably, replacing any hold for h.VM.
func (r *Records) PutHold(h Hold) error {
	if err := h.Validate(); err != nil {
		return err
	}
	p, err := r.vmPath(HoldDir, h.VM)
	if err != nil {
		return err
	}
	return r.put(p, h)
}

// GetHoldFor reads vm's hold for the caller's binding. ok is true whenever a
// hold exists; a hold of another incarnation or attempt is returned with
// ErrOtherIncarnation or ErrOtherAttempt. It is still a hold and still
// vetoes.
func (r *Records) GetHoldFor(vm string, b Binding) (Hold, bool, error) {
	h, ok, err := r.GetHold(vm)
	if err != nil || !ok {
		return h, ok, err
	}
	return h, true, h.Binding.check(b)
}

// GetHold reads vm's hold; ok is false when there is none. It does NOT check
// the binding: callers acting for one attempt use GetHoldFor.
func (r *Records) GetHold(vm string) (Hold, bool, error) {
	p, err := r.vmPath(HoldDir, vm)
	if err != nil {
		return Hold{}, false, err
	}
	return r.readHold(p, vm)
}

func (r *Records) readHold(p, vm string) (Hold, bool, error) {
	var h Hold
	ok, err := r.get(p, &h)
	if err != nil || !ok {
		return Hold{}, false, err
	}
	if h.VM != vm {
		return Hold{}, false, fmt.Errorf("fwmig: hold %s names vm %q", p, h.VM)
	}
	return h, true, nil
}

// RemoveHold drops vm's hold durably; absent is success.
func (r *Records) RemoveHold(vm string) error {
	p, err := r.vmPath(HoldDir, vm)
	if err != nil {
		return err
	}
	return r.remove(p)
}

// ListHolds is every hold, sorted by VM. One that does not read is an error.
func (r *Records) ListHolds() ([]Hold, error) {
	dir, names, err := r.list(HoldDir)
	if err != nil {
		return nil, err
	}
	var out []Hold
	for _, n := range names {
		h, ok, err := r.readHold(filepath.Join(dir, n), strings.TrimSuffix(n, ".json"))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, h)
		}
	}
	return out, nil
}

// PutOwedDiscard writes o durably under its vm and attempt.
func (r *Records) PutOwedDiscard(o OwedDiscard) error {
	if err := o.Validate(); err != nil {
		return err
	}
	p, err := r.owedPath(o.VM, o.Attempt)
	if err != nil {
		return err
	}
	return r.put(p, o)
}

// GetOwedDiscardFor reads the owed-discard record for vm and b.Attempt. ok
// is true whenever one exists; one of another incarnation is returned with
// ErrOtherIncarnation.
func (r *Records) GetOwedDiscardFor(vm string, b Binding) (OwedDiscard, bool, error) {
	o, ok, err := r.GetOwedDiscard(vm, b.Attempt)
	if err != nil || !ok {
		return o, ok, err
	}
	return o, true, o.Binding.check(b)
}

// GetOwedDiscard reads the owed-discard record for vm and attempt. It does
// NOT check the incarnation: use GetOwedDiscardFor.
func (r *Records) GetOwedDiscard(vm, attempt string) (OwedDiscard, bool, error) {
	p, err := r.owedPath(vm, attempt)
	if err != nil {
		return OwedDiscard{}, false, err
	}
	return r.readOwed(p)
}

func (r *Records) readOwed(p string) (OwedDiscard, bool, error) {
	var o OwedDiscard
	ok, err := r.get(p, &o)
	if err != nil || !ok {
		return OwedDiscard{}, false, err
	}
	if want := o.VM + "-" + o.Attempt + ".json"; filepath.Base(p) != want {
		return OwedDiscard{}, false, fmt.Errorf("fwmig: owed-discard record %s names %s", p, want)
	}
	return o, true, nil
}

// RemoveOwedDiscard drops the record for vm and attempt durably; absent is
// success.
func (r *Records) RemoveOwedDiscard(vm, attempt string) error {
	p, err := r.owedPath(vm, attempt)
	if err != nil {
		return err
	}
	return r.remove(p)
}

// ListOwedDiscards is every owed-discard record, sorted by file name. One
// that does not read is an error.
func (r *Records) ListOwedDiscards() ([]OwedDiscard, error) {
	dir, names, err := r.list(DiscardOwedDir)
	if err != nil {
		return nil, err
	}
	var out []OwedDiscard
	for _, n := range names {
		o, ok, err := r.readOwed(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}
