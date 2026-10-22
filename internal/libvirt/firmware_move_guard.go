package libvirt

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
	"github.com/google/uuid"
)

// The firmware move guard (spec §5.1). While a live firmware migration's
// record names a VM on this host — a source marker or a target hold — the
// libvirt operations and firmware-state writes that could run, stop, redefine,
// undefine or overwrite either copy of its TPM or NVRAM state are refused,
// except through the move's own exempt entry points.
//
// The records live in internal/fwmig; fwmig.Wire installs a guard built from
// them on the host's libvirt client and on its FirmwareStore. This file holds
// the rules, so the client, the store and libvirtfake answer from one table.

// ErrFirmwareMoveInFlight: a record of a live firmware migration names the VM
// on this host, or a record cannot be read, and the operation is refused.
var ErrFirmwareMoveInFlight = errors.New("live firmware migration in flight")

// ErrFirmwareMoveNoRecord: an exempt entry point was called for a VM no record
// names. An exempt entry point acts only for the move a record describes.
var ErrFirmwareMoveNoRecord = errors.New("no live firmware migration record")

// ErrFirmwareMoveRecordUnreadable: a firmware move record on this host cannot
// be read, so the guard cannot tell whether it names the VM, and refuses. It
// names no move in flight: the refusal carries the file
// (*FirmwareRecordUnreadableError) and what to do about it.
var ErrFirmwareMoveRecordUnreadable = errors.New("firmware move record unreadable")

// IsFirmwareMoveRefusal reports whether err is a refusal of the firmware move
// guard: a record names the VM, or a record cannot be read.
func IsFirmwareMoveRefusal(err error) bool {
	return errors.Is(err, ErrFirmwareMoveInFlight) || errors.Is(err, ErrFirmwareMoveRecordUnreadable)
}

// FirmwareRecordUnreadableError is a firmware move record file (or record
// directory) that cannot be read. A FirmwareMoveLookup returns it; the guard
// refuses on it, naming the file and the remedy.
type FirmwareRecordUnreadableError struct {
	Path string
	Err  error
}

func (e *FirmwareRecordUnreadableError) Error() string {
	return fmt.Sprintf("firmware move record %s cannot be read (%v); until it is repaired, or moved out of %s once no "+
		"firmware move on this host needs it, every operation it might name is refused here, and the condition "+
		"firmware_migration_record_unreadable names it", e.Path, e.Err, filepath.Dir(e.Path))
}

func (e *FirmwareRecordUnreadableError) Unwrap() error { return e.Err }

// FirmwareOp is a class of guarded operation (spec §5.1 table rows).
type FirmwareOp string

const (
	OpStart      FirmwareOp = "start"       // StartDomain, snapshot reverts, restore
	OpResume     FirmwareOp = "resume"      // ResumeDomain
	OpStop       FirmwareOp = "stop"        // DestroyDomain, ShutdownDomain, forceRemoveDomain's destroy
	OpDefine     FirmwareOp = "define"      // DefineDomain, SetBootOrder
	OpUndefine   FirmwareOp = "undefine"    // UndefineDomain*, forceRemoveDomain's undefine
	OpWriteState FirmwareOp = "write_state" // store ReadFirmwareBundle, RemoveNvram, RenameNvram
	OpWipe       FirmwareOp = "wipe"        // store wipes
)

// FirmwareExemption names the exempt entry point a call comes through; ""
// is an ordinary call. Each is allowed only for the op, record kind and
// record state spec §5.1 gives it, and (except ResumePartitionPaused, which
// knows no attempt) only for the record's own uuid and attempt.
type FirmwareExemption string

const (
	ViaResumeFirmwareMoveSource          FirmwareExemption = "ResumeFirmwareMoveSource"
	ViaResumeFirmwareMoveSourceOperator  FirmwareExemption = "ResumeFirmwareMoveSourceForOperator"
	ViaResumePartitionPaused             FirmwareExemption = "ResumePartitionPaused"
	ViaResumeFirmwareMoveTarget          FirmwareExemption = "ResumeFirmwareMoveTarget"
	ViaDiscardFirmwareMoveTarget         FirmwareExemption = "DiscardFirmwareMoveTarget"
	ViaUndefineFirmwareMoveLeftover      FirmwareExemption = "UndefineFirmwareMoveLeftover"
	ViaWipeFirmwareMoveSource            FirmwareExemption = "WipeFirmwareMoveSource"
	ViaMaterialiseFirmwareMoveNvram      FirmwareExemption = "MaterialiseFirmwareMoveNvram"
	ViaPushFirmwareMoveNvram             FirmwareExemption = "PushFirmwareMoveNvram"
	ViaRemoveFirmwareMoveTargetState     FirmwareExemption = "RemoveFirmwareMoveTargetState"
	ViaQuarantineFirmwareMoveTargetState FirmwareExemption = "QuarantineFirmwareMoveTargetState"
	ViaStopFirmwareMoveTargetForOperator FirmwareExemption = "StopFirmwareMoveTargetForOperator"
	ViaPushSourceNvramForOperator        FirmwareExemption = "PushSourceNvramForOperator"
	// ViaQuarantineFirmwareMoveSourceForOperator moves a cleaning move's
	// source state into the quarantine (D-5 --accept-target on a cleanup the
	// source state's change stopped).
	ViaQuarantineFirmwareMoveSourceForOperator FirmwareExemption = "QuarantineFirmwareMoveSourceForOperator"
	// The D-5 --discard-target of a leftover an owed DISCARD names after its
	// hold went: stop it, quarantine its state, undefine it keeping state.
	ViaStopOwedFirmwareLeftover       FirmwareExemption = "StopOwedFirmwareLeftover"
	ViaQuarantineOwedFirmwareLeftover FirmwareExemption = "QuarantineOwedFirmwareLeftover"
	ViaUndefineOwedFirmwareLeftover   FirmwareExemption = "UndefineOwedFirmwareLeftover"
)

// FirmwareCall is one guarded call.
type FirmwareCall struct {
	Op      FirmwareOp
	Name    string // the VM (domain) name; "" for a uuid-only call
	UUID    string // the domain uuid; "" when the caller knows only the name
	Attempt string // the move's attempt, for an exempt entry point
	Via     FirmwareExemption
}

// FirmwareRecordKind tells a source marker from a target hold.
type FirmwareRecordKind string

const (
	FirmwareMarker FirmwareRecordKind = "marker"
	FirmwareHold   FirmwareRecordKind = "hold"
	// FirmwareLeftover is a target's record of a leftover an owed DISCARD
	// names after its hold went (fwmig.Leftover).
	FirmwareLeftover FirmwareRecordKind = "leftover"
	// FirmwareStaged is a VM's own firmware state (NVRAM, swtpm tree) sitting
	// in an unfinished quarantine of the reconciler
	// (<data_dir>/fwmig-quarantine/<vm>-reconciling-<uuid>) or an interrupted
	// restore (<vm>-restoring-<uuid>): the domain's own paths are empty, so a
	// start, resume or define would boot the VM on blank firmware state. Those
	// are refused; a stop, an undefine, a wipe (the quarantine finishing) and a
	// state write (the restore moving it back) are not.
	FirmwareStaged FirmwareRecordKind = "staged"
)

// The record states the rules name. They are fwmig's values; fwmig's tests
// pin that they agree.
const (
	FirmwarePhaseCleaning           = "cleaning"
	FirmwarePhaseSourcePaused       = "source_paused"
	FirmwareHoldPrepared            = "prepared"
	FirmwareHoldVerified            = "verified"
	FirmwareHoldResuming            = "resuming"
	FirmwareHoldMismatch            = "mismatch"
	FirmwareHoldReleasedUnconfirmed = "released_unconfirmed"
)

// FirmwareMoveRecord is what the guard needs to know of one record.
type FirmwareMoveRecord struct {
	Kind    FirmwareRecordKind
	VM      string
	UUID    string
	Attempt string
	Peer    string // a marker's target, a hold's source
	State   string // a marker's phase, a hold's state
	// PreCutover (marker): the phase is before cutover, fwmig's
	// Marker.BeforeCutover.
	PreCutover bool
	// ParkedPreCutover (marker): the marker is parked, and was parked from a
	// phase before cutover (preparing, prepared, migrating), so the source's
	// copy is still the current one. Unlike PreCutover it holds for
	// source_paused too.
	ParkedPreCutover bool
	// Parked (marker): the phase is a parked one, whatever it was parked
	// from.
	Parked bool
	// RetainedBundle (marker): the attempt's retained bundle is on disk.
	RetainedBundle bool
	// Path (staged): the directory that holds the state.
	Path string
}

// FirmwareMoveLookup returns every record that names the VM by name or by
// uuid ("" = not known). An error is a record that cannot be read; the guard
// refuses on it.
type FirmwareMoveLookup func(name, uuid string) ([]FirmwareMoveRecord, error)

// FirmwareMoveGuard answers whether a call may go ahead. A zero guard allows
// everything: a client or store nothing has wired.
type FirmwareMoveGuard struct {
	Check func(FirmwareCall) error
}

func (g FirmwareMoveGuard) check(c FirmwareCall) error {
	if g.Check == nil {
		return nil
	}
	return g.Check(c)
}

// NewFirmwareMoveGuard is the guard of spec §5.1 over the records lookup
// returns. It fails closed: a lookup error refuses, and so does a nil lookup.
func NewFirmwareMoveGuard(lookup FirmwareMoveLookup) FirmwareMoveGuard {
	return FirmwareMoveGuard{Check: func(c FirmwareCall) error { return checkFirmwareCall(lookup, c) }}
}

func checkFirmwareCall(lookup FirmwareMoveLookup, c FirmwareCall) error {
	who := c.Name
	if who == "" {
		who = "uuid " + c.UUID
	}
	if lookup == nil {
		return fmt.Errorf("%w: %s of %s refused: no firmware move records to check", ErrFirmwareMoveRecordUnreadable, c.Op, who)
	}
	var recs []FirmwareMoveRecord
	if c.Name != "" || c.UUID != "" {
		var err error
		if recs, err = lookup(c.Name, c.UUID); err != nil {
			// Not "in flight": the record may be any VM's. Name the file.
			var ue *FirmwareRecordUnreadableError
			if errors.As(err, &ue) {
				return fmt.Errorf("%w: %s of %s refused: %w", ErrFirmwareMoveRecordUnreadable, c.Op, who, ue)
			}
			return fmt.Errorf("%w: %s of %s refused: the firmware move records on this host cannot be read: %w", ErrFirmwareMoveRecordUnreadable, c.Op, who, err)
		}
	}
	if len(recs) == 0 {
		// The partition pauser resumes every guest it paused through its
		// entry point, a firmware VM or not: with no record it is an
		// ordinary resume. Every other entry point acts only for a move.
		if c.Via != "" && c.Via != ViaResumePartitionPaused {
			return fmt.Errorf("%w: VM %s: %s acts only for a live firmware migration, and no record names attempt %q", ErrFirmwareMoveNoRecord, who, c.Via, c.Attempt)
		}
		return nil
	}
	for _, r := range recs {
		if ordinaryAllows(r, c.Op) || (c.Via != "" && exemptionAllows(r, c)) {
			continue
		}
		return refusal(r, c)
	}
	return nil
}

// heldPaused: the hold states whose guest is held paused (or mismatched) and
// must not be run, stopped, redefined or have its state written.
func heldPaused(state string) bool {
	switch state {
	case FirmwareHoldPrepared, FirmwareHoldVerified, FirmwareHoldResuming, FirmwareHoldMismatch:
		return true
	}
	return false
}

// ordinaryAllows is the table for an ordinary call. A marker refuses every
// op; a hold refuses every op, except that a released_unconfirmed hold (the
// guest runs; its NVRAM is not yet confirmed) lets a paused guest resume.
func ordinaryAllows(r FirmwareMoveRecord, op FirmwareOp) bool {
	if r.Kind == FirmwareStaged {
		switch op {
		case OpStop, OpUndefine, OpWipe, OpWriteState:
			return true
		}
		return false
	}
	return r.Kind == FirmwareHold && r.State == FirmwareHoldReleasedUnconfirmed && op == OpResume
}

func sameUUID(a, b string) bool { return a != "" && strings.EqualFold(a, b) }

// exemptionAllows is the exempt column of the table: the entry point, the op
// it may do, the record kind and state it may do it under, and the binding.
func exemptionAllows(r FirmwareMoveRecord, c FirmwareCall) bool {
	bound := sameUUID(r.UUID, c.UUID) && c.Attempt != "" && r.Attempt == c.Attempt
	marker, hold := r.Kind == FirmwareMarker, r.Kind == FirmwareHold
	switch c.Via {
	case ViaResumeFirmwareMoveSource:
		// §7 M1p, and its recovery retry: before cutover only. Never from
		// source_paused, whose D-5 action discards the target first and has
		// an entry point of its own.
		return marker && c.Op == OpResume && bound && r.PreCutover
	case ViaResumeFirmwareMoveSourceOperator:
		// §17 D-5 --accept-source from source_paused (spec §5.y), and only
		// when that park came before cutover: the source's copy is current.
		return marker && c.Op == OpResume && bound && r.State == FirmwarePhaseSourcePaused && r.ParkedPreCutover
	case ViaResumePartitionPaused:
		// The partition pauser knows the domain's uuid, not the attempt. A
		// marker in progress before cutover only: a parked move resumes its
		// source through its own steps (the M1p handler and its retry, which
		// ask the target first), never the pauser, since a parked target may
		// hold a copy it cannot report (D2-13 re-review 3, m-C).
		return marker && c.Op == OpResume && sameUUID(r.UUID, c.UUID) && r.PreCutover && !r.Parked
	case ViaResumeFirmwareMoveTarget:
		return hold && c.Op == OpResume && bound && r.State == FirmwareHoldResuming
	case ViaDiscardFirmwareMoveTarget:
		return hold && (c.Op == OpStop || c.Op == OpUndefine) && bound && heldPaused(r.State)
	case ViaUndefineFirmwareMoveLeftover:
		return marker && c.Op == OpUndefine && bound && r.State == FirmwarePhaseCleaning
	case ViaWipeFirmwareMoveSource:
		return marker && c.Op == OpWipe && bound && r.State == FirmwarePhaseCleaning && r.RetainedBundle
	case ViaMaterialiseFirmwareMoveNvram:
		return hold && c.Op == OpWriteState && bound && r.State == FirmwareHoldPrepared
	case ViaPushFirmwareMoveNvram:
		return hold && c.Op == OpWriteState && bound && (r.State == FirmwareHoldVerified || r.State == FirmwareHoldResuming)
	case ViaRemoveFirmwareMoveTargetState:
		return hold && c.Op == OpWipe && bound && r.State == FirmwareHoldPrepared
	case ViaQuarantineFirmwareMoveTargetState:
		return hold && c.Op == OpWipe && bound && heldPaused(r.State)
	case ViaStopFirmwareMoveTargetForOperator:
		// D-5: --stop-target while the hold is prepared, verified or
		// resuming (spec §5.y), and the stop of a released_unconfirmed guest.
		switch r.State {
		case FirmwareHoldPrepared, FirmwareHoldVerified, FirmwareHoldResuming, FirmwareHoldReleasedUnconfirmed:
			return hold && c.Op == OpStop && bound
		}
		return false
	case ViaPushSourceNvramForOperator:
		// D-5 --push-source-nvram while the hold is released_unconfirmed
		// (spec §5.y).
		return hold && c.Op == OpWriteState && bound && r.State == FirmwareHoldReleasedUnconfirmed
	case ViaStopOwedFirmwareLeftover:
		return r.Kind == FirmwareLeftover && c.Op == OpStop && bound
	case ViaQuarantineOwedFirmwareLeftover:
		return r.Kind == FirmwareLeftover && c.Op == OpWipe && bound
	case ViaUndefineOwedFirmwareLeftover:
		return r.Kind == FirmwareLeftover && c.Op == OpUndefine && bound
	case ViaQuarantineFirmwareMoveSourceForOperator:
		// D-5 --accept-target on a source cleanup that stopped: the source
		// state is moved aside, never deleted, from a cleaning marker.
		return marker && c.Op == OpWipe && bound && r.State == FirmwarePhaseCleaning
	}
	return false
}

func refusal(r FirmwareMoveRecord, c FirmwareCall) error {
	dir, what := "to", "phase"
	switch r.Kind {
	case FirmwareHold:
		dir, what = "from", "state"
	case FirmwareStaged:
		return fmt.Errorf("%w: VM %s: its firmware state (NVRAM, vTPM) is in %s, not in place, and the VM must not boot on blank firmware state; %s refused. "+
			"The reconciler finishes a leftover's quarantine on its next pass; for the VM's own domain, "+
			"`lv host superseded-disks <host> --restore %s` puts the state back",
			ErrFirmwareMoveInFlight, r.VM, r.Path, refusedHow(c), r.Path)
	case FirmwareLeftover:
		return fmt.Errorf("%w: VM %s: the leftover of live firmware migration %s from %s, whose DISCARD is owed, is kept until `lv doctor firmware-move %s --discard-target` quarantines it; %s refused",
			ErrFirmwareMoveInFlight, r.VM, r.Attempt, r.Peer, r.VM, refusedHow(c))
	}
	return fmt.Errorf("%w: VM %s: live firmware migration %s %s %s in %s %s; %s refused",
		ErrFirmwareMoveInFlight, r.VM, r.Attempt, dir, r.Peer, what, r.State, refusedHow(c))
}

func refusedHow(c FirmwareCall) string {
	how := string(c.Op)
	if c.Via != "" {
		how += " through " + string(c.Via)
	}
	return how
}

// domainOpsAPI is the part of libvirt the guarded domain operations use.
type domainOpsAPI interface {
	snapshotAPI
	DomainShutdown(dom golibvirt.Domain) error
}

var _ domainOpsAPI = (*golibvirt.Libvirt)(nil)

// SetFirmwareMoveGuard installs the firmware move guard every guarded
// operation of this client asks (fwmig.Wire). It is asked before the start
// guard, whatever that one's readiness.
func (c *Client) SetFirmwareMoveGuard(g FirmwareMoveGuard) {
	c.mu.Lock()
	c.fwGuard = g
	c.mu.Unlock()
}

func (c *Client) firmwareGuard() FirmwareMoveGuard {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.fwGuard
}

// domainUUID is the canonical form of a domain's uuid.
func domainUUID(d golibvirt.Domain) string { return uuid.UUID(d.UUID).String() }

// lookupBound looks name up and, for a call that names a uuid, refuses a
// domain of that name with another uuid: an exempt entry point never acts on
// a domain found only by name.
func lookupBound(v snapshotAPI, name, wantUUID string) (golibvirt.Domain, error) {
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return dom, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if got := domainUUID(dom); !sameUUID(wantUUID, got) {
		return dom, fmt.Errorf("domain %s has uuid %s, not %s", name, got, wantUUID)
	}
	return dom, nil
}

// resumeDomain resumes name after the guard allows c (an OpResume call).
func resumeDomain(v snapshotAPI, fg FirmwareMoveGuard, c FirmwareCall) error {
	if err := fg.check(c); err != nil {
		return fmt.Errorf("resume domain %s: %w", c.Name, err)
	}
	var (
		dom golibvirt.Domain
		err error
	)
	if c.UUID != "" {
		dom, err = lookupBound(v, c.Name, c.UUID)
	} else if dom, err = v.DomainLookupByName(c.Name); err != nil {
		err = fmt.Errorf("lookup domain %s: %w", c.Name, err)
	}
	if err != nil {
		return err
	}
	if err := v.DomainResume(dom); err != nil {
		return fmt.Errorf("resume domain %s: %w", c.Name, err)
	}
	return nil
}

func destroyDomain(v snapshotAPI, fg FirmwareMoveGuard, name string) error {
	if err := fg.check(FirmwareCall{Op: OpStop, Name: name}); err != nil {
		return fmt.Errorf("destroy domain %s: %w", name, err)
	}
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := v.DomainDestroy(dom); err != nil {
		return fmt.Errorf("destroy domain %s: %w", name, err)
	}
	return nil
}

func shutdownDomain(v domainOpsAPI, fg FirmwareMoveGuard, name string) error {
	if err := fg.check(FirmwareCall{Op: OpStop, Name: name}); err != nil {
		return fmt.Errorf("shutdown domain %s: %w", name, err)
	}
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := v.DomainShutdown(dom); err != nil {
		return fmt.Errorf("shutdown domain %s: %w", name, err)
	}
	return nil
}

func undefineDomain(v snapshotAPI, fg FirmwareMoveGuard, name string, removeStorage bool) error {
	if err := fg.check(FirmwareCall{Op: OpUndefine, Name: name}); err != nil {
		return fmt.Errorf("undefine domain %s: %w", name, err)
	}
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	// Always include NVRAM flag — UEFI domains cannot be undefined without it.
	flags := golibvirt.DomainUndefineNvram
	if removeStorage {
		flags |= golibvirt.DomainUndefineManagedSave |
			golibvirt.DomainUndefineSnapshotsMetadata |
			golibvirt.DomainUndefineCheckpointsMetadata
	}
	if err := v.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(flags)); err != nil {
		return fmt.Errorf("undefine domain %s: %w", name, err)
	}
	return nil
}

// keepStateUndefineFlags undefines a domain and keeps its NVRAM and swtpm
// state (probe (b): flags 72, both files byte-unchanged).
const keepStateUndefineFlags = golibvirt.DomainUndefineKeepNvram | golibvirt.DomainUndefineKeepTpm

func undefineDomainPreservingState(v snapshotAPI, fg FirmwareMoveGuard, name string) error {
	if err := fg.check(FirmwareCall{Op: OpUndefine, Name: name}); err != nil {
		return fmt.Errorf("undefine (keep state) domain %s: %w", name, err)
	}
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := v.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(keepStateUndefineFlags)); err != nil {
		return fmt.Errorf("undefine (keep state) domain %s: %w", name, err)
	}
	return nil
}

// keptDiskDeleteUndefineFlags undefines the domain of a VM deleted with
// --keep-disks: NVRAM and swtpm state are kept as keepStateUndefineFlags
// keeps them, and libvirt's snapshot and checkpoint METADATA goes with the
// domain. libvirt refuses to undefine a shut-off domain that still holds
// either without these ("cannot delete inactive domain with N snapshots").
// The flags remove metadata only: no overlay file, qcow2 internal snapshot,
// memory image or firmware bundle is touched. Never for a domain that is
// about to be defined again (undefineDomainPreservingState): that one keeps
// its snapshots.
const keptDiskDeleteUndefineFlags = keepStateUndefineFlags |
	golibvirt.DomainUndefineSnapshotsMetadata |
	golibvirt.DomainUndefineCheckpointsMetadata

func undefineDeletedDomainKeepingState(v snapshotAPI, fg FirmwareMoveGuard, name string) error {
	if err := fg.check(FirmwareCall{Op: OpUndefine, Name: name}); err != nil {
		return fmt.Errorf("undefine (keep disks) domain %s: %w", name, err)
	}
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	if err := v.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(keptDiskDeleteUndefineFlags)); err != nil {
		return fmt.Errorf("undefine (keep disks) domain %s: %w", name, err)
	}
	return nil
}

// defineDomain defines xmlConfig after the guard allows a define of the
// domain it names; policy is the console password policy (DefineDomain).
func defineDomain(v snapshotAPI, fg FirmwareMoveGuard, xmlConfig string, policy func(string) (string, error)) error {
	if err := fg.check(FirmwareCall{Op: OpDefine, Name: DomainNameFromXML(xmlConfig), UUID: UUIDFromXML(xmlConfig)}); err != nil {
		return fmt.Errorf("define domain: %w", err)
	}
	xmlConfig, err := policy(xmlConfig)
	if err != nil {
		return fmt.Errorf("define domain: %w", err)
	}
	if _, err := v.DomainDefineXML(xmlConfig); err != nil {
		return fmt.Errorf("define domain: %w", err)
	}
	return nil
}

// DomainNameFromXML is the <name> of a domain definition, "" when it has
// none.
func DomainNameFromXML(domXML string) string {
	i := strings.Index(domXML, "<name>")
	if i < 0 {
		return ""
	}
	rest := domXML[i+len("<name>"):]
	j := strings.Index(rest, "</name>")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// ── Exempt entry points (spec §5.1, I5) ──

// ResumeFirmwareMoveSource resumes the source guest of a move that failed
// before cutover with the source paused and no target domain (spec §7 M1p),
// for the M1p handler and its recovery retry. The marker must be the
// attempt's and before cutover; source_paused is refused here (the D-5
// action has ResumeFirmwareMoveSourceForOperator).
func (c *Client) ResumeFirmwareMoveSource(name, uuid, attempt string) error {
	return resumeDomain(c.virt, c.firmwareGuard(), FirmwareCall{Op: OpResume, Name: name, UUID: uuid, Attempt: attempt, Via: ViaResumeFirmwareMoveSource})
}

// ResumeFirmwareMoveSourceForOperator resumes the source guest for the D-5
// --accept-source action on a source_paused move (spec §5.y), after the
// action has discarded the target's copy. The marker must be the attempt's,
// source_paused, and parked before cutover.
func (c *Client) ResumeFirmwareMoveSourceForOperator(name, uuid, attempt string) error {
	return resumeDomain(c.virt, c.firmwareGuard(), FirmwareCall{Op: OpResume, Name: name, UUID: uuid, Attempt: attempt, Via: ViaResumeFirmwareMoveSourceOperator})
}

// ResumePartitionPaused is the partition pauser resuming a guest it paused.
// Under a marker it is allowed only while the move is in progress before
// cutover (spec §5.1), so a source guest still the live copy is not left
// paused once the partition heals; under a parked marker it is refused, and
// the move's own steps resume the source.
func (c *Client) ResumePartitionPaused(name, uuid string) error {
	return resumeDomain(c.virt, c.firmwareGuard(), FirmwareCall{Op: OpResume, Name: name, UUID: uuid, Via: ViaResumePartitionPaused})
}

// ResumeFirmwareMoveTarget resumes the held target guest: the hold must be
// the attempt's and in state resuming, written before this call (spec §6.6).
func (c *Client) ResumeFirmwareMoveTarget(name, uuid, attempt string) error {
	return resumeDomain(c.virt, c.firmwareGuard(), FirmwareCall{Op: OpResume, Name: name, UUID: uuid, Attempt: attempt, Via: ViaResumeFirmwareMoveTarget})
}

// DiscardFirmwareMoveTarget takes the held target domain away and keeps its
// state for the quarantine (spec §6.8): destroy if paused, then undefine with
// KEEP_NVRAM|KEEP_TPM. A running guest is never destroyed by a discard. No
// domain of the name is nothing to discard.
func (c *Client) DiscardFirmwareMoveTarget(name, uuid, attempt string) error {
	return discardFirmwareMoveTarget(c.virt, c.firmwareGuard(), name, uuid, attempt)
}

func discardFirmwareMoveTarget(v snapshotAPI, fg FirmwareMoveGuard, name, uuid, attempt string) error {
	call := FirmwareCall{Name: name, UUID: uuid, Attempt: attempt, Via: ViaDiscardFirmwareMoveTarget}
	for _, op := range []FirmwareOp{OpStop, OpUndefine} {
		call.Op = op
		if err := fg.check(call); err != nil {
			return fmt.Errorf("discard %s: %w", name, err)
		}
	}
	if !domainExists(v, name) {
		return nil
	}
	dom, err := lookupBound(v, name, uuid)
	if err != nil {
		return fmt.Errorf("discard %s: %w", name, err)
	}
	st, _, err := v.DomainGetState(dom, 0)
	if err != nil {
		return fmt.Errorf("discard %s: get state: %w", name, err)
	}
	switch golibvirt.DomainState(st) {
	case golibvirt.DomainShutoff:
	case golibvirt.DomainPaused:
		if err := v.DomainDestroy(dom); err != nil {
			return fmt.Errorf("discard %s: destroy: %w", name, err)
		}
	default:
		return fmt.Errorf("%w: discard %s: the domain is %s, not paused or shut off; a discard never stops a guest that may run",
			ErrFirmwareMoveInFlight, name, coarseDomainState(golibvirt.DomainState(st)))
	}
	if err := v.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(keepStateUndefineFlags)); err != nil {
		return fmt.Errorf("discard %s: undefine (keep state): %w", name, err)
	}
	return nil
}

// UndefineFirmwareMoveLeftover undefines a moved VM's source definition and
// keeps its state (spec §6.7 step 3): marker phase cleaning, domain inactive.
func (c *Client) UndefineFirmwareMoveLeftover(name, uuid, attempt string) error {
	return undefineFirmwareMoveLeftover(c.virt, c.firmwareGuard(), name, uuid, attempt)
}

func undefineFirmwareMoveLeftover(v snapshotAPI, fg FirmwareMoveGuard, name, uuid, attempt string) error {
	return undefineKeepingState(v, fg, name, uuid, attempt, ViaUndefineFirmwareMoveLeftover)
}

func undefineKeepingState(v snapshotAPI, fg FirmwareMoveGuard, name, uuid, attempt string, via FirmwareExemption) error {
	if err := fg.check(FirmwareCall{Op: OpUndefine, Name: name, UUID: uuid, Attempt: attempt, Via: via}); err != nil {
		return fmt.Errorf("undefine leftover %s: %w", name, err)
	}
	dom, err := lookupBound(v, name, uuid)
	if err != nil {
		return fmt.Errorf("undefine leftover %s: %w", name, err)
	}
	// An undefine of an ACTIVE domain leaves it running as a transient one.
	if st, _, err := v.DomainGetState(dom, 0); err != nil || golibvirt.DomainState(st) != golibvirt.DomainShutoff {
		return fmt.Errorf("undefine leftover %s: the domain is not shut off (state %d, %v)", name, st, err)
	}
	if err := v.DomainUndefineFlags(dom, golibvirt.DomainUndefineFlagsValues(keepStateUndefineFlags)); err != nil {
		return fmt.Errorf("undefine leftover %s: %w", name, err)
	}
	return nil
}

// StopOwedFirmwareLeftover stops a leftover an owed DISCARD names, under its
// leftover record (D-5 --discard-target --stop-target): destroy when force,
// else an ACPI shutdown.
func (c *Client) StopOwedFirmwareLeftover(name, uuid, attempt string, force bool) error {
	return stopForOperator(c.virt, c.firmwareGuard(), name, uuid, attempt, force, ViaStopOwedFirmwareLeftover)
}

// UndefineOwedFirmwareLeftover undefines a shut-off leftover an owed DISCARD
// names, keeping its state, under its leftover record.
func (c *Client) UndefineOwedFirmwareLeftover(name, uuid, attempt string) error {
	return undefineKeepingState(c.virt, c.firmwareGuard(), name, uuid, attempt, ViaUndefineOwedFirmwareLeftover)
}

// StopFirmwareMoveTargetForOperator stops a held target guest for an
// operator's D-5 action (--stop-target, spec §5.y): the hold is prepared,
// verified, resuming or released_unconfirmed. Destroy when force, else an
// ACPI shutdown.
func (c *Client) StopFirmwareMoveTargetForOperator(name, uuid, attempt string, force bool) error {
	return stopFirmwareMoveTargetForOperator(c.virt, c.firmwareGuard(), name, uuid, attempt, force)
}

func stopFirmwareMoveTargetForOperator(v domainOpsAPI, fg FirmwareMoveGuard, name, uuid, attempt string, force bool) error {
	return stopForOperator(v, fg, name, uuid, attempt, force, ViaStopFirmwareMoveTargetForOperator)
}

func stopForOperator(v domainOpsAPI, fg FirmwareMoveGuard, name, uuid, attempt string, force bool, via FirmwareExemption) error {
	if err := fg.check(FirmwareCall{Op: OpStop, Name: name, UUID: uuid, Attempt: attempt, Via: via}); err != nil {
		return fmt.Errorf("stop %s: %w", name, err)
	}
	dom, err := lookupBound(v, name, uuid)
	if err != nil {
		return fmt.Errorf("stop %s: %w", name, err)
	}
	if force {
		err = v.DomainDestroy(dom)
	} else {
		err = v.DomainShutdown(dom)
	}
	if err != nil {
		return fmt.Errorf("stop %s: %w", name, err)
	}
	return nil
}
