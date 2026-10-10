package grpcapi

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/storage"
)

// One iSCSI LUN, one disk.
//
// An iscsi pool is one pre-provisioned LUN, and its driver allocates nothing:
// CreateDisk hands every disk on the pool the same /dev/disk/by-path device.
// Two disks on one LUN — of one VM, or of two VMs on any hosts — are one block
// device written by two guests, which corrupts it silently. So a create takes
// each LUN it puts a disk on, or is refused naming what holds it.
//
// TAKING A LUN IS A VOTER DECISION. The LUN's allocations form a sequence;
// allocation g is decided at key (lun, <LUN key>, g) by single-decree claims
// (docs/design/recovery-claims.md §3) over the adopted voter generation's
// members, a majority deciding (lunElectorate; with no member generation a LUN
// is not allocated at all). The value names the claim, the VM (by uuid), the
// disk and the creating host.
//
// A create, on the host that will own the VM:
//
//  1. refuses a LUN twice within itself, and one another create on this host
//     has in flight (the local registry, lunClaims), or that this host's
//     replica or libvirt shows in use (lunHoldersHere) — before deciding
//     anything;
//  2. registers its LUNs in the registry BEFORE it proposes, and holds them
//     until the create returns — after its row commits;
//  3. walks the LUN's allocations from just below the LUN's checkpoint
//     (corrosion.GetLUNResolved; a hint the walker verifies against the
//     voters, lunWalkStart), DECIDING every allocation it passes. At each
//     allocation it decides with its own value: its own decided, it holds the
//     LUN; another's decided, that allocation must be proven GONE before the
//     walk goes on (lunAllocationHolder) — and the checkpoint moves past it.
//
// GONE is positive evidence, never an absence: the host that ran the create,
// asked by name (LUNHolders, its answer bound to that host), has the LUN
// neither in flight, nor in a row of its replica, nor in a libvirt domain; or
// that host's removal is recorded (its tombstone, or an adopted voter
// generation without it and no live row). A host this replica merely has no
// row for, or cannot reach, holds what it took: Unavailable, naming it.
//
// A create that fails after its own allocation was decided resolves it itself
// (lunHold.release): its allocation is gone, so the checkpoint moves past it.
// A walk therefore costs O(open allocations): the latest holder, plus any
// allocation gone since the last walker.
//
// A rebuild or a recreate MOVES the claim of the VM it replaces: its preflight
// (preflightLUNs), before the teardown, takes this host's hold — durable,
// released only on positive evidence (vm_lun_hold.go) — then, once nothing
// else can refuse, decides the LUN's next allocation for the VM with this
// host as allocator and the host the VM is re-created on (RunHost) beside it,
// passing over the VM's own earlier one. A racing create meets the new
// allocation and asks both hosts. The create then takes the LUN over without
// a claim of its own — while this host's hold stands — so nothing about the
// claim can refuse after the teardown.
//
// THE GATE. Nothing is allocated on a fixed-device pool until the release
// feature iscsi_lun_claim is open and a member voter generation is adopted
// (iscsiLUNClaimGate).

// iscsiLUNClaimFeature is the release feature that opens iSCSI allocation.
// Its string is frozen once it ships.
const iscsiLUNClaimFeature = "iscsi_lun_claim"

// lunPeerAskTimeout bounds how long a create waits for one host's answer.
const lunPeerAskTimeout = 5 * time.Second

// lunAskMaxKeys bounds one question: a VM has at most a few dozen disks.
const lunAskMaxKeys = 64

// lunMaxGenerations bounds one walk.
const lunMaxGenerations = 1 << 16

// iscsiDevicePrefix is where every iscsi pool's device lives.
const iscsiDevicePrefix = "/dev/disk/by-path/"

// SetReleaseFeatureGate wires the release-feature gate: fn(ctx, feature)
// returns nil once the feature's release token has latched and its use is
// recorded. Nil closes every release feature. The daemon wires the release
// token's RequireReleaseFeature (feat/release-token); until then nothing opens
// iscsi_lun_claim.
func (s *Server) SetReleaseFeatureGate(fn func(ctx context.Context, feature string) error) {
	s.releaseFeatureMu.Lock()
	defer s.releaseFeatureMu.Unlock()
	s.releaseFeatureGate = fn
}

// iscsiLUNClaimGate is the one place allocation on a fixed-device pool waits:
// for the release latch, and for an electorate to decide on.
func (s *Server) iscsiLUNClaimGate(ctx context.Context) error {
	s.releaseFeatureMu.Lock()
	gate := s.releaseFeatureGate
	s.releaseFeatureMu.Unlock()
	why := "the release feature is not wired on this build"
	if gate != nil {
		why = ""
		if err := gate(ctx, iscsiLUNClaimFeature); err != nil {
			why = err.Error()
		}
	}
	if why != "" {
		return status.Errorf(codes.FailedPrecondition,
			"an iSCSI LUN is allocated by a voter claim (release feature %s), which is not open yet (%s): "+
				"the cluster upgrade must finish first", iscsiLUNClaimFeature, why)
	}
	if _, err := s.lunElectorate(ctx); err != nil {
		return err
	}
	return nil
}

// lunElectorateT is who decides a LUN allocation: the adopted voter
// generation's members, a majority of them.
type lunElectorateT struct {
	gen    int64
	voters []string
	quorum int
}

// lunElectorate is the adopted member voter generation. There is no fallback:
// with none adopted — automatic genesis pending, or after a reset — a LUN is
// not allocated (FailedPrecondition), because a set two replicas derive from
// their own host lists need not intersect (re-review 2, I-2).
func (s *Server) lunElectorate(ctx context.Context) (lunElectorateT, error) {
	gen, err := corrosion.AdoptedVoterGeneration(ctx, s.db)
	if err != nil {
		return lunElectorateT{}, status.Errorf(codes.Unavailable, "read the voter generation: %v", err)
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return lunElectorateT{}, status.Errorf(codes.Unavailable, "read the voter generation: %v", err)
	}
	if !cfg.Explicit() {
		return lunElectorateT{}, status.Errorf(codes.FailedPrecondition,
			"an iSCSI LUN is allocated by a voter claim, and %s has adopted no voter generation with members "+
				"(automatic genesis is pending — see the ha.voter.genesis_pending health condition — or the voters "+
				"were reset): adopt one with `lv cluster voter init`, then retry", s.hostName)
	}
	names := cfg.Names()
	return lunElectorateT{gen: gen, voters: names, quorum: corrosion.MajorityOf(len(names))}, nil
}

// lunUse is one disk of a create that sits on a fixed device.
type lunUse struct {
	key       string // storage.FixedDevice key: the LUN
	device    string
	disk      string
	pool      string
	overwrite bool // the disk says overwrite
}

// lunClaim is one in-flight create's (or recreate's) hold on a LUN.
type lunClaim struct {
	id    uint64
	vm    string
	vmID  string
	disk  string
	token string // a recreate's hold that its own create takes over
}

// lunClaimRegistry is the LUNs this host's in-flight creates are taking. The
// zero value is ready to use.
type lunClaimRegistry struct {
	mu   sync.Mutex
	next uint64
	m    map[string]lunClaim // LUN key → the create holding it
}

// take registers every use for vm, or none of them: if another in-flight
// create holds one, it returns that LUN's key and holder. A hold registered
// under token (a recreate's, holdLUNsForRecreate) is taken over by the create
// carrying it. The returned id names this registration; release drops it
// (idempotent).
func (r *lunClaimRegistry) take(vm, vmID, token string, uses []lunUse) (id uint64, release func(), heldKey string, held lunClaim) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range uses {
		if c, ok := r.m[u.key]; ok && (token == "" || c.token != token) {
			return 0, nil, u.key, c
		}
	}
	if r.m == nil {
		r.m = map[string]lunClaim{}
	}
	r.next++
	id = r.next
	for _, u := range uses {
		r.m[u.key] = lunClaim{id: id, vm: vm, vmID: vmID, disk: u.disk, token: token}
	}
	var once sync.Once
	return id, func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			for k, c := range r.m {
				if c.id == id {
					delete(r.m, k)
				}
			}
		})
	}, "", lunClaim{}
}

// holding returns the in-flight claims on keys, except registration own.
func (r *lunClaimRegistry) holding(keys map[string]bool, own uint64) map[string]lunClaim {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]lunClaim{}
	for k := range keys {
		if c, ok := r.m[k]; ok && c.id != own {
			out[k] = c
		}
	}
	return out
}

// resolveVolumeFault, when set (tests only), is consulted first by every
// resolution of a disk's storage: a non-nil error is that resolution's
// error, as a transient read failure would be.
var resolveVolumeFault func(stackName, volumeName string) error

// lunHandoffKey carries a recreate's hold token into its create.
type lunHandoffKey struct{}

func lunHandoffFrom(ctx context.Context) string {
	t, _ := ctx.Value(lunHandoffKey{}).(string)
	return t
}

// fixedDeviceUses resolves spec's disks, for a create on this host, to the
// fixed devices (iscsi LUNs) they take, refusing a create that puts two of
// its own disks on one — and returns every disk's resolved storage (by disk
// name), which the create then uses as it is: the claim and the disk are one
// resolution, so they cannot disagree (re-review 4, I-2). A disk whose
// storage does not resolve refuses the create now, as the create's disk loop
// would: never counted as no LUN, which let a transient read error, or a pool
// row arriving between two resolutions, attach a LUN nothing claimed.
func (s *Server) fixedDeviceUses(ctx context.Context, spec *pb.VMSpec) ([]lunUse, map[string]storage.Config, error) {
	cfgs := map[string]storage.Config{}
	var uses []lunUse
	seen := map[string]lunUse{}
	for _, d := range spec.Disks {
		if d.Storage == "" {
			continue
		}
		name := diskNameOrRoot(d.Name)
		cfg, err := s.resolveVolume(ctx, spec.StackName, d.Storage)
		if err != nil {
			return nil, nil, status.Errorf(codes.FailedPrecondition, "storage %q: %v", d.Storage, err)
		}
		cfgs[name] = cfg
		key, dev, ok := storage.FixedDevice(cfg)
		if !ok {
			continue
		}
		u := lunUse{key: key, device: dev, disk: name, pool: d.Storage, overwrite: d.Overwrite}
		if err := addLUNUse(spec.Name, seen, &uses, u); err != nil {
			return nil, nil, err
		}
	}
	return uses, cfgs, nil
}

func diskNameOrRoot(name string) string {
	if name == "" {
		return "root"
	}
	return name
}

// addLUNUse appends u, refusing a second disk of the VM on u's LUN.
func addLUNUse(vm string, seen map[string]lunUse, uses *[]lunUse, u lunUse) error {
	if first, dup := seen[u.key]; dup {
		return status.Errorf(codes.FailedPrecondition,
			"disks %q (storage %q) and %q (storage %q) of VM %q are both iSCSI LUN %s: an iscsi pool is "+
				"one LUN and holds one disk, and two disks on one LUN corrupt each other — give each disk "+
				"a pool of its own LUN (lv pool create ... --driver iscsi --option lun=N)",
			first.disk, first.pool, u.disk, u.pool, vm, u.device)
	}
	seen[u.key] = u
	*uses = append(*uses, u)
	return nil
}

// lookupVolumeConfig is the storage config a disk's storage name has on this
// host — a volume of the stack, or one of this host's pools — without the
// checks a write there needs: found false when there is none by that name,
// an error only when what would say so cannot be read.
func (s *Server) lookupVolumeConfig(ctx context.Context, stackName, volumeName string) (storage.Config, bool, error) {
	if f := resolveVolumeFault; f != nil {
		if err := f(stackName, volumeName); err != nil {
			return storage.Config{}, false, err
		}
	}
	if stackName != "" {
		f, err := s.storedStackFile(ctx, stackName)
		if err != nil {
			return storage.Config{}, false, err
		}
		if f != nil {
			if vol, ok := f.Volumes[volumeName]; ok {
				return storage.Config{Driver: vol.Driver, Source: vol.Source, Target: vol.Target, Options: vol.Options}, true, nil
			}
		}
	}
	if ref, ok := s.lookupStoragePool(volumeName); ok {
		return storage.Config{Driver: ref.Driver, Source: ref.Source, Target: ref.Target, Options: ref.Options}, true, nil
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, s.hostName, volumeName)
	if err != nil {
		return storage.Config{}, false, err
	}
	if !ok {
		return storage.Config{}, false, nil
	}
	return storage.Config{Driver: rec.Driver, Source: rec.Source, Target: rec.Target, Options: rec.Options}, true, nil
}

// recreateFixedDeviceUses is fixedDeviceUses for a rebuild or recreate of
// cur judged on this host — the host running it, which need not be the host
// the VM is re-created on, and pools are per host. A storage this host
// cannot read refuses (re-review 4, I-2): it is never counted as no LUN. A
// storage with no volume or pool of that name here is skipped — its disk is
// created where the VM lands, which judges it — unless cur's own disk of
// that name is an iSCSI LUN: the claim on that LUN must move from here, and
// cannot without knowing it.
func (s *Server) recreateFixedDeviceUses(ctx context.Context, spec *pb.VMSpec, cur *corrosion.VMRecord) ([]lunUse, error) {
	var curLUNs map[string]string // disk name → device
	var uses []lunUse
	seen := map[string]lunUse{}
	for _, d := range spec.Disks {
		if d.Storage == "" {
			continue
		}
		name := diskNameOrRoot(d.Name)
		cfg, found, err := s.lookupVolumeConfig(ctx, spec.StackName, d.Storage)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable,
				"storage %q of disk %q of VM %q cannot be read on %s (%v), so whether it is an iSCSI LUN cannot "+
					"be judged — retry", d.Storage, name, spec.Name, s.hostName, err)
		}
		if !found {
			if curLUNs == nil && cur != nil {
				curLUNs = map[string]string{}
				disks, err := corrosion.VMIncarnationDisks(ctx, s.db, cur.Name, cur.CreatedAt)
				if err != nil {
					return nil, status.Errorf(codes.Unavailable, "read the disks of VM %q: %v", cur.Name, err)
				}
				for _, cd := range disks {
					if _, ok := storage.FixedDeviceKeyOfPath(cd.Path); ok {
						curLUNs[cd.DiskName] = cd.Path
					}
				}
			}
			if dev, ok := curLUNs[name]; ok {
				return nil, status.Errorf(codes.FailedPrecondition,
					"disk %q of VM %q is iSCSI LUN %s, and %s has no storage %q to judge its claim by — run the "+
						"update or rebuild from a host with that pool", name, spec.Name, dev, s.hostName, d.Storage)
			}
			continue
		}
		key, dev, ok := storage.FixedDevice(cfg)
		if !ok {
			continue
		}
		u := lunUse{key: key, device: dev, disk: name, pool: d.Storage, overwrite: d.Overwrite}
		if err := addLUNUse(spec.Name, seen, &uses, u); err != nil {
			return nil, err
		}
	}
	return uses, nil
}

// hasFixedDeviceDisk reports whether spec, re-creating cur, puts a disk on a
// fixed device (an iscsi LUN), judged as recreateFixedDeviceUses judges it:
// an error is a refusal, never "no".
func (s *Server) hasFixedDeviceDisk(ctx context.Context, spec *pb.VMSpec, cur *corrosion.VMRecord) (bool, error) {
	uses, err := s.recreateFixedDeviceUses(ctx, spec, cur)
	return len(uses) > 0, err
}

// lunHold is a create's hold on its LUNs.
type lunHold struct {
	s    *Server
	drop func()
	// own is the allocation generation this create decided, per LUN.
	own map[string]int64
	// keep names the LUNs the create takes over from the VM it replaces, as
	// they are; claimed, those its recreate preflight claimed for it.
	keep map[string]bool
	// committed is set once the create's row is written: from then on its
	// allocations are held by the row.
	committed bool
	// cfgs is every disk's storage as the claim resolved it, by disk name:
	// the create uses it as it is.
	cfgs map[string]storage.Config
}

// release drops the hold once the create has returned. A create that did not
// commit, and left no domain, resolves the allocations it decided: they are
// gone, so the LUN's checkpoint moves past them and no later walker has to
// prove it.
func (h *lunHold) release(ctx context.Context, vm string) {
	if h == nil {
		return
	}
	defer h.drop()
	if h.committed || h.s == nil || len(h.own) == 0 {
		return
	}
	if h.s.virt != nil && h.s.virt.DomainExists(vm) {
		return // a domain outlived the create: it holds the LUN
	}
	for k, g := range h.own {
		if err := corrosion.AdvanceLUNResolved(context.WithoutCancel(ctx), h.s.db, k, g+1, h.s.hostName); err != nil {
			slog.Warn("iSCSI LUN: could not record a failed create's allocation as resolved; a later create proves it",
				"lun", k, "generation", g, "error", err)
		}
	}
}

// claimLUNs takes, for the VM spec creates on this host, every iscsi LUN its
// disks would use — or refuses the create, naming what holds one. The caller
// must call hold.release once the create has returned, after setting
// hold.committed when its row was written.
func (s *Server) claimLUNs(ctx context.Context, spec *pb.VMSpec) (*lunHold, error) {
	uses, cfgs, err := s.fixedDeviceUses(ctx, spec)
	if err != nil {
		return nil, err
	}
	if len(uses) == 0 {
		return &lunHold{drop: func() {}, cfgs: cfgs}, nil
	}
	rep, hasRep := replacedVMFor(ctx, spec.Name)
	// What the recreate's preflight already judged — the replaced VM's own
	// disk, or a LUN it claimed for it — is taken over without any claim:
	// nothing about the claim may refuse after the teardown.
	taken := func(u lunUse) bool {
		return hasRep && rep.claimed[u.key] == u.disk
	}
	needClaim := false
	for _, u := range uses {
		if !taken(u) {
			needClaim = true
		}
	}
	if needClaim {
		if err := s.iscsiLUNClaimGate(ctx); err != nil {
			return nil, err
		}
	}
	byKey := make(map[string]lunUse, len(uses))
	keys := make(map[string]bool, len(uses))
	for _, u := range uses {
		byKey[u.key] = u
		keys[u.key] = true
	}

	id, drop, heldKey, held := s.lunClaims.take(spec.Name, spec.Uuid, lunHandoffFrom(ctx), uses)
	if drop == nil {
		return nil, lunHeldError(spec.Name, byKey[heldKey], &pb.LUNHolder{
			Lun: heldKey, VmName: held.vm, DiskName: held.disk, HostName: s.hostName, InFlight: true, VmId: held.vmID,
		})
	}
	hold := &lunHold{s: s, drop: drop, own: map[string]int64{}, keep: map[string]bool{}, cfgs: cfgs}
	ok := false
	defer func() {
		if !ok {
			hold.release(ctx, spec.Name)
		}
	}()

	// Anything this host already knows holds a LUN refuses before a
	// generation is spent on it. The VM's own name is not a holder here: an
	// orphan domain of that name is cleaned up by the create.
	here, err := s.lunHoldersHere(ctx, keys, rep, hasRep, id, lunHandoffFrom(ctx), spec.Name)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cannot confirm iSCSI LUN %s is free: read disks: %v",
			uses[0].device, err)
	}
	if len(here) > 0 {
		return nil, lunHeldError(spec.Name, byKey[here[0].Lun], here[0])
	}
	// A LUN taken over from a moved claim is taken only while the host that
	// moved it still holds it — asked after this create's own registration
	// above, so a racer that found both hosts empty cannot meet this create
	// going on (vm_lun_hold.go).
	var takenKeys []string
	for _, u := range uses {
		if taken(u) {
			takenKeys = append(takenKeys, u.key)
		}
	}
	if len(takenKeys) > 0 {
		// Every takeover is verified: one that names no hold to verify is
		// refused, never let through (re-review 4, m-3).
		if rep.holdToken == "" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"VM %q: the re-create takes over iSCSI LUNs its moved claim names, but names no hold to verify "+
					"them by; nothing was started", spec.Name)
		}
		if err := s.verifyLUNHold(ctx, spec.Name, rep, takenKeys); err != nil {
			return nil, err
		}
	}
	for _, u := range uses {
		if taken(u) {
			hold.keep[u.key] = rep.luns[u.key] == u.disk
			continue
		}
		mine := corrosion.LUNAllocation{LUN: u.key, ClaimID: randid.New(), VMID: spec.Uuid, VMName: spec.Name,
			Disk: u.disk, Host: s.hostName}
		g, prev, err := s.allocateLUN(ctx, spec.Name, u, mine, rep, hasRep, id, lunHandoffFrom(ctx), true)
		if err != nil {
			return nil, err
		}
		hold.own[u.key] = g
		// The allocation just before this one is this VM's own kept LUN —
		// a re-create of it moved the claim, keeping the disk, and was torn
		// down before its create committed. The LUN is the VM's own disk:
		// it is taken over as it is, never refused for holding data, and
		// nothing is written over it unless the disk says overwrite
		// (re-review 4, concern 3).
		if keptForVM(prev, spec.Name, u) {
			hold.keep[u.key] = true
			slog.Info("iSCSI LUN: a create of the VM a re-create kept this LUN for takes it over as it is",
				"vm", spec.Name, "disk", u.disk, "lun", u.device, "after_allocation", prev.Generation)
		}
	}
	ok = true
	return hold, nil
}

// keptForVM reports whether prev, the allocation decided just before a
// create's own, is a moved allocation that kept u's LUN as the disk of the
// VM being created — same name, same disk — and u does not ask to write
// over it.
func keptForVM(prev *corrosion.LUNAllocation, vm string, u lunUse) bool {
	return prev != nil && prev.Kept && prev.VMName == vm && prev.Disk == u.disk && !u.overwrite
}

// verifyLUNHold refuses the create of vm unless the host that moved its
// claim (rep.holdHost) still holds rep.holdToken on every key.
func (s *Server) verifyLUNHold(ctx context.Context, vm string, rep replacedVM, keys []string) error {
	var present bool
	var err error
	if rep.holdHost == "" || rep.holdHost == s.hostName {
		present, err = s.lunHoldPresent(rep.holdToken, keys)
	} else {
		var resp *pb.LUNHoldersResponse
		resp, err = s.askLUNHoldersResp(ctx, rep.holdHost, &pb.LUNHoldersRequest{Luns: keys, HoldToken: rep.holdToken})
		present = err == nil && resp.HoldPresent
	}
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"VM %q: cannot confirm with %s that it still holds the iSCSI LUN it moved for this re-create (%v); "+
				"nothing was started", vm, rep.holdHost, err)
	}
	if !present {
		return status.Errorf(codes.Aborted,
			"VM %q: %s no longer holds the iSCSI LUN it moved for this re-create — the re-create was given up, "+
				"and the LUN may since be another VM's; nothing was started. Create the VM again under the same "+
				"name on the same pools: unless another VM has taken the LUN since, it takes its own disk over as "+
				"it is, with no overwrite", vm, rep.holdHost)
	}
	return nil
}

// lunWalkStart is where a walk of lun's allocations starts: its checkpoint,
// once verified. The checkpoint is a replicated row a peer could write, so it
// is trusted only when some proposer has proposed a value at the allocation
// just below it — a value is only ever proposed at g once every allocation
// below g was proven gone (the walk's own rule) — and otherwise the walk
// starts at 0.
func (s *Server) lunWalkStart(ctx context.Context, el lunElectorateT, lun string) (int64, error) {
	c, err := corrosion.GetLUNResolved(ctx, s.db, lun)
	if err != nil || c <= 0 {
		return 0, nil
	}
	_, found, err := s.learnLUN(ctx, el, lun, c-1)
	if err != nil {
		return 0, err
	}
	if !found {
		slog.Warn("iSCSI LUN: the LUN's checkpoint names an allocation no voter has a value below; walking from 0",
			"lun", lun, "checkpoint", c)
		return 0, nil
	}
	// The value at c-1 proves only that everything below c-1 was gone when it
	// was proposed — not c-1 itself — so the walk decides c-1 too and meets
	// its holder (re-review 2, m-2).
	return c - 1, nil
}

// lunDecisionError is a decision the voters did not reach, with their reasons.
func lunDecisionError(u lunUse, vm string, err error) error {
	var nm *claims.NoMajorityError
	if errors.As(err, &nm) {
		return status.Errorf(codes.Unavailable,
			"cannot take iSCSI LUN %s for VM %q: the voters did not decide it (%v); nothing was allocated",
			u.device, vm, err)
	}
	return status.Errorf(codes.Unavailable, "cannot take iSCSI LUN %s for VM %q: %v", u.device, vm, err)
}

// allocateLUN walks u's LUN's allocations from the checkpoint until one is
// decided for mine, and returns its generation and the allocation decided
// just before it, when the walk met it. An allocation decided for another
// create is gone, or refuses.
//
// advanceOwn moves the checkpoint to mine once it is decided after passing
// the replaced VM's own allocation. A re-create's preflight passes false: its
// moved allocation moves the checkpoint only once the re-created VM's create
// commits (re-review 4, I-1), so a re-create refused before its create —
// however often — never walks the checkpoint past the allocation of the VM
// that still runs.
func (s *Server) allocateLUN(ctx context.Context, vm string, u lunUse, mine corrosion.LUNAllocation, rep replacedVM, hasRep bool, reg uint64, ownHold string, advanceOwn bool) (int64, *corrosion.LUNAllocation, error) {
	el, err := s.lunElectorate(ctx)
	if err != nil {
		return 0, nil, err
	}
	start, err := s.lunWalkStart(ctx, el, u.key)
	if err != nil {
		return 0, nil, lunDecisionError(u, vm, err)
	}
	// An allocation of the VM a rebuild or recreate replaces (its name and
	// this disk) is passed over once nothing but that VM holds the LUN — the
	// claim MOVES to the allocation this walk decides — and the checkpoint
	// moves past it only once the new allocation is decided (re-review 2,
	// C-1). That deferral is defence in depth, not what keeps the old
	// allocation in view: every walk starts one below the checkpoint
	// (lunWalkStart), so an advance made at once would still leave a walker
	// deciding the old allocation and meeting its holder (re-review 3, m-3).
	passedOwn := false
	var prev *corrosion.LUNAllocation
	for g := start; g < start+lunMaxGenerations; g++ {
		mine.Generation = g
		out, err := s.decideLUNWith(ctx, el, mine)
		if err != nil {
			return 0, nil, lunDecisionError(u, vm, err)
		}
		a := out.Value.LUN
		if a == nil {
			return 0, nil, status.Errorf(codes.Internal, "iSCSI LUN %s: allocation %d decided a value that is not a LUN allocation", u.device, g)
		}
		if a.ClaimID == mine.ClaimID {
			if passedOwn && advanceOwn {
				if err := corrosion.AdvanceLUNResolved(ctx, s.db, u.key, g, s.hostName); err != nil {
					slog.Warn("iSCSI LUN: record checkpoint", "lun", u.key, "generation", g, "error", err)
				}
			}
			return g, prev, nil
		}
		prev = a
		holder, err := s.lunAllocationHolder(ctx, el, *a, rep, hasRep, reg, ownHold)
		if err != nil {
			return 0, nil, err
		}
		if holder != nil {
			return 0, nil, lunHeldError(vm, u, holder)
		}
		if hasRep && a.VMName == rep.name && a.Disk == u.disk {
			passedOwn = true
			continue
		}
		if passedOwn {
			continue // the checkpoint waits for this walk's own decision
		}
		if err := corrosion.AdvanceLUNResolved(ctx, s.db, u.key, g+1, s.hostName); err != nil {
			slog.Warn("iSCSI LUN: record checkpoint", "lun", u.key, "generation", g+1, "error", err)
		}
	}
	return 0, nil, status.Errorf(codes.ResourceExhausted, "iSCSI LUN %s: more than %d open allocations", u.device, lunMaxGenerations)
}

// lunSpec is the proposer spec of one allocation under el.
func lunSpec(el lunElectorateT, key corrosion.ClaimKey, propose *corrosion.ClaimValue) claims.Spec {
	sp := claims.Spec{
		Key: key, Generation: el.gen, Voters: el.voters, PrepareQuorum: el.quorum,
		Electorate: func(corrosion.ClaimValue) ([]string, int) { return el.voters, el.quorum },
		StartRound: 1,
	}
	if propose != nil {
		v := *propose
		sp.Propose = func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return v, nil }
	}
	return sp
}

// decideLUN decides mine's allocation under the current electorate.
func (s *Server) decideLUN(ctx context.Context, mine corrosion.LUNAllocation) (claims.Outcome, error) {
	el, err := s.lunElectorate(ctx)
	if err != nil {
		return claims.Outcome{}, err
	}
	return s.decideLUNWith(ctx, el, mine)
}

// decideLUNWith decides mine's allocation under el, proposing mine.
func (s *Server) decideLUNWith(ctx context.Context, el lunElectorateT, mine corrosion.LUNAllocation) (claims.Outcome, error) {
	v := corrosion.ClaimValue{LUN: &mine}
	return s.claimProposer().Decide(ctx, lunSpec(el, corrosion.LUNClaimKey(mine.LUN, mine.Generation), &v))
}

// learnLUN learns, without deciding, the value proposed at allocation g of
// lun, if a quorum's promises report one.
func (s *Server) learnLUN(ctx context.Context, el lunElectorateT, lun string, g int64) (*corrosion.LUNAllocation, bool, error) {
	v, found, err := s.claimProposer().Learn(ctx, lunSpec(el, corrosion.LUNClaimKey(lun, g), nil))
	if err != nil || !found || v == nil || v.LUN == nil {
		return nil, false, err
	}
	return v.LUN, true, nil
}

// lunAllocationHolder returns what still holds allocation a, or nil once it
// is PROVEN gone (see the file comment): nothing here — registry, replica,
// libvirt — holds the LUN, and the host that ran a's create either answers,
// by name, that nothing there does, or is recorded removed. reg and ownHold
// are the asking create's own registration and hold, which are not holders.
//
// A MOVED allocation (a rebuild's or recreate's, vm_lun_hold.go) names two
// hosts: Host, which holds the claim, and RunHost, which runs the re-created
// VM. It is gone only when BOTH show nothing (or are recorded removed), and
// Host is asked first — the order the hold's release relies on.
func (s *Server) lunAllocationHolder(ctx context.Context, el lunElectorateT, a corrosion.LUNAllocation, rep replacedVM, hasRep bool, reg uint64, ownHold string) (*pb.LUNHolder, error) {
	keys := map[string]bool{a.LUN: true}
	here, err := s.lunHoldersHere(ctx, keys, rep, hasRep, reg, ownHold, "")
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read disks: %v", err)
	}
	if len(here) > 0 {
		return here[0], nil
	}
	hosts := []string{a.Host}
	if a.RunHost != "" && a.RunHost != a.Host {
		hosts = append(hosts, a.RunHost)
	}
	for _, host := range hosts {
		if host == s.hostName {
			continue // this host's registry, holds, replica and domains were just read
		}
		holder, err := s.lunAllocationHolderOn(ctx, el, a, host, rep, hasRep)
		if err != nil || holder != nil {
			return holder, err
		}
	}
	return nil, nil
}

// lunAllocationHolderOn asks host what holds allocation a: its holder, nil
// once host shows nothing or its removal is recorded, or Unavailable.
func (s *Server) lunAllocationHolderOn(ctx context.Context, el lunElectorateT, a corrosion.LUNAllocation, host string, rep replacedVM, hasRep bool) (*pb.LUNHolder, error) {
	req := &pb.LUNHoldersRequest{Luns: []string{a.LUN}}
	if hasRep {
		req.ReplacedName, req.ReplacedCreatedAt = rep.name, rep.snap.CreatedAt
	}
	there, askErr := s.askLUNHolders(ctx, host, req)
	if askErr == nil {
		if len(there) > 0 {
			return there[0], nil
		}
		return nil, nil
	}
	// No answer. Gone only on a record of the host's removal.
	if removed, err := corrosion.HostRemoved(ctx, s.db, host); err == nil && removed {
		slog.Info("iSCSI LUN: a host of an earlier allocation was removed from the cluster",
			"lun", a.LUN, "generation", a.Generation, "host", host, "vm", a.VMName)
		return nil, nil
	}
	if s.votedOut(ctx, el, host) {
		slog.Info("iSCSI LUN: a host of an earlier allocation was removed from the voters, and has no "+
			"row here", "lun", a.LUN, "host", host)
		return nil, nil
	}
	return nil, status.Errorf(codes.Unavailable,
		"iSCSI LUN %s was taken by a create of VM %q on %s, which cannot be asked whether that create is gone (%v), "+
			"and whose removal from the cluster is not recorded here; nothing was allocated — retry once %s answers, "+
			"or once it is removed (lv host rm)", a.LUN, a.VMName, host, askErr, host)
}

// votedOut reports whether the adopted voter generation records host's
// removal: host was a member of an earlier generation, is not one of the
// adopted one, and this replica holds no live row for it. A host that was
// never a voter is not evidenced removed by any generation.
func (s *Server) votedOut(ctx context.Context, el lunElectorateT, host string) bool {
	if el.gen <= 1 || slicesContains(el.voters, host) {
		return false
	}
	if h, err := corrosion.GetHost(ctx, s.db, host); err != nil || h != nil {
		return false
	}
	for g := el.gen - 1; g >= 1; g-- {
		cfg, err := corrosion.GetVoterConfig(ctx, s.db, g)
		if err != nil || cfg == nil {
			continue
		}
		if _, ok := cfg.Member(host); ok {
			return true
		}
	}
	return false
}

func slicesContains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// lunHeldError is the refusal of a disk whose LUN h holds.
func lunHeldError(vm string, u lunUse, h *pb.LUNHolder) error {
	if h.InFlight {
		return status.Errorf(codes.Aborted,
			"disk %q (storage %q) of VM %q is iSCSI LUN %s, which a create of VM %q (disk %q) on %s is taking "+
				"right now: an iscsi pool is one LUN and holds one disk — retry once that create has finished, "+
				"or give this disk a pool of its own LUN (--option lun=N)",
			u.disk, u.pool, vm, u.device, h.VmName, h.DiskName, h.HostName)
	}
	return status.Errorf(codes.FailedPrecondition,
		"disk %q (storage %q) of VM %q is iSCSI LUN %s, which is already %s of VM %q (host %s): an iscsi "+
			"pool is one LUN and holds one disk, and two VMs writing one LUN corrupt it — give this disk a pool "+
			"of its own LUN (lv pool create ... --driver iscsi --option lun=N)",
		u.disk, u.pool, vm, u.device, lunUseLabel(h), h.VmName, h.HostName)
}

// lunUseLabel says how a holder uses the LUN.
func lunUseLabel(h *pb.LUNHolder) string {
	switch {
	case h.Backing:
		return fmt.Sprintf("the base disk %q reads from (a linked clone)", h.DiskName)
	case h.DiskName == "":
		return "a disk"
	}
	return fmt.Sprintf("disk %q", h.DiskName)
}

// lunHoldersHere is what this host knows holds any of keys: its in-flight
// creates (except registration own); its moved holds (vm_lun_hold.go; except
// the hold ownHold); every live VM's use of the LUN in its replica — as a
// disk, or as a linked clone's base — except the replaced incarnation's rows
// (name AND created_at); and every libvirt domain on this host whose disks use
// the LUN — a guest running with no row still holds it — except the replaced
// VM's domain and selfDomain (the VM this host is creating, whose orphan the
// create cleans up). Sorted, so a refusal names the same holder each time.
func (s *Server) lunHoldersHere(ctx context.Context, keys map[string]bool, rep replacedVM, hasRep bool, own uint64, ownHold, selfDomain string) ([]*pb.LUNHolder, error) {
	var out []*pb.LUNHolder
	for k, c := range s.lunClaims.holding(keys, own) {
		out = append(out, &pb.LUNHolder{Lun: k, VmName: c.vm, DiskName: c.disk, HostName: s.hostName, InFlight: true, VmId: c.vmID})
	}
	holds, err := s.lunHoldHolders(keys, ownHold)
	if err != nil {
		return nil, err
	}
	for _, h := range holds {
		// A hold whose re-create is still running here is in the registry
		// too: name it once.
		dup := false
		for _, o := range out {
			if o.InFlight && o.Lun == h.Lun && o.VmName == h.VmName {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, h)
		}
	}
	uses, err := corrosion.LiveVMDiskUsesWithPathPrefix(ctx, s.db, iscsiDevicePrefix)
	if err != nil {
		return nil, err
	}
	for _, d := range uses {
		if hasRep && d.VMName == rep.name && d.VMCreatedAt == rep.snap.CreatedAt {
			continue
		}
		k, ok := storage.FixedDeviceKeyOfPath(d.Path)
		if !ok || !keys[k] {
			continue
		}
		out = append(out, &pb.LUNHolder{Lun: k, VmName: d.VMName, DiskName: d.DiskName, HostName: d.HostName,
			Backing: d.Via == "backing", VmCreatedAt: d.VMCreatedAt})
	}
	if s.virt != nil {
		names, err := s.virt.ListDomains()
		if err != nil {
			return nil, fmt.Errorf("list libvirt domains: %w", err)
		}
		for _, dom := range names {
			if dom == selfDomain || (hasRep && dom == rep.name) {
				continue
			}
			x, err := s.virt.DumpXML(dom)
			if err != nil {
				// Only libvirt saying the domain does not exist — undefined
				// since it was listed — lets it hold nothing. Any other error
				// (a dropped connection makes every lookup fail too) fails the
				// answer: a guest with no row must never read as nothing
				// (re-review 3, m-2).
				if lv.IsNoDomain(err) {
					continue
				}
				return nil, fmt.Errorf("read domain %s: %w", dom, err)
			}
			for _, src := range domainDiskSources(x) {
				if k, ok := storage.FixedDeviceKeyOfPath(src.path); ok && keys[k] {
					out = append(out, &pb.LUNHolder{Lun: k, VmName: dom, DiskName: src.target, HostName: s.hostName})
				}
			}
		}
	}
	sortLUNHolders(out)
	return out, nil
}

// domainDiskSource is one disk of a domain: its source and target device.
type domainDiskSource struct{ path, target string }

// domainDiskSources reads a domain's disk sources — a file, or a block device
// as an iscsi LUN is attached — and their backing chains.
func domainDiskSources(domXML string) []domainDiskSource {
	type source struct {
		File string `xml:"file,attr"`
		Dev  string `xml:"dev,attr"`
	}
	type backing struct {
		Source  source   `xml:"source"`
		Backing *backing `xml:"backingStore"`
	}
	var dom struct {
		Devices struct {
			Disks []struct {
				Source  source   `xml:"source"`
				Backing *backing `xml:"backingStore"`
				Target  struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		return nil
	}
	var out []domainDiskSource
	add := func(src source, target string) {
		for _, p := range []string{src.File, src.Dev} {
			if p != "" {
				out = append(out, domainDiskSource{path: p, target: target})
			}
		}
	}
	for _, d := range dom.Devices.Disks {
		add(d.Source, d.Target.Dev)
		for b := d.Backing; b != nil; b = b.Backing {
			add(b.Source, d.Target.Dev)
		}
	}
	return out
}

func sortLUNHolders(hs []*pb.LUNHolder) {
	sort.Slice(hs, func(i, j int) bool {
		a, b := hs[i], hs[j]
		if a.InFlight != b.InFlight {
			return !a.InFlight // a committed holder names the conflict first
		}
		if a.VmName != b.VmName {
			return a.VmName < b.VmName
		}
		if a.DiskName != b.DiskName {
			return a.DiskName < b.DiskName
		}
		return a.Lun < b.Lun
	})
}

// askLUNHolders asks one host, within lunPeerAskTimeout. The answer counts
// only from that host: it names itself (answered_by), and where the
// connection shows the answering certificate, its CN is the host. An answer
// never adds a LUN that was not asked about.
func (s *Server) askLUNHolders(ctx context.Context, host string, req *pb.LUNHoldersRequest) ([]*pb.LUNHolder, error) {
	resp, err := s.askLUNHoldersResp(ctx, host, req)
	if err != nil {
		return nil, err
	}
	return resp.Holders, nil
}

// askLUNHoldersResp is askLUNHolders' whole answer, its holders limited to
// the LUNs asked.
func (s *Server) askLUNHoldersResp(ctx context.Context, host string, req *pb.LUNHoldersRequest) (*pb.LUNHoldersResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, lunPeerAskTimeout)
	defer cancel()
	c, done, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, err
	}
	defer done()
	var p peer.Peer
	resp, err := c.LUNHolders(ctx, req, grpc.Peer(&p))
	if err != nil {
		return nil, err
	}
	if by := resp.GetAnsweredBy(); by != host {
		return nil, fmt.Errorf("asked %s, answered by %q", host, by)
	}
	if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
		if cn := ti.State.PeerCertificates[0].Subject.CommonName; cn != host {
			return nil, fmt.Errorf("asked %s, answered by a certificate for %q", host, cn)
		}
	}
	asked := make(map[string]bool, len(req.Luns))
	for _, k := range req.Luns {
		asked[k] = true
	}
	var out []*pb.LUNHolder
	for _, h := range resp.GetHolders() {
		if h != nil && asked[h.Lun] {
			out = append(out, h)
		}
	}
	return &pb.LUNHoldersResponse{Holders: out, AnsweredBy: resp.GetAnsweredBy(), HoldPresent: resp.GetHoldPresent()}, nil
}

// LUNHolders answers, from this host's in-flight creates, its replica and its
// libvirt domains, which VMs hold any of the asked LUNs, naming itself.
// Peer-only. Only the replaced incarnation the request names — by name and
// created_at — is exempt.
func (s *Server) LUNHolders(ctx context.Context, req *pb.LUNHoldersRequest) (*pb.LUNHoldersResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if len(req.Luns) > lunAskMaxKeys {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d LUNs per question", lunAskMaxKeys)
	}
	keys := make(map[string]bool, len(req.Luns))
	for _, k := range req.Luns {
		keys[k] = true
	}
	var rep replacedVM
	hasRep := req.ReplacedName != "" && req.ReplacedCreatedAt != ""
	if hasRep {
		rep = replacedVM{name: req.ReplacedName, snap: corrosion.VMDeleteSnapshot{CreatedAt: req.ReplacedCreatedAt}}
	}
	holders, err := s.lunHoldersHere(ctx, keys, rep, hasRep, 0, "", "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read disks: %v", err)
	}
	resp := &pb.LUNHoldersResponse{Holders: holders, AnsweredBy: s.hostName}
	if req.HoldToken != "" {
		if resp.HoldPresent, err = s.lunHoldPresent(req.HoldToken, req.Luns); err != nil {
			return nil, status.Errorf(codes.Internal, "read the holds: %v", err)
		}
	}
	return resp, nil
}
