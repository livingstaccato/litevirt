package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/storage"
)

// One iSCSI LUN, one disk.
//
// An iscsi pool is one pre-provisioned LUN, and its driver allocates nothing:
// CreateDisk hands every disk on the pool the same /dev/disk/by-path device.
// Two disks on one LUN — of one VM, or of two VMs on any hosts — are one block
// device written by two guests, which corrupts it silently. So a create takes
// each LUN it puts a disk on, or is refused naming the VM that holds it.
//
// TAKING A LUN IS A VOTER-MAJORITY DECISION. The LUN's allocations form a
// sequence; allocation g is decided by the recovery-claim voters at key
// (lun, <LUN key>, g) (docs/design/recovery-claims.md §3 — single-decree
// Paxos over the adopted voter generation). The value names the claim, the
// VM (by uuid, one incarnation), the disk and the creating host. A create, on
// the host that will own the VM:
//
//  1. refuses a LUN twice within itself, and one another create on this host
//     has in flight (the local registry, lunClaims);
//  2. registers its LUNs in that registry, BEFORE it proposes anything, and
//     holds them until the create returns — after its disk rows commit;
//  3. walks the LUN's allocations from 0, deciding each one with its own
//     value as the proposal. Where the decided value is its own, it holds the
//     LUN. Where it is another create's, that allocation must be proven gone
//     before the walk goes on to the next: no live disk row here uses the LUN,
//     and the host that ran that create — asked over LUNHolders — has it
//     neither in flight nor in its replica. Anything else refuses: Aborted
//     naming the VM while its create is in flight, FailedPrecondition naming
//     the VM that holds it, Unavailable when that host cannot be asked;
//  4. refuses a LUN its replica shows any other live VM using, as its disk or
//     as a linked clone's base (backing) — what a LUN taken before claims
//     existed looks like.
//
// Two concurrent creates cannot both hold a LUN: at any allocation only one
// value is ever chosen, and a create that learns another's value goes on
// only past an allocation proven gone — the creating host answers "in
// flight" from step 2 until the rows commit, and from its replica after. A
// host cut off from a majority of the voters decides nothing, so it allocates
// no LUN at all (Unavailable). A host that cannot be asked holds what it took.
//
// A rebuild or a recreate re-creates a VM onto the LUN its previous
// incarnation held. That incarnation is matched by its uuid and disk name in a
// decided value, or by its name and created_at in a disk row — the replaced
// identity the teardown hands the create (vm_recreate_replaces.go), never a
// name alone — and the new incarnation takes the LUN over as it is: nothing is
// written to it (vm_lun_image.go).
//
// THE GATE. Nothing is allocated on a fixed-device pool until the release
// feature iscsi_lun_claim is open (iscsiLUNClaimGate): a voter on an older
// build does not know a LUN key, and an older host allocates without asking.
// Refusing is safer than the old silent sharing.

// iscsiLUNClaimFeature is the release feature that opens iSCSI allocation.
// Its string is frozen once it ships.
const iscsiLUNClaimFeature = "iscsi_lun_claim"

// lunPeerAskTimeout bounds how long a create waits for one host's answer.
const lunPeerAskTimeout = 5 * time.Second

// lunAskMaxKeys bounds one question: a VM has at most a few dozen disks.
const lunAskMaxKeys = 64

// lunMaxGenerations bounds the allocation walk of one LUN.
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

// iscsiLUNClaimGate is the one place allocation on a fixed-device pool waits
// for the release latch.
func (s *Server) iscsiLUNClaimGate(ctx context.Context) error {
	s.releaseFeatureMu.Lock()
	gate := s.releaseFeatureGate
	s.releaseFeatureMu.Unlock()
	why := "the release feature is not wired on this build"
	if gate != nil {
		err := gate(ctx, iscsiLUNClaimFeature)
		if err == nil {
			return nil
		}
		why = err.Error()
	}
	return status.Errorf(codes.FailedPrecondition,
		"an iSCSI LUN is allocated by a voter-majority claim (release feature %s), which is not open yet (%s): "+
			"the cluster upgrade must finish first", iscsiLUNClaimFeature, why)
}

// lunUse is one disk of a create that sits on a fixed device.
type lunUse struct {
	key    string // storage.FixedDevice key: the LUN
	device string
	disk   string
	pool   string
}

// lunClaim is one in-flight create's hold on a LUN.
type lunClaim struct {
	id   uint64
	vm   string
	vmID string
	disk string
}

// lunClaimRegistry is the LUNs this host's in-flight creates are taking. The
// zero value is ready to use.
type lunClaimRegistry struct {
	mu   sync.Mutex
	next uint64
	m    map[string]lunClaim // LUN key → the create holding it
}

// take registers every use for vm, or none of them: if another in-flight
// create holds one, it returns that LUN's key and holder. The returned id
// names this registration; release drops it (idempotent).
func (r *lunClaimRegistry) take(vm, vmID string, uses []lunUse) (id uint64, release func(), heldKey string, held lunClaim) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range uses {
		if c, ok := r.m[u.key]; ok {
			return 0, nil, u.key, c
		}
	}
	if r.m == nil {
		r.m = map[string]lunClaim{}
	}
	r.next++
	id = r.next
	for _, u := range uses {
		r.m[u.key] = lunClaim{id: id, vm: vm, vmID: vmID, disk: u.disk}
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

// fixedDeviceUses resolves spec's disks to the fixed devices (iscsi LUNs) they
// would take, refusing a create that puts two of its own disks on one. A disk
// whose storage does not resolve is left to the create loop, which reports it.
func (s *Server) fixedDeviceUses(ctx context.Context, spec *pb.VMSpec) ([]lunUse, error) {
	var uses []lunUse
	seen := map[string]lunUse{}
	for _, d := range spec.Disks {
		if d.Storage == "" {
			continue
		}
		cfg, err := s.resolveVolume(ctx, spec.StackName, d.Storage)
		if err != nil {
			continue
		}
		key, dev, ok := storage.FixedDevice(cfg)
		if !ok {
			continue
		}
		name := d.Name
		if name == "" {
			name = "root"
		}
		u := lunUse{key: key, device: dev, disk: name, pool: d.Storage}
		if first, dup := seen[key]; dup {
			return nil, status.Errorf(codes.FailedPrecondition,
				"disks %q (storage %q) and %q (storage %q) of VM %q are both iSCSI LUN %s: an iscsi pool is "+
					"one LUN and holds one disk, and two disks on one LUN corrupt each other — give each disk "+
					"a pool of its own LUN (lv pool create ... --driver iscsi --option lun=N)",
				first.disk, first.pool, u.disk, u.pool, spec.Name, u.device)
		}
		seen[key] = u
		uses = append(uses, u)
	}
	return uses, nil
}

// claimLUNs takes, for the VM spec creates on this host, every iscsi LUN its
// disks would use — or refuses the create, naming the VM that holds one. The
// caller must call release once the create has returned (its disk rows
// committed, or the create failed). keep names the LUNs the VM's replaced
// incarnation held as the same disk: the create takes them over as they are.
func (s *Server) claimLUNs(ctx context.Context, spec *pb.VMSpec) (release func(), keep map[string]bool, err error) {
	uses, err := s.fixedDeviceUses(ctx, spec)
	if err != nil {
		return nil, nil, err
	}
	if len(uses) == 0 {
		return func() {}, nil, nil
	}
	if err := s.iscsiLUNClaimGate(ctx); err != nil {
		return nil, nil, err
	}
	byKey := make(map[string]lunUse, len(uses))
	keys := make(map[string]bool, len(uses))
	for _, u := range uses {
		byKey[u.key] = u
		keys[u.key] = true
	}

	id, drop, heldKey, held := s.lunClaims.take(spec.Name, spec.Uuid, uses)
	if drop == nil {
		return nil, nil, lunHeldError(spec.Name, byKey[heldKey], &pb.LUNHolder{
			Lun: heldKey, VmName: held.vm, DiskName: held.disk, HostName: s.hostName, InFlight: true, VmId: held.vmID,
		})
	}
	kept := false
	defer func() {
		if !kept {
			drop()
		}
	}()

	rep, hasRep := replacedVMFor(ctx, spec.Name)
	keep = map[string]bool{}
	for _, u := range uses {
		own, err := s.allocateLUN(ctx, spec, u, rep, hasRep, id)
		if err != nil {
			return nil, nil, err
		}
		keep[u.key] = own
	}

	// A LUN taken before claims existed is a disk row and nothing else: any
	// other live VM's use of it, as a disk or a clone's base, refuses.
	here, err := s.lunHoldersHere(ctx, keys, rep, hasRep, id)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "cannot confirm iSCSI LUN %s is free: read disks: %v",
			uses[0].device, err)
	}
	if len(here) > 0 {
		return nil, nil, lunHeldError(spec.Name, byKey[here[0].Lun], here[0])
	}
	// The replaced incarnation's own disk on the LUN (a LUN it took before
	// claims existed has no decided value naming it).
	if hasRep {
		for _, u := range uses {
			if rep.luns[u.key] == u.disk {
				keep[u.key] = true
			}
		}
	}
	kept = true
	return drop, keep, nil
}

// allocateLUN walks u's LUN's allocations until one is decided for this
// create. own reports that the allocation before it was the replaced
// incarnation's same disk: the LUN is taken over as it is.
func (s *Server) allocateLUN(ctx context.Context, spec *pb.VMSpec, u lunUse, rep replacedVM, hasRep bool, reg uint64) (own bool, err error) {
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return false, status.Errorf(codes.Unavailable, "iSCSI LUN %s: read the voter generation: %v", u.device, err)
	}
	if !cfg.Explicit() {
		return false, status.Errorf(codes.Unavailable,
			"iSCSI LUN %s: an iSCSI LUN is allocated by a voter majority, and %s has adopted no voter generation",
			u.device, s.hostName)
	}
	mine := corrosion.LUNAllocation{LUN: u.key, ClaimID: randid.New(), VMID: spec.Uuid, VMName: spec.Name,
		Disk: u.disk, Host: s.hostName}
	for g := int64(0); g < lunMaxGenerations; g++ {
		mine.Generation = g
		out, err := s.decideLUN(ctx, cfg, mine)
		if err != nil {
			var nm *claims.NoMajorityError
			if errors.As(err, &nm) {
				return false, status.Errorf(codes.Unavailable,
					"cannot take iSCSI LUN %s for VM %q: no majority of the voters answered (%v) — this host may be "+
						"cut off from the cluster; nothing was allocated", u.device, spec.Name, err)
			}
			return false, status.Errorf(codes.Unavailable, "cannot take iSCSI LUN %s for VM %q: %v", u.device, spec.Name, err)
		}
		a := out.Value.LUN
		if a == nil {
			return false, status.Errorf(codes.Internal, "iSCSI LUN %s: allocation %d decided a value that is not a LUN allocation", u.device, g)
		}
		if a.ClaimID == mine.ClaimID {
			return own, nil
		}
		if hasRep && rep.uuid != "" && a.VMID == rep.uuid && a.Disk == u.disk {
			own = true // the replaced incarnation's own disk: the takeover
			continue
		}
		own = false
		holder, err := s.lunAllocationHolder(ctx, *a, rep, hasRep, reg)
		if err != nil {
			return false, err
		}
		if holder != nil {
			return false, lunHeldError(spec.Name, u, holder)
		}
	}
	return false, status.Errorf(codes.ResourceExhausted, "iSCSI LUN %s: more than %d allocations", u.device, lunMaxGenerations)
}

// decideLUN decides one allocation of a LUN under generation cfg, proposing
// mine.
func (s *Server) decideLUN(ctx context.Context, cfg *corrosion.VoterConfig, mine corrosion.LUNAllocation) (claims.Outcome, error) {
	names := cfg.Names()
	q := corrosion.MajorityOf(len(names))
	key := corrosion.LUNClaimKey(mine.LUN, mine.Generation)
	v := corrosion.ClaimValue{LUN: &mine}
	return s.claimProposer().Decide(ctx, claims.Spec{
		Key: key, Generation: cfg.Generation, Voters: names, PrepareQuorum: q,
		Electorate: func(corrosion.ClaimValue) ([]string, int) { return names, q },
		Propose:    func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return v, nil },
		StartRound: 1,
	})
}

// lunAllocationHolder returns what still holds allocation a, or nil once it
// is proven gone: no live disk row here uses the LUN, and the host that ran
// a's create has it neither in flight nor in its replica. reg is the asking
// create's own registration, which is not a holder. A host that cannot
// be asked is an error (Unavailable): what it took, it holds. A host no longer
// in the cluster runs no create.
func (s *Server) lunAllocationHolder(ctx context.Context, a corrosion.LUNAllocation, rep replacedVM, hasRep bool, reg uint64) (*pb.LUNHolder, error) {
	keys := map[string]bool{a.LUN: true}
	here, err := s.lunHoldersHere(ctx, keys, rep, hasRep, reg)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read disks: %v", err)
	}
	if len(here) > 0 {
		return here[0], nil
	}
	if a.Host == s.hostName {
		return nil, nil // lunHoldersHere already asked this host's registry
	}
	host, err := corrosion.GetHost(ctx, s.db, a.Host)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read host %s: %v", a.Host, err)
	}
	if host == nil {
		slog.Info("iSCSI LUN: the host that took an earlier allocation is no longer in the cluster",
			"lun", a.LUN, "generation", a.Generation, "host", a.Host, "vm", a.VMName)
		return nil, nil
	}
	req := &pb.LUNHoldersRequest{Luns: []string{a.LUN}}
	if hasRep {
		req.ReplacedName, req.ReplacedCreatedAt = rep.name, rep.snap.CreatedAt
	}
	there, err := s.askLUNHolders(ctx, a.Host, req)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable,
			"iSCSI LUN %s was taken by a create of VM %q on %s, which cannot be asked whether that create is gone (%v); "+
				"nothing was allocated — retry once %s answers", a.LUN, a.VMName, a.Host, err, a.Host)
	}
	if len(there) > 0 {
		return there[0], nil
	}
	return nil, nil
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
// creates (except registration own), then every live VM's use of the LUN in
// its replica — as a disk, or as a linked clone's base — except the replaced
// incarnation's own rows (name AND created_at). Sorted, so a refusal names the
// same holder each time.
func (s *Server) lunHoldersHere(ctx context.Context, keys map[string]bool, rep replacedVM, hasRep bool, own uint64) ([]*pb.LUNHolder, error) {
	var out []*pb.LUNHolder
	for k, c := range s.lunClaims.holding(keys, own) {
		out = append(out, &pb.LUNHolder{Lun: k, VmName: c.vm, DiskName: c.disk, HostName: s.hostName, InFlight: true, VmId: c.vmID})
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
			Backing: d.Via == "backing"})
	}
	sortLUNHolders(out)
	return out, nil
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

// askLUNHolders asks one host, within lunPeerAskTimeout. An answer never adds
// a LUN that was not asked about.
func (s *Server) askLUNHolders(ctx context.Context, host string, req *pb.LUNHoldersRequest) ([]*pb.LUNHolder, error) {
	ctx, cancel := context.WithTimeout(ctx, lunPeerAskTimeout)
	defer cancel()
	c, done, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, err
	}
	defer done()
	resp, err := c.LUNHolders(ctx, req)
	if err != nil {
		return nil, err
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
	return out, nil
}

// LUNHolders answers, from this host's in-flight creates and its replica,
// which VMs hold any of the asked LUNs. Peer-only. Only the replaced
// incarnation the request names — by name and created_at — is exempt.
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
	holders, err := s.lunHoldersHere(ctx, keys, rep, hasRep, 0)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read disks: %v", err)
	}
	return &pb.LUNHoldersResponse{Holders: holders}, nil
}
