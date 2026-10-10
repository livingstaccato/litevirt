package grpcapi

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
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
// (docs/design/recovery-claims.md §3) over the electorate lunElectorate
// names: the adopted voter generation's members, a majority deciding — or,
// with no member generation adopted, the derived voter set, ALL of whom must
// accept, and which must be more than half the cluster's hosts (any two such
// sets share a voter). The value names the claim, the VM (by uuid), the disk
// and the creating host.
//
// A create, on the host that will own the VM:
//
//  1. refuses a LUN twice within itself, and one another create on this host
//     has in flight (the local registry, lunClaims), or that this host's
//     replica or libvirt shows in use (lunHoldersHere) — before deciding
//     anything;
//  2. registers its LUNs in the registry BEFORE it proposes, and holds them
//     until the create returns — after its row commits;
//  3. walks the LUN's allocations from the LUN's checkpoint: every allocation
//     below it is decided and proven gone (corrosion.GetLUNResolved; a hint
//     the walker verifies against the voters, lunWalkStart). At each
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
// A rebuild or a recreate keeps the claim of the VM it replaces: its preflight
// (preflightLUNs) judges the LUN before the teardown — and re-claims it then
// for the VM, if no allocation names it — and the create takes the LUN over
// without deciding anything, so nothing about the claim can refuse after the
// teardown. The teardown-to-create window is covered by a registry hold
// (holdLUNsForRecreate).
//
// THE GATE. Nothing is allocated on a fixed-device pool until the release
// feature iscsi_lun_claim is open, and an electorate exists
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

// lunElectorateT is who decides a LUN allocation.
type lunElectorateT struct {
	gen     int64
	voters  []string
	quorum  int
	derived bool
}

// lunElectorate is the adopted voter generation's members (a majority
// decides), or — with no member generation adopted: genesis pending, or after
// a reset — the derived voter set (every host not offline, maintenance or
// fenced), ALL of whom must accept, and which must be more than half of the
// cluster's hosts. Two such derived sets each hold more than half the hosts,
// so they share a voter, whose promise keeps two decisions apart, however two
// replicas disagree about host states.
func (s *Server) lunElectorate(ctx context.Context) (lunElectorateT, error) {
	gen, err := corrosion.AdoptedVoterGeneration(ctx, s.db)
	if err != nil {
		return lunElectorateT{}, status.Errorf(codes.Unavailable, "read the voter generation: %v", err)
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return lunElectorateT{}, status.Errorf(codes.Unavailable, "read the voter generation: %v", err)
	}
	if cfg.Explicit() {
		names := cfg.Names()
		return lunElectorateT{gen: gen, voters: names, quorum: corrosion.MajorityOf(len(names))}, nil
	}
	set, err := corrosion.VoterSet(ctx, s.db)
	if err != nil {
		return lunElectorateT{}, status.Errorf(codes.Unavailable, "read the voter set: %v", err)
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return lunElectorateT{}, status.Errorf(codes.Unavailable, "read the hosts: %v", err)
	}
	var names []string
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	if 2*len(names) <= len(hosts) || len(names) == 0 {
		return lunElectorateT{}, status.Errorf(codes.FailedPrecondition,
			"an iSCSI LUN is allocated by a voter claim, and this cluster has adopted no voter generation (genesis is "+
				"pending — see the ha.voter.genesis_pending health condition — or the voters were reset): it then "+
				"decides over every voting-eligible host, and only %d of its %d hosts are (%s) — not more than half. "+
				"Bring the others back, remove the dead ones, or adopt a generation (lv cluster voter init)",
			len(names), len(hosts), strings.Join(names, ", "))
	}
	return lunElectorateT{gen: gen, voters: names, quorum: len(names), derived: true}, nil
}

// lunUse is one disk of a create that sits on a fixed device.
type lunUse struct {
	key    string // storage.FixedDevice key: the LUN
	device string
	disk   string
	pool   string
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

// lunHandoffKey carries a recreate's hold token into its create.
type lunHandoffKey struct{}

func lunHandoffFrom(ctx context.Context) string {
	t, _ := ctx.Value(lunHandoffKey{}).(string)
	return t
}

// holdLUNsForRecreate registers spec's LUNs in this host's registry before a
// rebuild or recreate tears the VM down, so between the teardown and the
// create no other create can read them as gone. The returned context carries
// the hold to the create, which takes it over; release drops it once the
// create has returned.
func (s *Server) holdLUNsForRecreate(ctx context.Context, spec *pb.VMSpec) (context.Context, func()) {
	uses, err := s.fixedDeviceUses(ctx, spec)
	if err != nil || len(uses) == 0 {
		return ctx, func() {}
	}
	token := randid.New()
	_, drop, _, _ := s.lunClaims.take(spec.Name, "", token, uses)
	if drop == nil {
		return ctx, func() {} // held by an in-flight create: the preflight refused already
	}
	return context.WithValue(ctx, lunHandoffKey{}, token), drop
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
	uses, err := s.fixedDeviceUses(ctx, spec)
	if err != nil {
		return nil, err
	}
	if len(uses) == 0 {
		return &lunHold{drop: func() {}}, nil
	}
	rep, hasRep := replacedVMFor(ctx, spec.Name)
	// What the recreate's preflight already judged — the replaced VM's own
	// disk, or a LUN it claimed for it — is taken over without any claim:
	// nothing about the claim may refuse after the teardown.
	taken := func(u lunUse) bool {
		return hasRep && (rep.luns[u.key] == u.disk || rep.claimed[u.key] == u.disk)
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
	hold := &lunHold{s: s, drop: drop, own: map[string]int64{}, keep: map[string]bool{}}
	ok := false
	defer func() {
		if !ok {
			hold.release(ctx, spec.Name)
		}
	}()

	// Anything this host already knows holds a LUN refuses before a
	// generation is spent on it. The VM's own name is not a holder here: an
	// orphan domain of that name is cleaned up by the create.
	here, err := s.lunHoldersHere(ctx, keys, rep, hasRep, id, spec.Name)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cannot confirm iSCSI LUN %s is free: read disks: %v",
			uses[0].device, err)
	}
	if len(here) > 0 {
		return nil, lunHeldError(spec.Name, byKey[here[0].Lun], here[0])
	}
	for _, u := range uses {
		if taken(u) {
			hold.keep[u.key] = rep.luns[u.key] == u.disk
			continue
		}
		mine := corrosion.LUNAllocation{LUN: u.key, ClaimID: randid.New(), VMID: spec.Uuid, VMName: spec.Name,
			Disk: u.disk, Host: s.hostName}
		g, err := s.allocateLUN(ctx, spec.Name, u, mine, rep, hasRep, id)
		if err != nil {
			return nil, err
		}
		hold.own[u.key] = g
	}
	ok = true
	return hold, nil
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
	return c, nil
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
// decided for mine, and returns its generation. An allocation decided for
// another create is gone, or refuses.
func (s *Server) allocateLUN(ctx context.Context, vm string, u lunUse, mine corrosion.LUNAllocation, rep replacedVM, hasRep bool, reg uint64) (int64, error) {
	el, err := s.lunElectorate(ctx)
	if err != nil {
		return 0, err
	}
	start, err := s.lunWalkStart(ctx, el, u.key)
	if err != nil {
		return 0, lunDecisionError(u, vm, err)
	}
	for g := start; g < start+lunMaxGenerations; g++ {
		mine.Generation = g
		out, err := s.decideLUNWith(ctx, el, mine)
		if err != nil {
			return 0, lunDecisionError(u, vm, err)
		}
		a := out.Value.LUN
		if a == nil {
			return 0, status.Errorf(codes.Internal, "iSCSI LUN %s: allocation %d decided a value that is not a LUN allocation", u.device, g)
		}
		if a.ClaimID == mine.ClaimID {
			return g, nil
		}
		holder, err := s.lunAllocationHolder(ctx, el, *a, rep, hasRep, reg)
		if err != nil {
			return 0, err
		}
		if holder != nil {
			return 0, lunHeldError(vm, u, holder)
		}
		if err := corrosion.AdvanceLUNResolved(ctx, s.db, u.key, g+1, s.hostName); err != nil {
			slog.Warn("iSCSI LUN: record checkpoint", "lun", u.key, "generation", g+1, "error", err)
		}
	}
	return 0, status.Errorf(codes.ResourceExhausted, "iSCSI LUN %s: more than %d open allocations", u.device, lunMaxGenerations)
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
// by name, that nothing there does, or is recorded removed. reg is the asking
// create's own registration, which is not a holder.
func (s *Server) lunAllocationHolder(ctx context.Context, el lunElectorateT, a corrosion.LUNAllocation, rep replacedVM, hasRep bool, reg uint64) (*pb.LUNHolder, error) {
	keys := map[string]bool{a.LUN: true}
	here, err := s.lunHoldersHere(ctx, keys, rep, hasRep, reg, "")
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read disks: %v", err)
	}
	if len(here) > 0 {
		return here[0], nil
	}
	if a.Host == s.hostName {
		return nil, nil // this host's registry, replica and domains were just read
	}
	req := &pb.LUNHoldersRequest{Luns: []string{a.LUN}}
	if hasRep {
		req.ReplacedName, req.ReplacedCreatedAt = rep.name, rep.snap.CreatedAt
	}
	there, askErr := s.askLUNHolders(ctx, a.Host, req)
	if askErr == nil {
		if len(there) > 0 {
			return there[0], nil
		}
		return nil, nil
	}
	// No answer. Gone only on a record of the host's removal.
	if removed, err := corrosion.HostRemoved(ctx, s.db, a.Host); err == nil && removed {
		slog.Info("iSCSI LUN: the host that took an earlier allocation was removed from the cluster",
			"lun", a.LUN, "generation", a.Generation, "host", a.Host, "vm", a.VMName)
		return nil, nil
	}
	if s.votedOut(ctx, el, a.Host) {
		slog.Info("iSCSI LUN: the host that took an earlier allocation was removed from the voters, and has no "+
			"row here", "lun", a.LUN, "host", a.Host)
		return nil, nil
	}
	return nil, status.Errorf(codes.Unavailable,
		"iSCSI LUN %s was taken by a create of VM %q on %s, which cannot be asked whether that create is gone (%v), "+
			"and whose removal from the cluster is not recorded here; nothing was allocated — retry once %s answers, "+
			"or once it is removed (lv host rm)", a.LUN, a.VMName, a.Host, askErr, a.Host)
}

// votedOut reports whether the adopted voter generation records host's
// removal: host was a member of an earlier generation, is not one of the
// adopted one, and this replica holds no live row for it. A host that was
// never a voter is not evidenced removed by any generation.
func (s *Server) votedOut(ctx context.Context, el lunElectorateT, host string) bool {
	if el.derived || el.gen <= 1 || slicesContains(el.voters, host) {
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
// creates (except registration own); every live VM's use of the LUN in its
// replica — as a disk, or as a linked clone's base — except the replaced
// incarnation's rows (name AND created_at); and every libvirt domain on this
// host whose disks use the LUN — a guest running with no row still holds it —
// except the replaced VM's domain and selfDomain (the VM this host is
// creating, whose orphan the create cleans up). Sorted, so a refusal names
// the same holder each time.
func (s *Server) lunHoldersHere(ctx context.Context, keys map[string]bool, rep replacedVM, hasRep bool, own uint64, selfDomain string) ([]*pb.LUNHolder, error) {
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
	return out, nil
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
	holders, err := s.lunHoldersHere(ctx, keys, rep, hasRep, 0, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read disks: %v", err)
	}
	return &pb.LUNHoldersResponse{Holders: holders, AnsweredBy: s.hostName}, nil
}
