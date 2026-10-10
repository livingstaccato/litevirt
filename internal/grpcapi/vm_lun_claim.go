package grpcapi

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// One iSCSI LUN, one disk.
//
// An iscsi pool is one pre-provisioned LUN, and its driver allocates nothing:
// CreateDisk hands every disk on the pool the same /dev/disk/by-path device.
// Two disks on one such pool — of one VM, or of two VMs on any hosts — are one
// block device written by two guests, which corrupts it silently. So a create
// refuses a LUN that is already a disk, naming the VM that holds it.
//
// "Already a disk" has to hold across hosts, and the replica alone cannot say
// it: two creates on two hosts each read a replica holding neither and both
// win. So each create, on the host that will own the VM:
//
//  1. refuses a LUN twice within itself;
//  2. registers its LUNs in this host's in-flight set (lunClaims), refusing one
//     another create here is still taking;
//  3. refuses a LUN its replica shows as a live VM's disk;
//  4. asks every other host (LUNHolders) for the VMs holding the LUN in its
//     replica or in its own in-flight set, and refuses on any answer;
//  5. keeps its registration until the create returns — after its disk rows
//     are committed here, where every later question reaches them.
//
// Steps 2 and 4 decide a race. Each of two racing creates registers before it
// asks, and a host answers from its registry under its lock, so whichever asks
// second finds the other's registration: at most one of them wins. Both may
// lose, when each asks after the other registered; that is a refusal the
// caller retries, never a shared LUN.
//
// Which hosts must answer: every host that can run a create — any host still
// counted as a voting member (not offline, maintenance or fenced) and past
// joining. One of those that cannot be asked refuses the create (Unavailable):
// the create it might be running is exactly what this check exists to see. A
// host that is down by the cluster's own account, or on an older build that
// does not know the question (Unimplemented), is not asked; its committed
// disks reach this host by replication like any other row. That leaves a
// create racing on a partitioned host the cluster has already marked down,
// which the shared_lun health condition reports once the two sides' rows meet
// (shared_lun_health.go).
//
// A VM's own rows hold nothing against it: a rebuild or a recreate re-creates
// a VM under its name onto the LUN its previous incarnation held, and a
// replica that has not applied that incarnation's tombstone still lists it.
// The name cannot belong to another live VM — the create refuses a name that
// exists.

// lunPeerAskTimeout bounds how long a create waits for one host's answer.
const lunPeerAskTimeout = 5 * time.Second

// lunAskMaxKeys bounds one question: a VM has at most a few dozen disks.
const lunAskMaxKeys = 64

// iscsiDevicePrefix is where every iscsi pool's device lives.
const iscsiDevicePrefix = "/dev/disk/by-path/"

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
func (r *lunClaimRegistry) take(vm string, uses []lunUse) (id uint64, release func(), heldKey string, held lunClaim) {
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
		r.m[u.key] = lunClaim{id: id, vm: vm, disk: u.disk}
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
// committed, or the create failed). own names the LUNs this VM's own rows
// still hold here: the previous incarnation of a VM being rebuilt or
// re-created, whose disk the new one takes over as it is.
func (s *Server) claimLUNs(ctx context.Context, spec *pb.VMSpec) (release func(), own map[string]bool, err error) {
	uses, err := s.fixedDeviceUses(ctx, spec)
	if err != nil {
		return nil, nil, err
	}
	if len(uses) == 0 {
		return func() {}, nil, nil
	}
	byKey := make(map[string]lunUse, len(uses))
	keys := make(map[string]bool, len(uses))
	for _, u := range uses {
		byKey[u.key] = u
		keys[u.key] = true
	}

	id, drop, heldKey, held := s.lunClaims.take(spec.Name, uses)
	if drop == nil {
		return nil, nil, lunHeldError(spec.Name, byKey[heldKey], &pb.LUNHolder{
			Lun: heldKey, VmName: held.vm, DiskName: held.disk, HostName: s.hostName, InFlight: true,
		})
	}
	kept := false
	defer func() {
		if !kept {
			drop()
		}
	}()

	here, err := s.lunHoldersHere(ctx, keys, spec.Name, id)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "cannot confirm iSCSI LUN %s is free: read disks: %v",
			uses[0].device, err)
	}
	if len(here) > 0 {
		return nil, nil, lunHeldError(spec.Name, byKey[here[0].Lun], here[0])
	}

	there, unasked, err := s.lunHoldersOnPeers(ctx, keys, spec.Name)
	if err != nil {
		return nil, nil, err
	}
	if len(there) > 0 {
		return nil, nil, lunHeldError(spec.Name, byKey[there[0].Lun], there[0])
	}
	if len(unasked) > 0 {
		return nil, nil, status.Errorf(codes.Unavailable,
			"cannot confirm iSCSI LUN %s is free for VM %q: host(s) %s did not answer, and a create there could be "+
				"taking it — retry once they answer, or once they are marked offline, fenced or in maintenance",
			uses[0].device, spec.Name, strings.Join(unasked, ", "))
	}
	own, err = s.ownLUNs(ctx, keys, spec.Name)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "cannot read VM %q's own disks: %v", spec.Name, err)
	}
	kept = true
	return drop, own, nil
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
		"disk %q (storage %q) of VM %q is iSCSI LUN %s, which is already disk %q of VM %q (host %s): an iscsi "+
			"pool is one LUN and holds one disk, and two VMs writing one LUN corrupt it — give this disk a pool "+
			"of its own LUN (lv pool create ... --driver iscsi --option lun=N)",
		u.disk, u.pool, vm, u.device, h.DiskName, h.VmName, h.HostName)
}

// lunHoldersHere is what this host knows holds any of keys: its in-flight
// creates (except registration own), then the live VM disks in its replica
// (except vm's own rows). Sorted, so a refusal names the same holder each
// time.
func (s *Server) lunHoldersHere(ctx context.Context, keys map[string]bool, vm string, own uint64) ([]*pb.LUNHolder, error) {
	var out []*pb.LUNHolder
	for k, c := range s.lunClaims.holding(keys, own) {
		out = append(out, &pb.LUNHolder{Lun: k, VmName: c.vm, DiskName: c.disk, HostName: s.hostName, InFlight: true})
	}
	disks, err := corrosion.LiveVMDisksWithPathPrefix(ctx, s.db, iscsiDevicePrefix)
	if err != nil {
		return nil, err
	}
	for _, d := range disks {
		if d.VMName == vm {
			continue
		}
		if k, ok := storage.FixedDeviceKeyOfPath(d.Path); ok && keys[k] {
			out = append(out, &pb.LUNHolder{Lun: k, VmName: d.VMName, DiskName: d.DiskName, HostName: d.HostName})
		}
	}
	sortLUNHolders(out)
	return out, nil
}

// ownLUNs is which of keys vm's own live disk rows in this replica are.
func (s *Server) ownLUNs(ctx context.Context, keys map[string]bool, vm string) (map[string]bool, error) {
	disks, err := corrosion.LiveVMDisksWithPathPrefix(ctx, s.db, iscsiDevicePrefix)
	if err != nil {
		return nil, err
	}
	own := map[string]bool{}
	for _, d := range disks {
		if k, ok := storage.FixedDeviceKeyOfPath(d.Path); ok && d.VMName == vm && keys[k] {
			own[k] = true
		}
	}
	return own, nil
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

// lunPeerMustAnswer reports whether a host in state could be running a create
// right now, so that a create may not go ahead without its answer. A host the
// cluster holds offline, fenced or in maintenance is not (VotingEligible), nor
// one whose daemon has not started yet (joining).
func lunPeerMustAnswer(state string) bool {
	return state != corrosion.HostStateJoining && corrosion.VotingEligible(state)
}

// lunHoldersOnPeers asks every other host which VMs hold any of keys.
// unasked names the hosts that had to answer and did not.
func (s *Server) lunHoldersOnPeers(ctx context.Context, keys map[string]bool, vm string) (holders []*pb.LUNHolder, unasked []string, err error) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "cannot list the hosts to ask whether an iSCSI LUN is free: %v", err)
	}
	req := &pb.LUNHoldersRequest{VmName: vm}
	for k := range keys {
		req.Luns = append(req.Luns, k)
	}
	sort.Strings(req.Luns)
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, h := range hosts {
		if h.Name == s.hostName {
			continue
		}
		must := lunPeerMustAnswer(h.State)
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			got, aerr := s.askLUNHolders(ctx, host, req)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case aerr == nil:
				holders = append(holders, got...)
			case status.Code(aerr) == codes.Unimplemented:
				slog.Info("iSCSI LUN check: host is on a build without LUNHolders; its committed disks reach this host by replication",
					"host", host)
			case must:
				slog.Warn("iSCSI LUN check: host did not answer", "host", host, "error", aerr)
				unasked = append(unasked, host)
			default:
				slog.Info("iSCSI LUN check: host not asked (not running creates)", "host", host, "state", h.State, "error", aerr)
			}
		}(h.Name)
	}
	wg.Wait()
	sort.Strings(unasked)
	sortLUNHolders(holders)
	return holders, unasked, nil
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
// which VMs hold any of the asked LUNs. Peer-only.
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
	holders, err := s.lunHoldersHere(ctx, keys, req.VmName, 0)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read disks: %v", err)
	}
	return &pb.LUNHoldersResponse{Holders: holders}, nil
}
