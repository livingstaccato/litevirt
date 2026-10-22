package grpcapi

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// TestServerOpts is the minimal set of fields the in-process fleet
// harness needs to build a Server. Anything not specified here gets
// the same zero-value treatment NewServer-via-daemon would give it,
// which is fine because no production daemon ever constructs a Server
// without libvirt + an image store. Tests that need those plumbing
// pieces inject them via the existing Set*() methods.
type TestServerOpts struct {
	// DBWorkerEvent observes actual loop boundaries; configure before startup.
	DBWorkerEvent     func(context.Context, string, string)
	ReleaseSweepEvery time.Duration

	HostName string
	DataDir  string
	PKIDir   string
	DB       *corrosion.Client
	// Virt is the libvirt backend. nil = scenarios that touch VM
	// lifecycle will NPE — set Virt to a *libvirtfake.Fake (or any
	// other LibvirtBackend impl) for those.
	Virt LibvirtBackend
}

// ImagePathForTests exposes the image store's path resolver for
// fleet-harness scenarios that need to stage a fake image file
// before driving DeployStack. Tests-only — production callers never
// need this because images come through real auto-pull.
func (s *Server) ImagePathForTests(imageName string) string {
	if s.images == nil {
		return ""
	}
	return s.images.ImagePath(imageName)
}

// PeerClientForTests exposes peerClient so the fleet harness can assert on peer
// DIALLING, not just on peer acceptance. The two halves were fixed at different
// times and only the inbound one had coverage.
func (s *Server) PeerClientForTests(ctx context.Context, hostName string) (pb.LiteVirtClient, *grpc.ClientConn, error) {
	return s.peerClient(ctx, hostName)
}

// SetClaimVoteObserverForTest registers fn to see every promise and accept
// this voter commits, from a peer's RPC or from its own proposer alike. The
// fleet harness uses it to check, across every voter, that no voter accepts two
// values at one ballot and that at most one value is ever chosen per claim key.
// nil removes it.
func (s *Server) SetClaimVoteObserverForTest(fn func(ClaimVote)) {
	s.claims.mu.Lock()
	s.claims.observer = fn
	s.claims.mu.Unlock()
}

// NewServerForTests is the in-process-fleet construction entry point.
// Identical to NewServer except virt and images stay nil — VM
// lifecycle RPCs will NPE if called, which is intentional: scenarios
// either inject fakes via Set*() or operate at the Corrosion layer.
//
// Do not call this from production code paths — the missing pieces
// (libvirt, image store) are not optional in a real daemon. The
// build-tag-free location is deliberate; the harness lives in tests/
// and can import internal/grpcapi without a wrapping interface.
func NewServerForTests(opts TestServerOpts) *Server {
	// Always wire an image.Store so the autoPullImages path on
	// DeployStack has somewhere to ImagePath() and ImageExists().
	// Tests that need a fully-stocked image cache write files into
	// opts.DataDir/images before calling the relevant RPC.
	imgs := image.NewStore(opts.DataDir)
	_ = imgs.Init()
	s := &Server{
		testDBWorkerEvent:     opts.DBWorkerEvent,
		testReleaseSweepEvery: opts.ReleaseSweepEvery,
		hostName:              opts.HostName,
		dataDir:               opts.DataDir,
		pkiDir:                opts.PKIDir,
		db:                    opts.DB,
		virt:                  opts.Virt,
		images:                imgs,
		events:                events.NewBus(),
		vmLocks:               make(map[string]*sync.Mutex),
		ReExecCh:              make(chan struct{}, 1),
		ShutdownCh:            make(chan struct{}, 1),
		fetchBinarySem:        make(chan struct{}, fetchBinaryMaxConcurrent),
		pushBackupSem:         make(chan struct{}, pushBackupMaxConcurrent),
		automationExportSem:   make(chan struct{}, automationExportConcurrent),
		lbKick:                make(chan struct{}, 1),
		vrrpAskKick:           make(chan struct{}, 1),
		fwStore:               lv.NewFirmwareStore(opts.DataDir),
	}
	s.wireCertificateVerifier()
	s.wireReplicationReleaseGates()
	s.wireConsolePasswordPolicy()
	if opts.DB != nil {
		s.wireMoveRecordWatch()
	}
	return s
}

// ForgetMoveRecordsForTest does to this host's stub and seed records what a
// daemon restart does: they are kept in memory only, so a restart forgets
// them, and every file at a disk path then reads as one this host did not
// create.
func (s *Server) ForgetMoveRecordsForTest() {
	s.migrationStubs.reset()
	s.migrationISOs.reset()
}

// SetLXCCapableForTest makes this server's runtime inventory list (on) or skip
// (off) its containers whatever lxc tooling the machine running the test has,
// so a fleet scenario that seeds a container runtime sees it in every host's
// inventory, as an LXC-capable host would report it.
func (s *Server) SetLXCCapableForTest(on bool) { s.lxcCapableForTest.Store(&on) }

// RecordSelfReportedIsolationForTest drives one §A self-reported-quarantine
// check synchronously, so a fleet scenario can assert the observation without
// waiting on the HA monitor's timer.
func (s *Server) RecordSelfReportedIsolationForTest(ctx context.Context) {
	s.observeOneSelfReportedQuarantine(ctx)
}

// SetVNCHandshakeTimeoutForTests shortens the bound on a viewer's RFB
// handshake (package-wide), returning the restore.
func SetVNCHandshakeTimeoutForTests(d time.Duration) func() {
	old := vncHandshakeTimeout
	vncHandshakeTimeout = d
	return func() { vncHandshakeTimeout = old }
}

// HoldVMLockForTest takes this server's per-VM lock on name, as a request in
// flight for that VM holds it, and returns its release.
func (s *Server) HoldVMLockForTest(name string) (release func()) { return s.lockVM(name) }

// NotEnforcingTokensForTests is what this server would report in
// PingResponse.not_enforcing, for a fleet scenario to assert on.
func (s *Server) NotEnforcingTokensForTests() []string { return s.notEnforcingTokens() }

// SetWALQuarantinedForTest makes this server report itself WAL-quarantined, the
// state the shipped rollback detector produces on a binary below a latched token.
func (s *Server) SetWALQuarantinedForTest(on bool) {
	fn := func() bool { return on }
	s.walQuarantined.Store(&fn)
}

// SetDependsOnWaitTimeoutForTests shortens waitForCondition's timeout so a
// fleet scenario can reach a failed compose depends-on wait without waiting
// the production 5-10 minutes. Zero restores the default.
func (s *Server) SetDependsOnWaitTimeoutForTests(d time.Duration) {
	s.dependsOnWaitTimeout.Store(int64(d))
}

// ForgetNetworkReconcileForTests drops everything ReconcileNetworksOnce
// remembers about this host, and the device each network was provisioned on
// here as far as this process holds it in memory (a state file set with
// SetNetworkDeviceStatePath is read again), as a daemon restart does: the next pass
// provisions every live network and tears down every tombstoned one again.
func (s *Server) ForgetNetworkReconcileForTests() {
	s.netReconcile.mu.Lock()
	defer s.netReconcile.mu.Unlock()
	s.netReconcile.applied, s.netReconcile.torn, s.netReconcile.lastErr = nil, nil, nil
	s.netDevs.mu.Lock()
	s.netDevs.defs, s.netDevs.pending, s.netDevs.loaded = nil, nil, false
	s.netDevs.arrivals, s.netDevs.loadErr = nil, nil
	s.netDevs.mu.Unlock()
}

// RecreateVMForTest runs the rolling engine's recreate of name to desired
// (serverOps.RecreateVM) on this server, with ctx as the deploy's caller. A
// compose file never carries an installer ISO into a desired spec, so a fleet
// scenario about re-creating an ISO VM drives this entry point directly.
func (s *Server) RecreateVMForTest(ctx context.Context, name string, desired *pb.VMSpec) error {
	return (&serverOps{s: s}).RecreateVM(ctx, name, desired)
}

// SetReplacedTombstoneWaitForTest sets how long a re-create on this server
// waits for its replica to apply the tombstone of the VM it replaces before
// retiring the stale row itself (vm_recreate_replaces.go).
func (s *Server) SetReplacedTombstoneWaitForTest(d time.Duration) {
	s.replacedTombstoneWait = d
}

// SetRecreateTornDownHookForTest runs fn in every rebuild and rolling recreate
// on this server once the old VM is torn down, before it is created again.
func (s *Server) SetRecreateTornDownHookForTest(fn func(name string)) { s.recreateTornDown = fn }

// SetImageRecreateGraceForTest sets how long a deleted VM row still records
// its image for lv image rm (imageRecreateGrace); d < 0 turns it off.
func (s *Server) SetImageRecreateGraceForTest(d time.Duration) {
	s.imagePrune.recentGrace.Store(int64(d))
}

// SetImageOpenFilesForTest replaces lv image rm's reading of the processes
// that hold a file open.
func (s *Server) SetImageOpenFilesForTest(fn func([]string) (map[string]string, error)) {
	s.imagePrune.openFiles = fn
}

// OpenFilesOfThisProcessForTest is lv image rm's open-file reading limited to
// the calling process: a fleet test runs without root, where the full read
// fails closed on every other user's process.
func OpenFilesOfThisProcessForTest(paths []string) (map[string]string, error) {
	self := strconv.Itoa(os.Getpid())
	return processesHoldingIn("/proc", func(pid string) bool { return pid == self }, paths)
}

// SetImageDeleteMarginForTest sets the margin the prune keeps a deleted
// image's file within (imageDeleteMargin's floor): a fleet test that removes an
// image moments after importing it removes the file at once.
func (s *Server) SetImageDeleteMarginForTest(d time.Duration) {
	s.imagePrune.deleteMargin.Store(int64(d))
}

// SetImageRecordHookForTest runs fn as an image operation begins recording
// its copy (recordImage), before it reads the catalog row: a test deletes the
// image there to land lv image rm inside the operation.
func (s *Server) SetImageRecordHookForTest(fn func(name string)) {
	if fn == nil {
		s.imagePrune.recordHook.Store(nil)
		return
	}
	s.SetImageRecordClockHookForTest(func(name, _ string) { fn(name) })
}

// SetImageRecordClockHookForTest is SetImageRecordHookForTest whose fn also
// gets the catalog insert clock the record is about to be written at, reserved
// as the operation began: a test orders two operations' records by it.
func (s *Server) SetImageRecordClockHookForTest(fn func(name, clock string)) {
	if fn == nil {
		s.imagePrune.recordHook.Store(nil)
		return
	}
	s.imagePrune.recordHook.Store(&fn)
}

// SetImagePushUnmarkedForTest makes PushImage omit its copy mark, as a build
// before it did: the target must still take the push for a copy.
func (s *Server) SetImagePushUnmarkedForTest(unmarked bool) {
	s.imagePrune.pushUnmarked.Store(unmarked)
}

// AutoPullFromPeerForTest is an auto-pull's transfer from source (what
// AutoPullImage runs once it has found no usable local file): two auto-pulls
// that both checked before either published each run it.
func (s *Server) AutoPullFromPeerForTest(ctx context.Context, name, source string) error {
	return s.pullImageFromPeer(ctx, name, source)
}

// SetClearFirewallTagsForTest replaces every firewall-tags clear this server
// makes (a delete's, a copied identity's) with fn, so a fleet scenario can
// make the clear fail; nil restores ClearFirewallTags.
func (s *Server) SetClearFirewallTagsForTest(fn func(ctx context.Context, kind, fwID string) error) {
	if fn == nil {
		s.testClearFirewallTagsLive.Store(nil)
		return
	}
	s.testClearFirewallTagsLive.Store(&fn)
}

// SweepReleaseUsesForTest runs one release use sweep pass on this server, as
// the lease holder's ticker does every releaseUseSweepInterval.
func (s *Server) SweepReleaseUsesForTest(ctx context.Context) {
	s.sweepReleaseUses(ctx, releaseUseProbes)
}

// SweepFirewallTagOrphansForTest runs one firewall-tags orphan sweep pass on
// this server with its clock at now (a fake clock: the grace is judged
// against it).
func (s *Server) SweepFirewallTagOrphansForTest(ctx context.Context, now time.Time) {
	s.sweepFirewallTagOrphans(ctx, now)
}

func (s *Server) dbWorkerEvent(ctx context.Context, name, event string) {
	if s.testDBWorkerEvent != nil {
		s.testDBWorkerEvent(ctx, name, event)
	}
}

// SetStackMemberDeleteHookForTest sets the seam DeleteStack calls with each
// member's name right before deleting it.
func (s *Server) SetStackMemberDeleteHookForTest(fn func(name string)) { s.stackMemberDeleteHook = fn }

// SetDeleteLeaseTakenHookForTest runs fn, with the VM's name, once a delete
// carried out on this host holds the VM's start lease and its lock, before
// it reads the row again: where a fleet scenario lands what another actor
// does meanwhile.
func (s *Server) SetDeleteLeaseTakenHookForTest(fn func(name string)) { s.deleteLeaseTakenHook = fn }

// FailVMReadBackForTests makes the read of a VM a start has just started
// fail (vmReadBackHook): a start libvirt answered whose answer cannot be
// read back. nil restores the real read.
func (s *Server) FailVMReadBackForTests(fn func(name string) error) { s.vmReadBackHook = fn }
