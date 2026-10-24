package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/litevirt/litevirt/internal/netutil"
	"github.com/litevirt/litevirt/internal/secretfile"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/billing"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fencessh"
	"github.com/litevirt/litevirt/internal/filerestore"
	"github.com/litevirt/litevirt/internal/firewall"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hlc"
	"github.com/litevirt/litevirt/internal/hostboot"
	"github.com/litevirt/litevirt/internal/hostnet"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/obs"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/pressure"
	"github.com/litevirt/litevirt/internal/restapi"
	"github.com/litevirt/litevirt/internal/scheduler"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
	"github.com/litevirt/litevirt/internal/ui"
	"github.com/litevirt/litevirt/internal/vfio"
	"github.com/litevirt/litevirt/internal/watchdog"
)

// grpcMaxMsgSize raises the gRPC max message size above the 4 MiB default for
// the internal cluster RPCs (full-state dump fallback, replication batches).
// StreamStateDump chunks well below this; it's a backstop for the non-chunked
// paths that share the connection.
const grpcMaxMsgSize = 64 << 20 // 64 MiB

// Daemon is the main litevirtd process.
type Daemon struct {
	// captureReg is the host's memory snapshot capture registry, shared by
	// the gRPC server, the partition pauser and the settle.
	captureReg *libvirt.CaptureRegistry
	// ownRowWake is signalled when an apply changes this host's own row;
	// bootRes keeps the boot report's figures (own_row.go).
	ownRowWake chan struct{}
	bootRes    bootResources
	// ownRowReconciling single-flights the own-row reconcile; the two func
	// fields replace the reconcile and the certificate source in tests.
	ownRowReconciling atomic.Bool
	ownRowReconciler  func(ctx context.Context, from string)
	ownRowCertSource  corrosion.InstalledCert
	// auditWired is closed once wireAuditKeyring has installed the keyring
	// audit rows are signed with; runAuditHold lands nothing before it.
	auditWiredOnce sync.Once
	auditWired     chan struct{}
	auditWiredDone sync.Once

	cfg *Config
	db  *corrosion.Client
	// pressure is the host-pressure sampler startPressure started, nil when
	// pressure is off; closeDatabase stops it before the database closes.
	pressure *pressure.Sampler
	// listHostPools is the sampler's pool-list read; nil is
	// corrosion.ListStoragePoolsForHost (a test seam).
	listHostPools func(context.Context, *corrosion.Client, string) ([]corrosion.StoragePoolRecord, error)
	virt          *libvirt.Client
	// fwStore is the host's one firmware store, guarded by the firmware move
	// guard from the moment libvirt is connected, and shared by the server and
	// the reconciler.
	fwStore *libvirt.FirmwareStore
	images  *image.Store
	grpcSrv *grpc.Server
	svc     *grpcapi.Server // gRPC service handler; held so background loops can refresh it
	checker *health.Checker
	metrics *metrics.Server

	// startWaitSvc is svc for the libvirt start-guard wait, which is wired
	// before svc exists and asks it which incarnation a create is starting.
	startWaitSvc *atomic.Pointer[grpcapi.Server]
	// bootWatchdog pets a watchdog timer a previous run left running, from the
	// start of New until Run hands it to the heartbeat (bootUnderWatchdog).
	// Nil when there is none.
	bootWatchdog *watchdog.BootKeeper
	// watchdogRunDir holds the self-fence marker and the boot streak
	// (watchdog.RunDir); "" in tests that build a Daemon by hand.
	watchdogRunDir string
	// watchdogCtrl is the heartbeat's controller (startWatchdog).
	watchdogCtrl *watchdog.Controller

	// buildServer replaces grpcapi.NewServer in newServer (tests, which have
	// no libvirt); nil in a daemon.
	buildServer func() *grpcapi.Server

	// certWatch reports on the certificates this node serves (cert_watch.go).
	certWatch *certWatch

	// mintClearance is the gRPC server the lease-mint clearance asks, published
	// once its gate is wired. Atomic because lease holders (the rebalancer)
	// start before the server exists. See wireLeaseMintClearance.
	mintClearance atomic.Pointer[grpcapi.Server]

	// migrationTLSMu serializes the migration-TLS install hook. Storage
	// migrations and the start-up install both run it, and
	// two installs interleaving their per-file skip/write could leave QEMU a
	// certificate from one set and a key from the other.
	migrationTLSMu sync.Mutex

	// authEngine is wired into the gRPC server below; kept on the daemon
	// struct so the backstop reload loop (runAuthEngineReload) can refresh it.
	authEngine *auth.Engine

	// opJournal is the host-local tier of the F1 operation journal (durable
	// artifacts only this host can restore); the startup recovery barrier reduces
	// it against replicated state before runtime loops + API serving start.
	opJournal *opjournal.Journal

	// realmRegistry holds Local + every configured OIDC/LDAP realm.
	// Login dispatches by name through this registry.
	realmRegistry *auth.Registry

	// fwReconciler polls security_groups + sg_rules and atomically
	// replaces this host's nftables ruleset. Stop() is called on
	// shutdown so the goroutine exits cleanly.
	fwReconciler *firewall.Reconciler

	// snapScheduler is the leader-gated minute-tick that fires backup
	// schedules. Built before the gRPC server (so daemon Run can wire
	// the Runner once svc exists) and Stop()-ed on shutdown.
	snapScheduler *scheduler.SnapshotScheduler

	// upgradePending is set at startup when a post-upgrade sentinel is present:
	// this boot is a freshly-swapped binary that must prove its local gRPC is
	// healthy before its host state flips upgrading→active (the watchdog does the
	// flip on confirm). Set once in startUpgradeWatchdog, read in Run.
	upgradePending bool
	// selfPinger, when set, replaces the local mTLS client the restart check
	// pings this daemon through (awaitServingThenActivate). Tests only.
	selfPinger func() (pinger, func(), error)
	// confirmServing, when set, replaces hostboot.ConfirmServing in the
	// restart's serving check (confirmActive). Tests only.
	confirmServing func(ctx context.Context) (bool, string, error)
	// returningGate, when set, replaces the release-feature gate a returning
	// boot's write goes through (returningBootGate). Tests only.
	returningGate releaseGate

	// rolledBackTokens names capability tokens this node already latched that this
	// binary has never heard of — i.e. this binary is a rollback below them. Set at
	// startup by preflightCapabilityRollback. Non-empty puts the node under WAL
	// quarantine: it stays UP and reachable, so peers can see it and an operator can
	// reseed it, but it emits no replicated writes.
	rolledBackTokens []string

	// exitFunc terminates the process on a watchdog rollback. Defaults to os.Exit;
	// overridable in tests.
	exitFunc func(int)

	// adminPasswordPath is where a freshly seeded admin password is written.
	// Empty means adminPasswordFile; overridable in tests, which must not write
	// to /etc — and must not silently pass on a machine where that write fails.
	adminPasswordPath string

	// pciScanOverride replaces pci.Scan in runPCIScan. Nil in production;
	// tests have no sysfs to scan.
	pciScanOverride func() ([]pci.Device, error)

	// flushTelemetry flushes OTLP telemetry with a bounded timeout. Assigned
	// once in Run, BEFORE the upgrade watchdog is armed — the watchdog
	// goroutine can call exit() before obs.Setup completes, and this field
	// itself must never be nil/racing when it does. It reads the real
	// shutdown func from telemetryShutdown rather than closing over it
	// directly, so it's safe to call at any time. Called by exit() so an
	// os.Exit path doesn't drop the last spans/logs.
	flushTelemetry func()

	// telemetryShutdown holds obs.Setup's shutdown func once Setup completes;
	// nil until then. Written once from Run, read concurrently by
	// flushTelemetry — which the watchdog goroutine (armed before Setup runs)
	// can invoke via exit() at any time — so this needs atomic access, not a
	// plain field. Finding 7.
	telemetryShutdown atomic.Pointer[func(context.Context) error]
}

// New creates a new daemon instance.
//
// A watchdog timer a previous run left running is petted before anything
// else, and through the rest of New and Run until Heartbeat takes it over
// (bootUnderWatchdog).
func New(cfg *Config) (*Daemon, error) {
	return bootUnderWatchdog(
		func() *watchdog.BootKeeper { return watchdog.KeepBootAlive(cfg.WatchdogDev, bootKeeperOptions(cfg)) },
		func(bk *watchdog.BootKeeper) (*Daemon, error) { return newDaemon(cfg, bk) },
	)
}

// wireWatchdog wires the heartbeat's controller before the heartbeat starts:
// the self-fence marker's directory, so a restarted daemon cannot cancel the
// reboot, and the liveness gate's DB round trip and threshold
// (watchdog.liveness_stale_sec; 0 turns the gate off). The pauser joins the
// gate once it exists (wirePauserLiveness).
func (d *Daemon) wireWatchdog(ctrl *watchdog.Controller) {
	ctrl.SetRunDir(d.watchdogRunDir)
	ctrl.SetLivenessStale(time.Duration(d.cfg.Watchdog.LivenessStaleSec) * time.Second)
	// Query waits for the client's lock without ctx: a writer holding it past
	// the threshold is the wedge the gate catches. Only a nil return counts as
	// progress; a timeout, an interrupt or SQLITE_BUSY/LOCKED does not
	// (SetDBProbe).
	ctrl.SetDBProbe(func(ctx context.Context) error {
		_, err := d.db.Query(ctx, "SELECT 1")
		return err
	})
}

// watchdogNotifier delivers a watchdog notification. *grpcapi.Server
// satisfies it.
type watchdogNotifier interface {
	NotifyWatchdog(kind string, sev notify.Severity, subject, detail string)
}

// wireWatchdogAlerts publishes the liveness gate's failing-probe alert
// (watchdog.db_probe_failing, watchdog.db_probe_recovered). Delivery reads
// the notification routes from the state store the failing probe runs on,
// so it runs on its own goroutine, one at a time, and drops an alert while
// earlier ones wait: the gate's log line is the record that always lands.
func (d *Daemon) wireWatchdogAlerts(ctx context.Context, ctrl *watchdog.Controller, n watchdogNotifier) {
	q := make(chan watchdog.DBProbeAlert, 4)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case a := <-q:
				kind, sev := "watchdog.db_probe_failing", notify.SevWarn
				if a.Recovered {
					kind, sev = "watchdog.db_probe_recovered", notify.SevInfo
				}
				n.NotifyWatchdog(kind, sev, d.cfg.HostName, a.Detail())
			}
		}
	}()
	ctrl.SetDBProbeAlert(func(a watchdog.DBProbeAlert) {
		select {
		case q <- a:
		default:
		}
	})
}

// startWatchdog builds the heartbeat's controller, wires it (owned: the
// shutdown ownership probe; wireWatchdog), and only then starts the
// heartbeat on it, continuing on the descriptor boot has been petting
// (bootUnderWatchdog) so the device is never closed between the two. The
// order is load-bearing: the heartbeat reads its wiring when it starts, and
// one started unwired would pet past this host's self-fence marker.
func (d *Daemon) startWatchdog(ctx context.Context, owned func() bool) *watchdog.Controller {
	ctrl := watchdog.NewController()
	ctrl.SetOwnershipCheck(owned)
	d.wireWatchdog(ctrl)
	d.watchdogCtrl = ctrl
	watchdog.StartHeartbeat(ctx, d.cfg.WatchdogDev, 0, ctrl, d.bootWatchdog.Handoff())
	return ctrl
}

// wirePauserLiveness adds the partition pauser's progress to the gate of
// the heartbeat startWatchdog started.
func (d *Daemon) wirePauserLiveness(pauser *health.PartitionPauser) {
	d.watchdogCtrl.SetPauserProgress(pauser.Progress)
}

// bootKeeperOptions are the boot keeper's bounds (watchdog.boot_keeper_*).
func bootKeeperOptions(cfg *Config) watchdog.BootOptions {
	return watchdog.BootOptions{
		RunDir:       watchdog.RunDir,
		Configured:   cfg.WatchdogDev != "",
		StreakWindow: time.Duration(cfg.Watchdog.BootKeeperStreakWindowSec) * time.Second,
		MaxBoots:     cfg.Watchdog.BootKeeperMaxBoots,
		MaxDuration:  time.Duration(cfg.Watchdog.BootKeeperMaxSec) * time.Second,
	}
}

// bootUnderWatchdog enforces the load-bearing boot order for the hardware
// watchdog: pet a timer a previous run left running FIRST, then boot.
//
// After a crash the timer counts from the crashed run's last pet (60 s with
// the default interval), and systemd restarts the unit 5 s later. Everything
// boot does before the heartbeat can be slow or fail on a full or read-only
// disk: opening the state store, the rollback check, the schema, the boot
// write. Petting only once the heartbeat started let a slow boot, or a crash
// loop failing in any of them, reboot the host and kill every VM on it.
//
// A boot that fails here abandons the keeper, which leaves the timer exactly
// as armed as the previous run left it. A boot that succeeds hands it to Run,
// which hands it to Heartbeat (or abandons it if Run fails first). Split out
// so the ordering is unit-tested without a live daemon.
func bootUnderWatchdog(
	keep func() *watchdog.BootKeeper,
	boot func(*watchdog.BootKeeper) (*Daemon, error),
) (*Daemon, error) {
	bk := keep()
	d, err := boot(bk)
	if err != nil {
		bk.Abandon()
		return nil, err
	}
	return d, nil
}

func newDaemon(cfg *Config, bootWatchdog *watchdog.BootKeeper) (*Daemon, error) {
	// Create HLC clock for this node
	clock := hlc.NewClock(cfg.HostName)

	// The gossip key is loaded before gossip starts: every stage but off refuses
	// to come up without one rather than join plaintext under a flag that says
	// otherwise.
	gossipKeys, err := gossipKeysFor(cfg)
	if err != nil {
		return nil, err
	}

	// Open embedded state store and join gossip cluster
	db, err := corrosion.NewClient(corrosion.Config{
		HostName:         cfg.HostName,
		DataDir:          cfg.DataDir,
		BindPort:         cfg.GossipPort,
		AdvertiseAddr:    cfg.AdvertiseAddress,
		JoinPeers:        cfg.JoinPeers,
		GossipEncryption: cfg.Enforcement.GossipEncryption,
		GossipKeys:       gossipKeys,
	}, clock)
	if err != nil {
		return nil, fmt.Errorf("state store: %w", err)
	}

	// Connect to libvirt
	virt, err := libvirt.NewClient()
	if err != nil {
		return nil, fmt.Errorf("libvirt: %w", err)
	}
	// The firmware move guard (fwmig) is in force before anything can start,
	// stop or redefine a domain, and is asked ahead of the start guard below.
	fwStore := libvirt.NewFirmwareStore(cfg.DataDir)
	fwmig.Wire(virt, fwStore)
	// No guarded VM starts before the per-NIC firewall is wired (re-review
	// R2-I2): after a host boots its nft tables are empty, and an onboot,
	// self-heal or restart-policy start would run its guest unguarded. Such a
	// start waits for SetStartGuard (Run), and refuses if it never comes. A
	// VM with no NIC guard does not wait (m3): it starts as it did before
	// guards. One whose guards cannot be read waits.
	startWaitSvc := &atomic.Pointer[grpcapi.Server]{}
	virt.RequireStartGuard(5*time.Minute, startWaitNeeded(db, func(name string) string {
		if svc := startWaitSvc.Load(); svc != nil {
			return svc.CreatingIncarnation(name)
		}
		return ""
	}))

	// An earlier build left the backup session directories 0777; narrow them
	// now rather than at the first backup (best effort, logged).
	libvirt.PrepareBackupRoots()

	// Image store
	store := image.NewStore(cfg.DataDir)
	if err := store.Init(); err != nil {
		return nil, fmt.Errorf("image store: %w", err)
	}

	return &Daemon{
		cfg:     cfg,
		db:      db,
		virt:    virt,
		fwStore: fwStore,
		images:  store,

		startWaitSvc:   startWaitSvc,
		bootWatchdog:   bootWatchdog,
		watchdogRunDir: watchdog.RunDir,
	}, nil
}

// Run starts all daemon services and blocks until context is cancelled.
// markRestarting flags this host 'upgrading' during a graceful shutdown so
// peers skip fence candidacy for the restart window, then waits briefly so the
// state replicates before the gRPC server stops serving. Best-effort and
// bounded — it must never block shutdown for long. The caller's ctx is already
// cancelled (SIGTERM), so this uses a fresh, short-lived context.
// localMaxRecvMsgSize is the largest response the in-process UI and REST clients
// will accept from the local daemon.
//
// gRPC defaults to 4 MiB. Both gateways serve `audit export`, and one page of
// that carries up to the server's default page of rows plus the evidence tables
// and the CA — comfortably past 4 MiB on a busy cluster. Left at the default the
// export fails at the gateway with a message-size error while the same call over
// `lv` (which raises its own limit) succeeds, so the failure reads as a broken UI
// rather than as a limit somebody chose. Matches the CLI's cliMaxRecvMsgSize.
const localMaxRecvMsgSize = 256 << 20

// writeBootState is the boot write: the state hostboot decides, with this
// build's version and resources, and — after a graceful stop or a crash of an
// active host — the check that records the host active once this daemon
// serves. A boot that does not await serving but follows one that never
// served checks too, so that once this daemon serves the next crash awaits
// serving again (hostboot.Served).
//
// A deferred boot (hostboot.Boot.Deferred: no evidence this daemon served
// since an earlier boot awaited it) makes no write at boot: the host keeps the
// state the cluster records, and the boot report is written with 'active'
// once this daemon serves (hostboot.ConfirmServingReport).
//
// A boot write decided from the recorded state (hostboot.Boot.From) is made
// only while the host is still recorded so, checked in the write's own
// transaction: a fence, drain or offline recorded between hostboot's read and
// this write is kept, and the boot report is written, keeping that state,
// once this daemon serves.
//
// On a WAL-quarantined daemon both writes are refused by the replicated write
// path, as every write is: the host stays as the cluster recorded it.
func (d *Daemon) writeBootState(ctx context.Context, cpus, memMiB, diskGiB int, hasResources bool) {
	d.writeBootStateWith(ctx, cpus, memMiB, diskGiB, hasResources, d.upgradePending, "")
}

// writeBootStateWith is writeBootState with the post-upgrade sentinel given:
// a boot passes d.upgradePending, the own-row reconcile false. expectFrom is
// the state the own-row reconcile acts over ("" for a boot): the decision is
// made only when it is taken from that state (Boot.From, which the write is
// guarded on in its own transaction), so a fence, drain or maintenance
// recorded after the reconcile's evaluation read the row is never returned
// to service. A refused decision leaves no trace on disk (hostboot.BootFiles).
func (d *Daemon) writeBootStateWith(ctx context.Context, cpus, memMiB, diskGiB int, hasResources, upgradePending bool, expectFrom string) {
	var files hostboot.BootFiles
	if expectFrom != "" {
		files = hostboot.SnapshotBootFiles(d.cfg.DataDir)
	}
	boot := hostboot.BootState(ctx, d.db, d.cfg.HostName, d.cfg.DataDir, upgradePending, time.Now())
	if expectFrom != "" && boot.From != expectFrom && (!boot.Deferred || boot.State != expectFrom) {
		slog.Info("boot report: this host's recorded state is not the one the own-row reconcile acts over; "+
			"writing nothing", "expected", expectFrom, "state", boot.State, "from", boot.From, "reason", boot.Reason)
		// No boot was written: the decision's marker, awaiting-serving note
		// and unclean-boot entry are undone, so nothing reads it as one.
		if err := files.Undo(); err != nil {
			slog.Warn("boot report: could not undo the refused decision's boot files", "error", err)
		}
		return
	}
	slog.Info("boot state", "state", boot.State, "await_serving", boot.AwaitServing, "deferred", boot.Deferred, "from", boot.From, "reason", boot.Reason)
	r := hostboot.Report{Version: d.cfg.Version, CPUs: cpus, MemMiB: memMiB, DiskGiB: diskGiB, HasResources: hasResources}
	reportOnServing := func(from string) confirmFunc {
		return func(ctx context.Context) (bool, string, error) {
			return hostboot.ConfirmServingReport(ctx, d.db, d.cfg.HostName, from, r)
		}
	}
	d.watchKeptFence(ctx, boot)
	if boot.Deferred {
		go d.awaitServingThenActivate(ctx, reportOnServing(boot.State))
		return
	}
	if beforeBootWrite != nil {
		beforeBootWrite()
	}
	var confirm confirmFunc
	returned := false
	if boot.Returning {
		var applied bool
		var err error
		if returned, applied, err = d.writeReturningBoot(ctx, boot, r); !returned {
			boot = boot.Fallback(err.Error())
			slog.Info("boot state", "state", boot.State, "from", boot.From, "reason", boot.Reason)
		} else {
			switch {
			case err != nil:
				slog.Warn("failed to write host startup state", "error", err)
				confirm = reportOnServing(boot.State)
			case !applied:
				slog.Warn("boot: this host's recorded state changed after the boot read it; leaving it, and reporting this boot once the daemon serves",
					"read", boot.From)
				confirm = reportOnServing(boot.State)
			}
		}
	}
	if returned {
		// Written through the release gate above.
	} else if boot.From != "" {
		applied, err := corrosion.UpdateHostStartupFrom(ctx, d.db, d.cfg.HostName, boot.From, boot.State, d.cfg.Version, cpus, memMiB, diskGiB, hasResources)
		switch {
		case err != nil:
			// Reported once this daemon serves, retried until it lands.
			slog.Warn("failed to write host startup state", "error", err)
			confirm = reportOnServing(boot.State)
		case !applied:
			slog.Warn("boot: this host's recorded state changed after the boot read it; leaving it, and reporting this boot once the daemon serves",
				"read", boot.From)
			confirm = reportOnServing(boot.State)
		}
	} else if err := corrosion.UpdateHostStartup(ctx, d.db, d.cfg.HostName, boot.State, d.cfg.Version, cpus, memMiB, diskGiB, hasResources); err != nil {
		slog.Warn("failed to write host startup state", "error", err)
	}
	switch {
	case boot.AwaitServing:
		go d.awaitServingThenActivate(ctx, confirm)
	case d.cfg.DataDir != "":
		if _, err := os.Lstat(hostboot.AwaitingPath(d.cfg.DataDir)); err == nil {
			go d.awaitServingThenNote(ctx)
		}
	}
}

// beforeBootWrite, when set, runs between hostboot's decision and the boot
// write. Tests only.
var beforeBootWrite func()

func (d *Daemon) markRestarting() {
	mctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	// hostboot leaves the marker that keeps the next boot 'upgrading' until it
	// serves, for an active host only: a fenced, offline or maintenance one
	// keeps its state.
	if err := hostboot.MarkRestarting(mctx, d.db, d.cfg.HostName, d.cfg.DataDir, time.Now()); err != nil {
		slog.Warn("shutdown: failed to mark host upgrading", "error", err)
		return
	}
	// Peers fence only after several accumulated health failures (~10s+), so a
	// short grace is enough for the 'upgrading' state to reach them first.
	time.Sleep(2 * time.Second)
}

// telemetryShutdownTimeout bounds every telemetry flush so a wedged collector
// can't stall daemon shutdown / a rolling upgrade past systemd's TimeoutStopSec.
const telemetryShutdownTimeout = 2 * time.Second

// armWatchdogThenSetupTelemetry enforces the load-bearing boot order: arm the
// post-upgrade watchdog FIRST, then run (possibly-blocking) telemetry setup, so a
// setup that hangs is still caught by the already-armed watchdog. Returns
// telemetry's shutdown func and setup error. Split out so the ordering invariant
// is testable without standing up a live daemon.
func armWatchdogThenSetupTelemetry(
	armWatchdog func(),
	setupTelemetry func() (func(context.Context) error, error),
) (func(context.Context) error, error) {
	armWatchdog()
	return setupTelemetry()
}

// boundedTelemetryShutdown flushes telemetry under a hard timeout. The returned
// shutdown honors context cancellation, so a slow/unreachable collector can't
// stall the flush past timeout. Safe with a nil shutdown (no-op).
func boundedTelemetryShutdown(shutdown func(context.Context) error, timeout time.Duration) error {
	if shutdown == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return shutdown(ctx)
}

// serverUnaryInterceptors is the daemon's unary chain, outermost first. The
// panic recovery comes first so a panic anywhere below it, an interceptor
// included, is answered Internal instead of ending the daemon
// (grpcapi.RecoverUnaryInterceptor).
func serverUnaryInterceptors(m *metrics.RPCMetrics, svc *grpcapi.Server) []grpc.UnaryServerInterceptor {
	return []grpc.UnaryServerInterceptor{grpcapi.RecoverUnaryInterceptor, m.UnaryInterceptor(), svc.UnaryAuthInterceptor}
}

// serverStreamInterceptors is serverUnaryInterceptors for streaming RPCs.
func serverStreamInterceptors(m *metrics.RPCMetrics, svc *grpcapi.Server) []grpc.StreamServerInterceptor {
	return []grpc.StreamServerInterceptor{grpcapi.RecoverStreamInterceptor, m.StreamInterceptor(), svc.StreamAuthInterceptor}
}

func (d *Daemon) Run(ctx context.Context) error {
	// Boot keeps a running watchdog petted until the heartbeat takes it over
	// below; a Run that returns before then leaves it armed (no-op after).
	defer d.bootWatchdog.Abandon()
	// qemu writes UEFI vars files with no flush and libvirt has no cache mode
	// for <nvram>: flush them from the first moment, so a host power cut
	// loses at most about a second of a guest's UEFI variable writes.
	nvramFlusher, stopNvramFlusher := d.startNvramFlusher(ctx)
	defer stopNvramFlusher()
	if err := d.checkMigrationNetwork(); err != nil {
		return err
	}
	// Boot order is load-bearing: arm the post-upgrade watchdog FIRST, then run
	// telemetry setup (which can block on a slow/unreachable collector — production
	// sets none of the PROVIDE_*_TIMEOUT caps). If setup ran first and hung, a
	// boot-hang would never roll back. Extracted to a helper so the ordering is
	// unit-tested without a live daemon (see daemon_telemetry_test.go). Fail-open:
	// a setup error degrades to local logging and never blocks boot.
	// Assigned BEFORE the watchdog is armed: startUpgradeWatchdog (below) can
	// spawn a goroutine that calls exit() while Setup is still running (or
	// hung), so this field must never be nil/racing at that point. It reads
	// telemetryShutdown — set at the bottom of this block, once Setup
	// returns — via atomic.Pointer, so the closure itself is safe to assign
	// once and call at any time; a call before Setup completes is a safe
	// no-op instead of a lost-rollback-telemetry bug. Finding 7.
	d.flushTelemetry = func() {
		if fn := d.telemetryShutdown.Load(); fn != nil {
			_ = boundedTelemetryShutdown(*fn, telemetryShutdownTimeout)
		}
	}
	shutdownTelemetry, terr := armWatchdogThenSetupTelemetry(
		func() { d.startUpgradeWatchdog(ctx) },
		func() (func(context.Context) error, error) {
			return obs.Setup(ctx, obs.Config{
				ServiceName:  "litevirt",
				Version:      d.cfg.Version,
				Environment:  d.cfg.Telemetry.Environment,
				HostName:     d.cfg.HostName,
				OTLPEndpoint: d.cfg.Telemetry.OTLPEndpoint,
				SampleRate:   d.cfg.Telemetry.SampleRate,
				LogLevel:     d.cfg.Telemetry.LogLevel,
				LogFormat:    d.cfg.Telemetry.LogFormat,
			})
		},
	)
	if terr != nil {
		slog.Warn("telemetry setup degraded to local logging", "error", terr)
	}
	d.telemetryShutdown.Store(&shutdownTelemetry)
	// Every telemetry flush is bounded (abnormal os.Exit path and normal defer
	// alike) so a wedged collector can't stall graceful stop / a rolling upgrade
	// past systemd's TimeoutStopSec into SIGKILL.
	defer func() { _ = boundedTelemetryShutdown(shutdownTelemetry, telemetryShutdownTimeout) }()
	// Wire tracing dial options into every pki.PeerDial caller (including the
	// corrosion replicator/anti-entropy dials, which pass none of their own —
	// finding 8), now that obs.Setup has resolved whether tracing is active.
	// Safe here: replication/anti-entropy start later in this method.
	pki.SetTraceDialOptions(obs.ClientDialOptions)

	// Finish or repair a host certificate renewal a crash interrupted
	// (pki/hostswap.go), before anything reads host.crt/host.key. A pair that
	// already loads is left alone.
	if _, err := pki.RecoverHostIdentity(d.cfg.PKIDir, d.cfg.HostName); err != nil {
		slog.Error("the host identity does not load and could not be recovered", "error", err)
	}

	// Pre-flight: refuse to start under a systemd unit that would kill
	// child QEMU processes on stop. See preflight.go for the rationale.
	if err := preflightUnitCheck(); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	// Pre-flight: if watchdog self-fencing is configured, refuse to start with a
	// missing/unusable device so we don't discover it only at fence time.
	if err := preflightWatchdog(d.cfg.WatchdogDev); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	// Pre-flight: detect that this binary is a rollback below a capability token
	// this node already latched. Deliberately NOT fatal. Exiting non-zero here
	// would, under the unit's OnFailure rollback, be a rollback loop; and the node
	// has to stay up anyway so peers can see it degraded and an operator can reseed
	// it. Fail-closed happens at the write path instead, wired below.
	// Release probation (C1): rolled back below a safe_if_unused release token
	// with no use in this replica. No replicated writes until a voter majority
	// confirms (RunReleaseProbation, below).
	if toks := BootRollbackCheck(ctx, d.cfg.DataDir, d.db); len(toks) > 0 {
		d.rolledBackTokens = toks
		slog.Error("preflight: this binary is a ROLLBACK below capability tokens this node "+
			"already latched; entering WAL quarantine — no replicated writes will be emitted "+
			"until this node is upgraded again or reseeded by an operator",
			"tokens", toks)
	}
	// Install the quarantine before InitSchema so nothing this daemon does can
	// emit. Local-only execs (schema DDL, replication apply) stay open by design,
	// so a reseed still works.
	d.db.SetWriteQuarantine(func() string {
		if len(d.rolledBackTokens) == 0 {
			return ""
		}
		return "rolled back below latched token(s): " + strings.Join(d.rolledBackTokens, ",")
	})

	// Initialize corrosion schema
	if err := corrosion.InitSchema(ctx, d.db); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}
	// Record, once, whether this node held users rows before anything could
	// replicate in: the positive evidence an external-realm login needs on a
	// node that is not credentials-live yet (corrosion/credentials_live.go).
	if err := d.db.NoteCredentialsBaseline(ctx); err != nil {
		return fmt.Errorf("record the credentials baseline: %w", err)
	}

	// Derive the cluster record from this node's CA if the cluster has none.
	// Presence-gated and idempotent — see corrosion.EnsureClusterRecord for why
	// it is derived rather than minted, and why it never rewrites a row.
	d.ensureClusterRecord(ctx)

	// Hold this host's audit rows while its own chain is still arriving, before
	// anything can write one. Only a host re-added under an old name, whose
	// CA-signed admission record (pki_dir/audit-rejoin.json, written by
	// `lv host add`) names history this replica does not have yet, holds: a
	// normal restart and a brand-new name never do. Without it a rebuilt host
	// chains its first rows onto an empty tail and forks its chain for good
	// (corrosion/audit_hold.go). Rows held across a restart are in the spool and
	// land first.
	d.configureAuditHold(ctx)
	// Whether this replica holds the cluster's history, decided once per
	// state.db: an existing member is seeded at its first start on this build;
	// a fresh replica becomes seeded at genesis or by an exchange with a seeded
	// peer (corrosion/audit_seeded.go). AdmitHost vouches only when seeded.
	if _, err := corrosion.DecideAuditSeeded(ctx, d.db, d.cfg.HostName); err != nil {
		slog.Error("could not decide whether this replica is seeded; it is treated as NOT seeded and "+
			"does not vouch for audit chain positions until an exchange with a seeded peer", "error", err)
	}
	go d.runAuditSeeded(ctx)

	// Before anything that writes an audit row is built: every writer signs with
	// the keyring this installs on d.db.
	d.wireAuditKeyring(ctx)

	// An operator's seeded assertion is audited here, signed, exactly once: not
	// in DecideAuditSeeded, which runs before the keyring exists.
	if err := corrosion.RecordAuditSeededAssertion(ctx, d.db, d.cfg.HostName); err != nil {
		slog.Error("could not audit this replica's seeded assertion; retried at the next start",
			"error", err)
	}

	// After the keyring: rows an earlier process left in the spool may land on
	// the first poll, and landed before it they would be written unsigned
	// (runAuditHold also waits for the wiring, whatever the order here).
	go d.runAuditHold(ctx)

	// Re-base THIS host's audit sub-chain at startup — but ONLY when it is
	// still entirely unsigned.
	//
	// This used to run unconditionally, and that was the single biggest hole in
	// the audit log's tamper-evidence: reseal recomputes hashes from whatever
	// the rows currently say, so an attacker with database write access could
	// edit a row, wait for (or cause) a restart, and have the daemon itself
	// rewrite the chain around the edit. `lv audit verify` then came back clean.
	//
	// Reseal now exists solely to heal rows written under the old global-chain
	// model, which were never tamper-evident to begin with. Once a host has any
	// signed row, its chain is verified rather than repaired: a hash that does
	// not recompute is a FINDING, and rewriting it would destroy the only
	// evidence that anything happened. resealHostChainLocked enforces the same
	// rule per row, in the SQL as well as in Go, because the statement
	// replicates.
	if signed, err := corrosion.HostHasSignedAuditRows(ctx, d.db, d.cfg.HostName); err != nil {
		slog.Warn("could not determine audit chain signing state", "error", err)
	} else if signed {
		slog.Debug("audit: chain is signed; skipping the legacy reseal", "host", d.cfg.HostName)
		d.db.NoteAuditResealNotNeeded(d.cfg.HostName)
	} else if n, err := corrosion.ResealAuditChain(ctx, d.db, d.cfg.HostName); errors.Is(err, corrosion.ErrAuditChainNotCaughtUp) {
		// A rebuilt host whose history has not arrived: a reseal of a partial
		// replica would rewrite rows its peers hold intact.
		slog.Info("audit: skipping the legacy reseal while this host's audit history is still arriving",
			"host", d.cfg.HostName)
	} else if err != nil {
		// Logged, not fatal. Until a reseal succeeds the legacy tail is not
		// anchored (corrosion.ErrAuditAnchorWithheld): an anchor over the
		// un-rebased tail would read as a truncation once it is rebased.
		slog.Warn("audit chain reseal at startup failed; the legacy chain is not anchored until a restart reseals it", "error", err)
	} else if n > 0 {
		slog.Info("audit: re-based legacy unsigned rows at startup",
			"host", d.cfg.HostName, "rows", n)
	}

	// Repair any private key this node holds that other local users can read.
	//
	// Unconditional, because the damage was: `lv host init root@<host>` pushed
	// host.key mode 0644 on every node it provisioned, and host.key is the
	// peer-mTLS identity — any local user on such a node could impersonate it to
	// the cluster. The push path is fixed, but nobody re-provisions an existing
	// cluster, so a repair at start is the only thing that reaches one. It used
	// to hang off enforcement.audit_signature, which then defaulted to false, so an
	// operator who upgraded specifically for this fix got neither the repair nor
	// a warning.
	if err := pki.TightenPrivateKeys(d.cfg.PKIDir); err != nil {
		slog.Error("a private key in the PKI directory is readable by other local users and "+
			"could not be tightened", "error", err)
	}
	// And the config file, which can hold inline auth secrets: owner-only, as
	// `lv host add` writes it, on a node upgraded in place too.
	d.tightenOwnConfig()

	// Set up libvirt TLS symlinks so qemu+tls:// migration works
	// using our existing PKI certs. Best-effort — log warning if it fails.
	if err := pki.SetupLibvirtTLS(d.cfg.PKIDir); err != nil {
		slog.Warn("failed to set up libvirt TLS certs", "error", err)
	}

	// Seed admin user on first start (if no users exist).
	if err := d.seedAdminUser(ctx); err != nil {
		slog.Warn("failed to seed admin user", "error", err)
	}

	// seed the built-in RBAC roles (Admin, Operator, Viewer,
	// Auditor, BackupOperator, NetworkAdmin, VMOperator, NoAccess) and
	// initialize the auth engine. The engine reloads on daemon start, then
	// mid-run: local grants reload synchronously, local revokes/deletes apply
	// in-memory deltas, and runAuthEngineReload (below) is the ~30s backstop
	// that picks up peer-replicated mutations.
	if err := auth.SeedBuiltinRoles(ctx, d.db); err != nil {
		slog.Warn("failed to seed built-in roles", "error", err)
	}
	d.authEngine = auth.NewEngine(d.db)
	if err := d.authEngine.Reload(ctx); err != nil {
		slog.Warn("failed to load role bindings", "error", err)
	}

	// build the realm registry from auth.realms YAML. The
	// "local" realm is always installed by BuildRegistry; OIDC/LDAP
	// realms come from config. A realm that fails to construct (e.g.
	// OIDC issuer unreachable at startup) downgrades to a warning so
	// the daemon can still serve local-only Logins; the operator gets
	// to see the error and fix the config without the daemon refusing
	// to start.
	registry, err := auth.BuildRegistry(ctx, d.db, d.cfg.Auth.Realms)
	if err != nil {
		slog.Warn("auth.realms config failed; falling back to local-only", "error", err)
		registry = auth.NewRegistry()
		registry.Register(auth.NewLocalRealm(d.db))
	}
	d.realmRegistry = registry
	if names := registry.Names(); len(names) > 0 {
		slog.Info("auth realms ready", "realms", names)
	}

	// The membership split gate goes in BEFORE this host's first write. The
	// boot state below is a state write, and on a node that has already split
	// it must reach host_membership too. Written to hosts.state alone, this
	// node's own host_membership row would miss it until anti-entropy.
	d.wireHostMembershipGate()
	d.wireHostMembershipRetireGate()
	// Likewise the runtime split gate: the boot report below is a runtime
	// write, and on a node that has already split it must reach host_runtime.
	d.wireHostRuntimeGate()
	d.wireHostRuntimeRetireGate()

	// The own-row hold goes in before this host's first own-row write
	// (corrosion/own_row_hold.go).
	d.configureOwnRowHold(ctx)
	// Register this host in corrosion
	if err := d.registerHost(ctx); err != nil {
		slog.Warn("failed to register host", "error", err)
	}
	// And correct the address if it has changed since the row was created —
	// registerHost is an INSERT, so it cannot.
	if err := d.reconcileHostAddress(ctx); err != nil {
		slog.Warn("could not reconcile this host's recorded address", "error", err)
	}
	// Write boot state in ONE batched mutation: state + version (+ resources if the
	// probe succeeded) share a single updated_at. Doing these as separate writes in
	// the same wall-clock second produced equal updated_at values, and on a peer the
	// later writes lost the LWW tie and were stranded (a re-exec upgrade's new
	// version never propagated). InsertHost is a no-op if the row already exists, so
	// this explicit write is what carries the new state/version after a re-exec.
	cpus, memMiB, niErr := d.virt.NodeInfo()
	diskGiB := 0
	if niErr == nil {
		diskGiB = d.sumPoolDiskTotalGiB(ctx)
	} else {
		slog.Warn("NodeInfo failed at startup; writing host state without resources", "error", niErr)
	}
	// On an upgrade boot, stay "upgrading" until the watchdog confirms local gRPC
	// is healthy (it flips to "active"); version + resources are still written
	// here either way so the new version propagates immediately. After a
	// graceful stop (SIGTERM), or a crash of an active host, the host likewise
	// stays "upgrading" until this daemon answers its own Ping
	// (awaitServingThenActivate): recorded active
	// before its gRPC server listened, it was fenced on the failure count its
	// observers carried through the restart (hostboot).
	d.bootRes.mu.Lock()
	d.bootRes.cpus, d.bootRes.memMiB, d.bootRes.diskGiB, d.bootRes.hasResources = cpus, memMiB, diskGiB, niErr == nil
	d.bootRes.mu.Unlock()
	d.checkerThenBootWrite(ctx, cpus, memMiB, diskGiB, niErr == nil)
	go d.runOwnRowHold(ctx)
	// Record version on the corrosion client so it goes into Crescent
	// peer handshakes (used by skew detection).
	d.db.SetLocalVersion(d.cfg.Version)

	// Register storage pools in the cluster DB and start periodic refresh.
	// Their statfs and path resolutions are bounded (poolStatfs,
	// storage.Bounded). The in-place hardening of an NFS mount runs a remount
	// command, and is waited for only up to startupStepBound
	// (startup_bound.go).
	d.registerStoragePools(ctx)
	awaitStartupStep("harden NFS pool mounts", startupStepBound, func() { d.hardenNFSPoolMounts(ctx) })
	d.refreshDBPoolCapacity(ctx)
	go d.refreshStoragePools(ctx)

	// Install the anti-entropy timing sink on the Client BEFORE starting the
	// replicator / anti-entropy loops (and the gRPC server) that read it — the
	// field is set-once-then-read, so wiring it here establishes happens-before
	// and avoids a data race with those goroutines. It lives on the Client so
	// dumps served directly through grpcapi (DumpStateBytes / StreamStateDump)
	// are observed too.
	d.db.SetSyncMetrics(metrics.NewAntiEntropyMetrics())

	// The host health checker was created (above, before the boot write) BEFORE
	// the replicator so the proof-table WAL gate is installed before any
	// replication goroutine runs (a nil gate fails closed, but wiring it up front
	// means no reliance on that), with the durable split-brain activation latch
	// loaded before any runtime work is wired, so a previously-enforced node that
	// restarts (including mid-partition) gates onboot VM starts / LB (re)apply
	// instead of running them ungated. (Peer capability is wired later via
	// SetPeerPinger; until then PeerSupports fails closed, so proof WAL entries
	// defer rather than leak — never a schema-version guess.)
	gateMetrics := metrics.NewRuntimeGateMetrics()      // shared by all gate observers
	stateWriteMetrics := metrics.NewStateWriteMetrics() // shared by all state-write observers

	// Start WAL-based replicator with Crescent relay protocol.
	// One relay election for both the replicator and anti-entropy, whose
	// scheduled pass always contacts this node's relays.
	relayCfg := corrosion.RelayConfig{
		BaseRelays:      3,
		NodesPerRelay:   50,
		FallbackTimeout: 15 * time.Second,
	}
	repl := corrosion.NewReplicator(d.db, d.cfg.PKIDir, relayCfg)
	// Token-based (fresh-Ping-cached) gate for proof-table WAL replication, wired
	// BEFORE Start: only send runtime_action_proofs mutations to a peer that
	// advertises the gate. Fail-closed until SetPeerPinger (below) — proofs defer.
	repl.SetProofReplicaGate(func(ctx context.Context, peer string) bool {
		return d.checker.PeerSupports(ctx, peer, capabilities.SplitBrainGateV1)
	})
	// LWW future-skew quarantine (partial): enabled only once LWWSkewGuardV1 has
	// latched on this node (cheap marker read, no ping/I/O), so a future-skewed peer's
	// rows can't win a conflict. The token is advertised, so enforcement is gated on the
	// enforcement.lww_skew_guard config flag AND the latch — behavior-neutral until an
	// operator enables it (and the flag is the reversible kill switch).
	// NOTE: does not address the backward-clock case (NowTS still emits wall-clock) —
	// that's deferred to a separate conflict-key migration.
	d.db.SetHLCSkewGuard(func() bool {
		// Config kill-switch AND the latched capability (the HA monitor drives the
		// latch while healthy). Latched (not Enforced) keeps this merge-hot-path read
		// off any peer dial.
		return d.cfg.Enforcement.LWWSkewGuard && d.checker.Latched(capabilities.LWWSkewGuardV1)
	})
	// Emit the LWW conflict key (updated_at) as HLC instead of RFC3339Nano once
	// enforcement.hlc_lww is set AND the token has latched cluster-wide (the HA monitor
	// drives the latch while healthy). Cheap Latched read on the per-write path; the
	// instant-based comparator makes the RFC3339↔HLC switch and a flag-off rollback safe.
	d.db.SetHLCEmit(func() bool {
		return d.cfg.Enforcement.HLCLww && d.checker.Latched(capabilities.HLCLwwV1)
	})
	// Emit the order-invariant digest_v2 hashes unless enforcement.digest_v2 is
	// explicitly off (it defaults on). No capability latch: v2 is negotiated PAIRWISE by wire-field presence (each node emits
	// v2 only when locally enabled; two peers compare v2 only when both emitted it), so a
	// non-uniform rollout only affects which node initiates a pull, never a decision.
	d.db.SetDigestV2Enabled(func() bool { return d.cfg.Enforcement.DigestV2 })
	// Resolve the natural-key identity tables (snapshots, container_snapshots) by their UNIQUE
	// natural key once enforcement.canonical_identity is set AND the token has latched
	// cluster-wide. Unlike digest_v2 this is NOT pairwise-negotiated — identity resolution
	// mutates shared state, so a per-sender flip would be non-convergent; it must be
	// fleet-uniform, which the cluster-wide latch guarantees. Cheap Latched read (no peer dial)
	// on the merge/apply hot path; the config flag is the reversible kill switch.
	d.db.SetCanonicalIdentity(func() bool {
		return d.cfg.Enforcement.CanonicalIdentity && d.checker.Latched(capabilities.CanonicalIdentityV1)
	})

	d.wireCorrosionGates()

	// Migrate legacy unscoped network names to stack-scoped names. After the
	// gates: its VM spec rewrites are desired-spec edits, which carry their
	// owner epoch once spec_conflict_v1 has latched, so receivers order them
	// by generation rather than by the row clock.
	if err := corrosion.MigrateLegacyNetworkNames(ctx, d.db); err != nil {
		slog.Warn("failed to migrate legacy network names", "error", err)
	}

	// Apply a replicated guarded VM-name replacement once vm_replace_v1 is DURABLY
	// LATCHED. Durable, not Latched or the config flag: a replace batch already on
	// the wire must not become unacceptable across a restart — a node that latched
	// only in memory would reload no marker and refuse it — or it stalls that
	// sender's stream forever.
	d.db.SetVMReplaceAccept(func() bool {
		return d.checker.DurablyLatched(capabilities.VMReplaceV1)
	})
	// Every push declares this build's release tokens from the first one
	// (I-R2-2): the server, which wires the live advertisement, is built later,
	// and a push that declared nothing would be refused by every peer with a
	// release feature in use.
	repl.SetAdvertisedCapabilities(capabilities.ReleaseTokens)
	repl.Start(ctx)

	// Audit key lifecycle, deferred until replication is running.
	//
	// Adoption and retirement both record a SEQUENCE, and both are permanent:
	// records are append-only and the strictest verified value wins, so a boundary
	// taken from a local tail that is behind the cluster can never be corrected.
	// Running this before the replicator meant a rebuilt or snapshot-restored node
	// pinned its contract start — or its predecessor's retirement — below its own
	// real history, and every row in the gap became a permanent finding on every
	// node the moment anti-entropy delivered it.
	go d.finishAuditKeyLifecycle(ctx)

	// Fold what `lv user reset-admin` journalled while this daemon could not be
	// reached, signed and at the time it happened (corrosion/pending_audit.go).
	go d.runPendingAuditFold(ctx)

	// Move the secret columns onto the sensitive lane once credentials_split_v1
	// has durably latched, and empty them once credentials_clear_v1 has too.
	// Inert until then; see corrosion.SplitCredentials.
	go d.runCredentialsSplit(ctx)

	// Give host state and isolation their own row once host_membership_split_v1
	// has durably latched. Inert until then; see corrosion.SplitHostMembership.
	go d.runHostMembershipSplit(ctx)

	// Give the host's own reports (version, schema version, resource totals)
	// their own row once host_runtime_split_v1 has durably latched. Inert
	// until then; see corrosion.SplitHostRuntime.
	go d.runHostRuntimeSplit(ctx)

	// Restore "at least one live admin" after racing deletes on two nodes
	// (corrosion/admin_floor.go).
	go d.runAdminFloor(ctx)

	// Start anti-entropy (periodic digest comparison + full sync as safety net).
	// Interval is operator-configurable (anti_entropy_interval_sec); 0 → 60s
	// default inside NewAntiEntropy. (P2-2)
	ae := corrosion.NewAntiEntropy(d.db, d.cfg.PKIDir, time.Duration(d.cfg.AntiEntropyIntervalSec)*time.Second)
	ae.SetRelayConfig(relayCfg)
	ae.SetLegacyRepair(d.cfg.AntiEntropyLegacyRepair)
	go ae.Start(ctx)
	// Release probation (entered only from a marker at boot) is lifted only by
	// asking a voter majority.
	go RunReleaseProbation(ctx, d.db, ae)

	// Start metrics server. Create the LXC runner ONCE here and share it with the
	// gRPC container adapter + health checker below, so the metrics collector can
	// also read live container cgroup usage (host-local, no RPC).
	lxcRunner := lxc.NewLxcRunner()
	lxcRunner.HostName = d.cfg.HostName
	lxcRunner.DefaultPidsMax = d.cfg.Containers.DefaultPidsMax
	lxcRunner.IDMappedRootfs = d.cfg.Containers.IDMappedRootfs
	lxcRunner.HostAccess = d.cfg.Containers.hostAccess(d.cfg.DataDir, d.cfg.PKIDir)
	lxcRunner.HostAccess.Deny = append(lxcRunner.HostAccess.Deny, d.storeDenyStatic()...)
	lxcRunner.HostAccess.DenyFunc = d.storeDenyDynamic
	lxcRunner.HostAccess.BlockInUse = d.vmDiskBlockInUse
	// In the background: it stats every protected tree, backup repos
	// included, and one of those may be on an NFS mount whose server does not
	// answer (startup_bound.go).
	go func(ha lxc.HostAccess) { d.noteHostAccessOverlaps(ctx, lxc.HostAccessOverlaps(ha)) }(lxcRunner.HostAccess)
	go refreshHookPolicies(ctx, lxcRunner)
	// What a crash left of a recreate's image fetch, and of a pull replacing
	// an OCI library item: before any create can read either.
	if err := lxcRunner.SweepFetchDir(); err != nil {
		slog.Warn("container image fetch: could not clear what an earlier run left staged", "error", err)
	}
	if err := lxc.RecoverOCILibrary(filepath.Join(d.cfg.DataDir, storage.OCILibraryDir)); err != nil {
		slog.Warn("oci library: could not finish what an interrupted pull left", "error", err)
	}
	lxcRunner.SubIDSpan = &lxc.IDMap{Base: d.cfg.Containers.IDMapBase, Size: int64(d.cfg.Containers.IDMapRanges) * lxc.IDMapSize}
	d.metrics = metrics.NewServer(d.cfg.MetricsPort, d.cfg.MetricsBind, d.db, d.virt, lxcRunner, d.cfg.HostName)
	d.metrics.SetReplicationTargets(repl.Targets)
	d.metrics.SetRelayRoles(repl.RelayRoles)
	d.metrics.SetParkedEntries(repl.ParkedCounts)
	// metrics_port: 0 DISABLES the endpoint, matching rest_port below and what
	// docs/configuration.md says about it. Without the guard, 0 composed ":0"
	// and bound an EPHEMERAL port on every interface — an unauthenticated
	// inventory endpoint on an unpredictable port, which is the opposite of
	// what an operator setting 0 is asking for, and the exposure warning then
	// named port 0, so the one datum needed to firewall it was useless.
	if d.cfg.MetricsPort > 0 {
		go d.metrics.Start()
	} else {
		slog.Info("metrics endpoint disabled (metrics_port: 0)")
	}

	// Start the host health checker (created above, before the replicator).
	go d.checker.Start(ctx)

	// One capacity policy shared by admission (svc below), failover, and the
	// rebalancer, so placement and admission can never disagree.
	capacity := d.cfg.Capacity.Policy()

	// Create the failover coordinator; started after the gRPC server is built
	// so its replica-promoter (auto_promote recovery) can be wired first.
	fc := failover.NewCoordinator(d.cfg.HostName, d.db)
	fc.SetCapacityPolicy(capacity)
	// The relay-health floor is the replicator's own BaseRelays.
	fc.RelayConfig = relayCfg

	// Start snapshot scheduler. Leader-gated like the
	// rebalancer; the runner is wired below once the gRPC Server is
	// constructed (it reuses lockVM + pickDisk).
	d.snapScheduler = scheduler.NewSnapshotScheduler(d.db, d.cfg.HostName, nil /* runner set after server build */)

	// Create the VM health checker (event bus wired after gRPC server is created
	// below). Gate restart-policy starts on local quorum (once enforced). The sweep
	// loop is NOT started here — it launches below, only after the full gate
	// (SetPeerPinger) and its callbacks are wired, so a gated runtime start never
	// runs in a window where capability can't yet be confirmed.
	vmChecker := health.NewVMChecker(d.cfg.HostName, d.cfg.DataDir, d.db, d.virt)
	vmChecker.SetGate(d.checker)
	vmChecker.SetGateRefusedObserver(gateMetrics.Refused)
	vmChecker.SetStateWriteFailObserver(stateWriteMetrics.Failed)

	// Start libvirt reconnect loop — auto-reconnects if libvirtd restarts (#42).
	go d.virt.StartReconnectLoop(ctx)

	// Can this host's QEMU do a VNC console password? A FIPS-mode host has no
	// DES for VNC authentication and would refuse every passworded start, so
	// it sets none and reports console_password_v1 in not_enforcing
	// (docs/ui.md "Console passwords"). Asynchronous: until it answers, a
	// refused start is still caught by the start backstop.
	if reason := libvirt.SpiceUnusableReason(); reason != "" {
		slog.Warn("SPICE consoles cannot connect on this host; VMs still run and VNC still works", "reason", reason)
	}
	go func() {
		defer d.virt.MarkVNCProbed()
		if reason := libvirt.ProbeVNCPassword(ctx); reason != "" {
			d.virt.SetVNCPasswordUnavailable(reason)
			slog.Warn("this host cannot give VNC consoles a password; they stay open here (SPICE keeps its own)",
				"reason", reason)
		}
	}()

	// Register domain event callback for immediate VM death detection (#44).
	eventHandler := health.NewDomainEventHandler(d.cfg.HostName, d.db)
	eventHandler.SetStateWriteFailObserver(stateWriteMetrics.Failed)
	d.virt.RegisterDomainEventCallback(eventHandler.Callback(ctx))

	// Create the VM reconciler (picks up "pending" VMs from failover and starts
	// them). Wire the split-brain gate now, but DON'T start the reconcile loop or
	// onboot autostart yet — they launch below, after SetPeerPinger and the
	// reconciler's callbacks (LB refresh, image pull, firmware paths) are wired, so
	// an isolated/latched restart can't run automated starts before the gate can
	// confirm capability.
	reconciler := health.NewReconciler(d.cfg.HostName, d.cfg.DataDir, d.db, d.virt)
	// One memory snapshot capture registry per host: the gRPC server's
	// captures, the partition pauser and the settle share it.
	d.captureReg = libvirt.NewCaptureRegistry()
	reconciler.SetCaptureRegistry(d.captureReg) // a settle drops the pauser's hold with its record
	reconciler.SetGate(d.checker)
	reconciler.SetOwnerEpochBackfill(d.cfg.Enforcement.OwnerEpoch) // Phase 4 backfill pass
	// Unconditional: the out-of-band stop sync waits until this node's replica
	// has caught up with a peer (anti-entropy, above) since start / last rejoin.
	reconciler.SetReplicaFreshness(d.db.ReplicaCaughtUp)
	reconciler.SetGateRefusedObserver(gateMetrics.Refused)
	reconciler.SetStateWriteFailObserver(stateWriteMetrics.Failed)
	reconciler.SetSharedStorageFenceEnforce(d.cfg.Enforcement.SharedStorageFence) // shared-disk transfer fence kill-switch

	// Daily prune of this host's vm_events rows so the operational event store
	// stays bounded (see config vm_event_*).
	go d.runVMEventPrune(ctx)

	// Hourly local GC of superseded/orphaned auth + LB rows (re-enroll / LB-recreate
	// churn). Local-only deterministic deletes — runs on every node.
	go d.runSupersededGC(ctx, metrics.NewGCMetrics())

	// Hourly removal of the disk copies a failover start set aside here, once
	// past superseded_disk_retention_days (health/superseded_retention.go).
	go d.runSupersededDiskSweep(ctx)

	// A UEFI vars file whose flush failed is a host condition
	// (nvram_flush_failed); the flusher itself started with Run.
	go d.runNvramFlushCondition(ctx, nvramFlusher)

	// Sample this host's aggregate disk/net rates into host_runtime_usage for the
	// placement engine's DiskIOPS/NetBW dimensions.
	go d.runRuntimeUsageSampler(ctx)

	// Backstop reload of the RBAC engine so peer-replicated role/binding
	// mutations take effect without a restart (local grants/revokes already
	// apply synchronously via reload/delta in the handlers).
	go d.runAuthEngineReload(ctx)

	// Install any cluster CRL this node is missing. Removing a host revokes its
	// certificate, and a revocation that never arrives is a decommissioned node
	// still holding a working peer credential.
	go d.runCRLSync(ctx)

	// Keep the live gossip keyring in step with pki_dir/gossip.key, and report
	// what it is using to pki_dir/gossip-keyring.state — the barrier
	// `lv host rotate-gossip-key` waits on between phases. Runs when gossip
	// encryption is off too, so the rotate and install commands can tell an
	// off node from one that never started.
	go d.db.WatchGossipKeyFile(ctx,
		filepath.Join(d.cfg.PKIDir, pki.GossipKeyName),
		filepath.Join(d.cfg.PKIDir, pki.GossipKeyringStateName),
		gossipKeyReloadInterval)

	// Publish this host's signed audit chain head periodically and at shutdown.
	// Nothing else can detect a truncated tail: the hash chain links backward,
	// so removing the last N rows leaves every surviving link verifying.
	go d.runAuditChainHeads(ctx)

	// Verify this node's view of the audit chain on a schedule and publish the
	// result. A check that only runs when an operator asks for it finds an
	// intrusion after the incident that prompted them to look.
	go d.runAuditChainVerify(ctx)

	// Start embedded DNS server, and tell the network layer to chain per-bridge
	// dnsmasq instances to it for the litevirt domain so guests can resolve
	// VM/container/anycast names (SetLocalResolver must precede network provisioning).
	dnsSrv := dns.NewServer(d.cfg.DNSDomain, d.cfg.DNSPort, d.db)
	network.SetLocalResolver(d.cfg.DNSDomain, d.cfg.DNSPort)
	go dnsSrv.Start(ctx)

	// Start hardware watchdog heartbeat (optional). The controller lets Phase-2 VIP
	// self-demotion trip a self-fence when a demotion can't be confirmed.
	// Clean-shutdown disarm hole (§B Phase 5): only a host that owns nothing may
	// disarm on SIGTERM. A restart re-pets inside the timeout; a stop that
	// abandons running workloads lets the watchdog reboot the host into a safely
	// fenced state. Probe errors count as NOT owned — the probe runs through the
	// same clients the daemon manages workloads with, so a host that cannot
	// answer is overwhelmingly one with no runtime at all (containers-only or
	// fresh hosts must not reboot on every daemon stop). VIP ownership is not
	// yet probed here — Phase 5 adds it with the quorum-gated handoff.
	watchdogCtrl := d.startWatchdog(ctx, func() bool {
		if names, err := d.virt.ListRunningDomains(); err == nil && len(names) > 0 {
			slog.Warn("watchdog: refusing shutdown disarm — running VMs owned", "count", len(names))
			return true
		}
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer probeCancel()
		if names, err := lxcRunner.ListRunning(probeCtx); err == nil && len(names) > 0 {
			slog.Warn("watchdog: refusing shutdown disarm — running containers owned", "count", len(names))
			return true
		}
		return false
	})
	// Central self-fence hard gate: once this node self-fences, the checker's Execution/
	// DecisionGate fail closed regardless of quorum, so every gate consumer (reconciler,
	// grpcapi server, failover coordinator) refuses runtime-ownership work during the
	// doomed fence-timeout window.
	d.checker.SetSelfFenced(watchdogCtrl.Fenced)

	// PCI device startup scan
	d.runPCIScan(ctx)

	// Start periodic PCI rescan timer (if configured).
	if interval := d.parsePCIRescanInterval(); interval > 0 {
		go d.runPeriodicPCIScan(ctx, interval)
	}

	// Ensure libvirt storage pools exist. libvirtd may stat a pool's
	// directory to define or refresh it, and block on an NFS server that does
	// not answer: waited for only up to startupStepBound.
	awaitStartupStep("ensure libvirt storage pools", startupStepBound, d.ensureStoragePools)

	// Start gRPC server with mTLS
	tlsCfg, err := pki.ServerTLSConfig(d.cfg.PKIDir)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}

	svc := d.newServer() // host address and release gate: before the first network pass
	svc.SetCaptureRegistry(d.captureReg)
	// A guarded VM recovers only onto a host that enforces NIC guards until
	// every host does (re-review m8).
	fc.SetNICGuardPlacement(svc.GuardHostNeeded)
	d.svc = svc
	d.wireWatchdogAlerts(ctx, watchdogCtrl, svc)
	// Managed fence SSH (internal/fencessh): this host's signed row, every
	// verified peer rendered into /etc/litevirt/ssh, and how each ssh fence
	// from here — the coordinator's and FenceHost's — reaches its target.
	fenceSSH := fencessh.New(fencessh.Config{
		Self: d.cfg.HostName, PKIDir: d.cfg.PKIDir, DB: d.db, Gate: svc,
		Accepting:     fencessh.SSHDAccepting(fencessh.SSHDPath(), "", fencessh.DefaultDir),
		Mode:          func() string { return d.cfg.Enforcement.FenceSSH },
		ProbeInterval: d.cfg.FenceSSHProbeInterval(),
		SelfCheck:     true,
		OnAccepting:   svc.FenceSSHAccepting,
	})
	svc.SetFenceSSH(fenceSSH)
	fc.FenceSSH = fenceSSH.FenceConfig
	go fenceSSH.Run(ctx)
	if d.startWaitSvc != nil {
		d.startWaitSvc.Store(svc)
	}
	svc.SetSupersededDiskRetentionDays(d.cfg.SupersededDiskRetentionDays)
	{
		iv := d.cfg.HostUpdates.IntervalMinutes
		if iv <= 0 {
			iv = 360
		} else if iv < 5 {
			iv = 5
		}
		svc.SetHostUpdates(grpcapi.HostUpdatesConfig{
			Enabled:      d.cfg.HostUpdates.Enabled,
			Interval:     time.Duration(iv) * time.Minute,
			RefreshIndex: d.cfg.HostUpdates.RefreshIndex,
		})
	}
	svc.SetContainerIDMapRange(d.cfg.Containers.IDMapBase, d.cfg.Containers.IDMapRanges)

	// Re-provision every network (bridge, gateway, DHCP, NAT, VXLAN) and tear
	// down every deleted one. dnsmasq is a child process that dies when the
	// daemon restarts; this brings it back. The same pass then runs on an
	// interval (StartNetworkReconciler, below), which is what carries a
	// network created or deleted on another node to this one.
	if err := svc.ReconcileNetworksOnce(ctx); err != nil {
		slog.Warn("startup network reconcile failed", "error", err)
	}
	// Wire the split-brain gate onto the gRPC server BEFORE ReconcileLBs (below)
	// re-applies VIPs, so an isolated/latched restart can't bring up a VIP ungated.
	svc.SetGate(d.checker)
	// The operator's hosts writes refuse on a replica that has not caught up
	// (grpcapi/host_incarnation.go).
	svc.SetHostWriteCurrencyCheck(true)
	// Start rebalance coordinator. Leader-gated; safe to start on
	// every host. Defaults to dry-run on every VM unless compose says otherwise.
	// Its lease stands down on the server's LeaseQuorumLost, as RunRebalance's
	// and the rebalance executor's do: one predicate for the one lease.
	rc := scheduler.NewRebalancer(d.cfg.HostName, d.db)
	rc.SetCapacityPolicy(capacity)
	rc.QuorumLost = svc.LeaseQuorumLost
	go rc.Start(ctx)
	d.checker.SetReleaseUseConfirmer(svc.PeerHoldsReleaseFeatureUse)
	// A peer advertising a release token this build does not know is, almost
	// always, a forward roll: a non-blocking look at its used records, never a
	// probation (N2). Probation comes only from a marker at boot.
	corrosion.WireUnknownReleaseObserver(ctx, d.checker, ae)
	// Take no replicated state from a peer that cannot keep a release feature
	// in use: pushes are refused in PushMutations, pulls here.
	d.db.SetReplicationSourceGate(svc.ReleaseSourceAllowed)
	// A probation round that hears of a newer voter generation adopts it (each
	// certificate verified) and counts against it (I-R4-2).
	ae.SetVoterAdopter(svc.AdoptVoterConfigs)
	// The server can answer the lease-mint clearance from here on: it has the
	// gate whose quorum and healthy-peer set its high-water read uses.
	d.mintClearance.Store(svc)
	svc.SetGateRefusedObserver(gateMetrics.Refused)
	svc.SetLeaseBarrierIncompleteObserver(gateMetrics.LeaseBarrierIncomplete)
	svc.SetLeaseClaimNoMajorityObserver(gateMetrics.LeaseTermClaimNoMajority)
	svc.SetStateWriteFailObserver(stateWriteMetrics.Failed)
	// SR-IOV VF-pool policy: which PFs litevirt may adopt for VF creation, the pool
	// cap, and the degraded gauge. Validate the allowlist against live hardware now,
	// and re-validate on the rescan cadence.
	svc.SetSRIOVMetrics(metrics.NewSRIOVMetrics())
	svc.SetSRIOVPolicy(d.cfg.PCI.SRIOV.Managed, d.cfg.PCI.SRIOV.MaxVFsPerPF, d.cfg.PCI.SRIOV.ManagedPFs)
	svc.ValidateSRIOVPolicy()
	// Spare pcie-root-ports on every newly-defined q35 domain, so hot-plug has a
	// free slot to attach into (see daemon.PCIConfig.SparePCIeRootPorts). Both the
	// server (create/import/clone/promote/update) and the reconciler (sweep
	// redefines) need it — a redefine that goes through either must agree on the
	// node's current value.
	svc.SetSparePCIeRootPorts(d.cfg.PCI.SparePCIeRootPorts)
	reconciler.SetSparePCIeRootPorts(d.cfg.PCI.SparePCIeRootPorts)
	if d.cfg.PCI.SRIOV.Managed {
		go svc.RunSRIOVValidation(ctx, d.parsePCIRescanInterval())
	}
	// Target the upgrade swap at the binary we're actually running (re-exec uses
	// os.Executable()), so a non-/usr/local/bin install upgrades correctly.
	if exe, err := os.Executable(); err == nil {
		svc.SetBinaryPath(exe)
	}
	svc.SetVersion(d.cfg.Version)
	svc.SetDNSDomain(d.cfg.DNSDomain)
	// Resolve OVMF firmware paths once (G1) and share with the server + reconciler
	// so every domain-builder renders the same files the capability label reflects.
	firmwarePaths := libvirt.ResolveFirmwarePaths()
	svc.SetFirmwarePaths(firmwarePaths)
	reconciler.SetFirmwarePaths(firmwarePaths)
	// One firmware store (NVRAM under the data dir, swtpm under libvirt's
	// root) for the host, the guarded one New built, shared by the server and
	// the reconciler.
	svc.SetFirmwareStore(d.fwStore)
	reconciler.SetFirmwareStore(d.fwStore)
	svc.SetSessionTimeouts(parseDurationOr(d.cfg.Auth.SessionIdleTimeout, 0), parseDurationOr(d.cfg.Auth.SessionHardExpiry, 0))
	// Validated at load (MemorySnapshotConfig.validate).
	if budget, deadline, err := d.cfg.MemorySnapshot.Durations(); err == nil {
		svc.SetMemorySnapshotTuning(grpcapi.MemorySnapshotTuning{PauseBudget: budget, LiveDeadline: deadline})
	}
	svc.SetStrictMTLSIdentity(d.cfg.Auth.StrictMTLSIdentity)
	svc.SetTrustRotatedPeerCerts(d.cfg.Auth.TrustRotatedPeerCerts)
	svc.SetForwardedIdentity(d.cfg.Auth.ForwardedIdentity)
	svc.SetRBACRealm(d.cfg.Auth.RBACRealm)
	// Split-brain-family enforcement kill-switches — so the HA monitor drives the
	// right tokens' latches (mandatory ∪ configured-on) and gates degraded/paging on
	// config intent. The actual enforcement predicates live on the consumers
	// (Coordinator, the lww/vip closures above), wired from the same config below.
	svc.SetEnforcementConfig(
		d.cfg.Enforcement.SafeFenceDefault,
		d.cfg.Enforcement.LWWSkewGuard,
		d.cfg.Enforcement.HLCLww,
		d.cfg.Enforcement.VIPSelfDemote,
		d.cfg.Enforcement.VIPProofReclaim,
		d.cfg.Enforcement.SharedStorageFence,
	)
	// netbox_ipam_v1 is advertised only while this node's config enables the
	// NetBox integration, so the cluster-wide latch requires config uniformity,
	// not just a uniform build (see capabilities.NetBoxIPAMV1).
	svc.SetNetBoxIPAM(d.cfg.NetBox.Enabled)
	// The INVENTORY MIRROR is a second, narrower opt-in, driving its own token
	// (netbox_mirror_v1) the same conditional-advertisement way. Default off:
	// NetBox is pure IPAM unless this node asks for inventory too, and the latch
	// requires every node to ask — the sweep runs on one lease holder, so a
	// non-uniform flag makes the inventory follow leadership. Set BEFORE
	// StartNetBoxMirror, which declines outright when it is off.
	svc.SetNetBoxMirrorInventory(d.cfg.NetBox.MirrorInventory)
	// BEFORE the mirror starts. The name decides which NetBox cluster object
	// every mirrored VM hangs off, and the CA re-key resolves the same one.
	svc.SetNetBoxClusterName(d.cfg.NetBox.ClusterName)
	svc.SetNetBoxSite(d.cfg.NetBox.Site)
	// The client itself. A node whose config ENABLES the integration but whose
	// client cannot be built (missing/empty token file, no URL) must not start:
	// it would advertise netbox_ipam_v1 — helping the cluster latch — while
	// every bind and claim on it refused for want of a client. Failing startup
	// keeps the "config uniformity" the latch depends on honest.
	if d.cfg.NetBox.Enabled {
		nbClient, err := netbox.New(netbox.Config{
			BaseURL:   d.cfg.NetBox.URL,
			TokenPath: d.cfg.NetBox.TokenPath,
			Timeout:   time.Duration(d.cfg.NetBox.TimeoutSec) * time.Second,
		})
		if err != nil {
			return fmt.Errorf("netbox client: %w", err)
		}
		svc.SetNetBoxClient(nbClient)
		// The real counter sink, replacing the noop. Registered on the default
		// registry, so it is served wherever /metrics is.
		svc.SetNetBoxMetrics(metrics.NewNetBoxMetrics())
		// Binding revalidation + the orphan sweep, on the configured cadence.
		// Started ONLY here: a node with no NetBox configuration creates no
		// goroutine and never enters the `netbox` leader-lease race. The sweep
		// itself is leader-gated, so every configured node running this loop
		// still means exactly one reclaiming node cluster-wide.
		svc.StartNetBoxMaintenance(ctx, time.Duration(d.cfg.NetBox.SweepIntervalSec)*time.Second)
		// The inventory mirror, on the SAME cadence and the SAME leader lease.
		// One key, not two: the sweeper reclaims addresses and the mirror
		// rewrites the objects that name them, so a cluster where two different
		// nodes led the two would have each acting on state the other was
		// changing underneath it.
		svc.StartNetBoxMirror(ctx, time.Duration(d.cfg.NetBox.SweepIntervalSec)*time.Second)
	}
	// One operator switch drives both operation_protocol_v1 and its dependent
	// capacity_admission_v1 token; capacity admission has no standalone flag.
	svc.SetOperationProtocol(d.cfg.Enforcement.OperationProtocol)
	svc.SetDefaultCPUMode(d.cfg.VM.DefaultCPUMode)
	svc.SetLiveResize(d.cfg.Enforcement.LiveResize)
	// Console passwords: every define on this host (grpcapi's and the health
	// reconciler's, which share d.virt) applies svc.ConsolePasswordActive —
	// this flag AND the console_password_v1 latch. NewServer wired the hook.
	svc.SetConsolePassword(d.cfg.Enforcement.ConsolePassword)
	// vrrp_unicast_v1: advertised only with enforcement.vrrp_unicast on; an
	// LB renders unicast VRRP only with this flag AND the durable latch.
	svc.SetVRRPUnicast(d.cfg.Enforcement.VRRPUnicast)
	svc.SetAllowUnencryptedStorageMigration(d.cfg.Migration.AllowUnencryptedStorage)
	svc.SetMigrationNetwork(d.cfg.Migration.Network)
	svc.SetMigrationAddress(d.cfg.Migration.Address)
	migrationTLS := d.migrationTLSInstaller()
	svc.SetMigrationTLS(migrationTLS)
	svc.SetMigrationCAFingerprint(func() (string, error) { return pki.MigrationCAFingerprint(d.cfg.PKIDir) })
	svc.SetMigrationCAList(func() ([]string, error) { return pki.MigrationCAFingerprints(d.cfg.PKIDir) })
	svc.SetMigrationTLSCheck(d.migrationTLSChecker())
	svc.SetMigrationTLSStatus(func() *pb.MigrationTLSHostStatus {
		return migrationTLSStatusRow(pki.InspectMigrationTLS(d.cfg.PKIDir, time.Now()))
	})
	go runMigrationExpiryWatch(ctx, d.cfg.PKIDir)
	// Install once at start so the operator sees the state in the log; it runs
	// again before each storage migration.
	ok, wrote, err := d.installMigrationTLS()
	logMigrationTLSInstall(ok, wrote, err)
	// Cluster-wide capacity policy (overcommit ratios + host reserves). Per-host
	// overrides live on the host record and win where set.
	svc.SetCapacityPolicy(capacity)
	svc.SetCanonicalIdentityEnforce(d.cfg.Enforcement.CanonicalIdentity) // drives the latch + conditional advertisement
	svc.SetVMReplaceEnforce(d.cfg.Enforcement.VMReplace)                 // drives the latch + conditional advertisement; gates `lv cutover`
	// The first pass over the swtpm tree (vtpm_state_sync), before anything
	// on this host can start a VM: the cutover resume below, the startup
	// recovery barrier, the runtime loops, onboot autostart and the API.
	// It completes, or runs past vtpmPassWait and raises
	// vtpm_state_not_durable; either way no vTPM guest writes state here
	// before the attempt to make that state synchronous. The vTPM capability
	// label (below) reuses the same probe.
	vtpmMarker := filepath.Join(d.cfg.DataDir, "vtpm-state-sync")
	vtpmSync := &vtpmStateSync{
		on:   d.cfg.VTPMStateSyncEnabled(),
		base: d.fwStore.SwtpmBase,
		wait: vtpmPassWait,
		// The host's own store: its swtpm tree is the one this host's
		// guests write.
		sync: func(on bool) libvirt.SwtpmSyncReport { return d.fwStore.SyncSwtpmState(on, vtpmMarker) },
		report: func(open bool, evidence map[string]any) bool {
			return d.syncVTPMCondition(ctx, open, evidence)
		},
	}
	tpmCapable := tpmCapableProbe(exec.LookPath, vtpmSync.probe)
	// The live firmware move label reads the pass the vTPM label's probe
	// ran this cycle, so a cycle walks the swtpm tree once.
	tpmReady := tpmReadyProbe(exec.LookPath, vtpmSync)
	awaitFirstVTPMPass(tpmCapable)
	// Finish any cutover cleanup a previous process left committed-but-unfinished.
	// The replacement transition displaced the rows describing what the replaced VM
	// owned, so its journaled manifest is the only surviving record of the volumes
	// to free — and nothing else will ever look at it.
	// In the background: it removes the replaced VM's volumes, which may be on
	// an NFS pool whose server does not answer, and it is safe at any time
	// (each cleanup is taken under its VMs' locks and re-read there). A
	// cleanup whose storage does not answer is deferred, not run under the
	// locks, and any cleanup left journaled is retried (startup_bound.go).
	go resumeVMReplaceCleanups(ctx, svc, vmReplaceCleanupMinRetry, vmReplaceCleanupRetry)
	svc.SetProjectAuthorityEnforce(d.cfg.Enforcement.ProjectAuthority) // F2: delegate project-quota admission to the authority holder
	svc.SetAuditSignatureEnforce(d.cfg.Enforcement.AuditSignature)     // drives the latch + conditional advertisement
	// Phase 4: owner_epoch_v1 is advertised only when the operator opted in AND
	// this node.s owned workloads have all graduated out of the pre-epoch 0, so
	// the fleet can never latch across a node whose generations do not exist yet.
	svc.SetOwnerEpochEnforce(d.cfg.Enforcement.OwnerEpoch)
	svc.SetIsolationEpochEnforce(d.cfg.Enforcement.IsolationEpoch)
	svc.SetOwnerEpochReady(func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ready, reason := svc.OwnerEpochReadiness(ctx)
		if !ready {
			slog.Debug("owner_epoch_v1 readiness withheld", "reason", reason)
		}
		return ready
	})
	// Phase 2: lease_term_v1 is advertised only when the operator opted in AND
	// this node can enforce — a readable ledger, split_brain_gate_v1 already
	// latched, and a cluster large enough that the quorum barrier does not break
	// failover.
	svc.SetLeaseTermEnforce(d.cfg.Enforcement.LeaseTerm)
	// recovery_claim_v1: advertised only with the flag on and this node ready
	// (split_brain_gate_v1 latched, able to vote durably), enforced only with
	// the flag AND the latch AND an adopted voter generation.
	svc.SetRecoveryClaimEnforce(d.cfg.Enforcement.RecoveryClaim)
	// partition_pause_v1: advertised only with enforcement.partition_pause on
	// (default on), because the majority relies on this node pausing.
	svc.SetPartitionPause(d.cfg.Enforcement.PartitionPause)
	// Resource pressure (docs/configuration.md, "Resource pressure"): this
	// host grades its own resources and Ready reports the grade. It reports
	// only; with pressure.enabled false nothing is sampled and peers read this
	// host's pressure as unknown.
	d.startPressure(ctx, svc, func() func(pressure.Report) { return metrics.NewPressureMetrics().Observe })
	// The reconciler is the SECOND executor boundary for this regime: a VM
	// reschedule proof never travels over an RPC, so it is claimed off the
	// replicated row there rather than in claimCarriedProof. The judgment is
	// injected because internal/grpcapi imports internal/health and cannot be
	// imported back — one implementation, wired to both callers.
	reconciler.SetLeaseTermGate(svc.LeaseTermGateForPendingProof)
	// The recovery-claim certificate is checked at the same boundary, for the
	// same reason: a reschedule proof is claimed off the replicated row here,
	// and a relocate-recreate proof by the container checker.
	reconciler.SetRecoveryClaimGate(svc.RecoveryClaimGateForPendingProof)
	// Layer 3 of partition pause (docs/design/partition-pause.md §6): a local
	// copy whose row a VERIFIED recovery-claim certificate gave to another
	// host is stopped on that proof, and only on it.
	reconciler.SetSettleVerifier(svc.VerifySettleProof)
	reconciler.SetPITOverlayReporter(svc.ReportPITOverlayHeld, svc.ClearPITOverlayHold)
	reconciler.SetPITOverlayFeature(svc.PITOverlayFeature)
	reconciler.SetSharedDiskWithheldReporter(svc.ReportSharedDiskWithheld, svc.ClearSharedDiskWithheld)
	svc.SetLeaseTermReady(func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ready, reason := svc.LeaseTermReadiness(ctx)
		if !ready {
			slog.Debug("lease_term_v1 readiness withheld", "reason", reason)
		}
		return ready
	})
	// Once the whole cluster has latched audit_signature_v1, a write this node
	// cannot sign is an error-level event rather than a normal one.
	//
	// It is NOT a refusal. Refusing was the first design and it lost the record
	// of operations that had already happened, because every caller of
	// InsertAuditLog discards its error — so the delete or the fence went ahead
	// with no audit row at all, which is exactly what an attacker would arrange
	// by making one file unreadable. The row is written unsigned and the
	// verifier reports it: a host that has signed once cannot legitimately stop,
	// so every such row is tampering on every node that reads the log.
	//
	// Latched, not Enforced: this is read on the audit write path, which must
	// not ping peers.
	d.db.SetAuditSignatureRequired(func() bool {
		return d.cfg.Enforcement.AuditSignature && d.checker.Latched(capabilities.AuditSignatureV1)
	})
	svc.SetMigrationMetrics(metrics.NewMigrationMetrics())
	svc.SetLBMetrics(metrics.NewLBMetrics())
	svc.SetHAHealthMetrics(metrics.NewHAHealthMetrics())
	svc.SetDualRunMetrics(metrics.NewDualRunMetrics())
	svc.SetSMARTMetrics(metrics.NewSMARTMetrics())
	svc.SetReservationMetrics(metrics.NewReservationMetrics())
	svc.SetStoragePoolsByName(d.storagePoolRefs())
	// The ceph pools' libvirt secrets (ephemeral: gone after a libvirtd
	// restart): defined now, then kept in line with the pools and keyrings.
	// An rbd disk's domain takes its monitors from its pool as configured on
	// this host when the domain is defined, not from when the disk was made.
	libvirt.SetCephMonitorResolver(svc.CephMonitorsForPool)
	// Deleted ceph images wait in their pool's trash for a background purge;
	// the ones a previous run had not finished are resumed (and named by
	// ceph_trash_leftover while they fail).
	if err := storage.ResumeCephPurges(d.cfg.DataDir); err != nil {
		slog.Warn("ceph: trash purges of a previous run not resumed", "error", err)
	}
	svc.ReconcileCephSecrets(ctx)
	go d.runCephSecretReconcile(ctx)
	// The iscsi pools' sessions: a host reboot drops them, and node records
	// at node.startup = manual bring none back. Logged back in now and kept
	// (grpcapi.ReconcileISCSISessions), off the start path: a portal that
	// does not answer must not hold the daemon's start.
	go d.runISCSISessionReconcile(ctx)
	// Two NICs of the cluster on one MAC (grpcapi.ReconcileMACCollisions).
	go d.runMACCollisionReconcile(ctx)
	// The nfs pools' exports: a host reboot unmounts them, and nothing but a
	// pool's Prepare mounted them. Mounted back now and kept
	// (grpcapi.ReconcileNFSMounts), off the start path: a server that does
	// not answer must not hold the daemon's start.
	go d.runNFSMountReconcile(ctx)
	// Before this daemon serves: no cold-migration copy can be in flight yet.
	svc.SweepColdMigrationScratch()
	svc.SetReplicator(repl)
	svc.SetAuthEngine(d.authEngine)
	svc.SetRealmRegistry(d.realmRegistry)
	vmChecker.SetEventBus(svc.EventBus())
	vmChecker.SetMigrateFunc(svc.MigrateVMForHealthCheck)
	// Every guest start the Server performs opens the healthcheck's start grace,
	// including RestartVM's, which keeps the row "running" and is otherwise
	// invisible to the checker's sweep.
	svc.SetVMStartObserver(vmChecker)
	reconciler.SetVMStartObserver(vmChecker) // onboot and failover starts open the healthcheck start grace too
	// hardware_v2 pre-start hook: the automated (re)start paths (failover reconciler +
	// health auto-restart) bypass startVMLocked, so wire them to the Server's shared
	// adoption-gate + PCI-start-preflight. A strict no-op until hardware_v2 latches, so
	// this changes nothing on a fleet where the feature is off.
	vmChecker.SetHardwareStartPreparer(svc.PrepareHardwareForStart)
	// A health restart runs under the VM's API lock, the one a move, a start
	// or a stop of the VM holds, so none interleaves with it.
	vmChecker.SetVMLocker(svc.TryLockVMForHealth)
	// A health restart moves a stopped VM's NICs onto the devices their
	// networks are on now, as a start through the Server does.
	vmChecker.SetNetworkFollower(svc.FollowNetworkDevices)
	vmChecker.SetCancelledStartProbe(svc.HasCancelledStart) // cancelled_starts.go: neither healed to running nor restarted

	// Wire reconciler callbacks now that gRPC server exists.
	reconciler.SetOnVMStarted(svc.RefreshLBForStack)
	reconciler.SetHardwareStartPreparer(svc.PrepareHardwareForStart)
	// A rebuilt domain's PCI passthrough (health/passthrough_rebuild.go).
	reconciler.SetPassthroughForRebuild(svc.PassthroughForRebuild)
	reconciler.SetCancelledStartProbe(svc.HasCancelledStart) // cancelled_starts.go: an error row's late-started domain is the sweep's
	// A held start whose daemon restarted before libvirt answered it: its
	// lease is taken over once the domain runs, and its outcome recorded
	// (health/held_start_orphan.go).
	reconciler.SetHeldStartProbe(svc.HasStartInFlight)
	reconciler.SetVMEventRecorder(svc.RecordVMEvent)
	// `lv stop --force` made under write quarantine: recorded on the VM's
	// row once the quarantine lifts, first in every pass
	// (grpcapi/operator_stop_marker.go).
	reconciler.SetOperatorStopReplay(svc.ReplayOperatorStopMarkers)
	svc.SetOperatorStopMarkerObserver(metrics.NewOperatorStopMetrics().Observe)
	// A start whose ceph key must be proven, late in a walk with no time left
	// for it, is left untouched for the next pass rather than half-started.
	reconciler.SetStartDeferral(svc.CephStartDeferral)
	// A cancel of a start records whether it was a proof-less transfer.
	svc.SetStartTransferProbe(reconciler.IsDeferredTransfer)
	reconciler.SetAutoPullImage(svc.AutoPullImage)
	reconciler.SetRecreateOverlay(svc.RecreateOverlayDisk) // under an image hold (m-6)
	reconciler.SetDiskStrandedObserver(svc.NotifyVMDiskStranded)
	reconciler.SetBackupInProgress(svc.BackupInProgress)
	reconciler.SetNetworkProvision(svc.ProvisionNetworkHere) // a failover start provisions like a VM create
	// Runtime owner-assert (Phase 3): corroborate a locally-running VM whose DB
	// row points elsewhere against every other active host's libvirt before
	// reclaiming it.
	reconciler.SetPeerRuntimeChecker(svc.CheckPeerVMRuntime)
	// Split-brain hardening (Phase 1): fresh-Ping peers for capability tokens so
	// cluster-wide activation of fail-closed gates is computed from live
	// reachability, never stale replicated rows. Once this is set, the proof-table
	// WAL gate (wired before repl.Start above) can positively confirm peers; until
	// now PeerSupports failed closed, deferring proof entries rather than leaking.
	// Paired with the readiness probe, which turns the peer health check from a
	// TLS handshake into an application-level question — see wirePeerProbes.
	wirePeerProbes(d.checker, svc)
	// Runtime ownership repair metrics (Phase 5): VM owner-assert + CT re-key
	// outcomes → litevirt_runtime_owner_assert_total.
	runtimeRepairMetrics := metrics.NewRuntimeRepairMetrics()
	reconciler.SetOwnerAssertObserver(func(_, result string) { runtimeRepairMetrics.OwnerAssert("vm", result) })
	// Orphaned runtimes: litevirt domains/containers with no live record, reported
	// (never reaped) as vm_orphan_runtime / ct_orphan_runtime and this gauge.
	orphanMetrics := metrics.NewOrphanRuntimeMetrics()
	observeOrphans := func(kind string, found []health.OrphanRuntime) {
		samples := make([]metrics.OrphanRuntimeSample, 0, len(found))
		for _, o := range found {
			samples = append(samples, metrics.OrphanRuntimeSample{Name: o.Name, Row: o.Row})
		}
		orphanMetrics.Set(kind, d.cfg.HostName, samples)
	}
	reconciler.SetOrphanRuntimeObserver(observeOrphans)

	// F1 startup recovery barrier: reduce the host-local operation journal against
	// replicated state BEFORE any runtime loop or API mutation runs — DB +
	// capability latch + membership are all wired by this point.
	if j, err := opjournal.Open(filepath.Join(d.cfg.DataDir, "opjournal")); err != nil {
		slog.Error("operation journal: open failed; skipping recovery", "error", err)
	} else {
		d.opJournal = j
		svc.SetOpJournal(j) // so the device-lease path can durably record allocations
		// Host network apply protocol (v48): the real netplan-touching System,
		// plus crash recovery INSIDE this barrier — a half-applied netplan
		// change is restored before any RPC or runtime loop can observe it.
		svc.SetHostNetworkEnv(&hostnet.RealSystem{
			AdvertiseIP: d.hostAddress(),
			GRPCPort:    d.cfg.GRPCPort,
		}, d.hostAddress())
		svc.RecoverHostNetworks(ctx)
		d.runOperationRecovery(ctx)
		svc.RecoverDeviceLeases(ctx) // roll back device leases a crash orphaned
	}

	// Resume, park or abort each live firmware move this host is the source
	// of (spec §8.1): its VM's lock is taken here, before any runtime loop
	// starts, and held until its recovery resolves or parks it.
	// Unconditional: outside the operation journal's branch above.
	svc.RecoverFirmwareMoves(ctx)
	// A VM recorded migrating here with no move of it running (this daemon
	// stopped mid-move) is named by vm.migration_unresolved.
	svc.RaiseLeftMigrating(ctx)

	// F1 resource-update recovery: resume any locally-owned VM wedged on a nonterminal
	// resource_update_running operation (a live resize that crashed after committing its
	// desired spec) — converge it to the committed spec + clear the barrier so a partial
	// failure never wedges active_operation_id. Uses replicated operation state (not the
	// host-local journal), so it runs regardless of the journal above. A reconciler pass
	// retries stragglers.
	// At start a VM whose lock is held (a firmware move's recovery holds it
	// until the start is wired, below) is skipped; the loop takes it later.
	svc.RecoverResourceOperationsAtStart(ctx)
	go svc.RunResourceOperationRecovery(ctx)

	// Release host reservations whose operation provably stopped running (one
	// finished past its header's owner epoch, or whose VM is gone), after the
	// recovery above has finished what it could.
	svc.SweepReservationsOnce(ctx)
	go svc.RunReservationRecovery(ctx)

	// F1 hardware-operation recovery: resume any locally-owned VM wedged on a
	// nonterminal device_attach/device_detach operation (a hot-plug that crashed
	// with the mutation barrier held) — roll an incomplete attach BACK and a detach
	// FORWARD to a single consistent state, clearing the barrier. Runs synchronously
	// after DB + libvirt + journal init (uses the host-local journal artifacts), and
	// a reconciler pass retries stragglers.
	svc.RecoverHardwareOperationsAtStart(ctx)

	// Release PCI devices a VM owns but provably does not hold, once the
	// recoveries above have settled every lease and operation that could
	// explain one (lab finding L1: a failed SR-IOV attach on an older build
	// left its VF owned). What it cannot prove it reports and leaves owned.
	svc.SweepUnattachedPCIOwnership(ctx)
	go svc.RunHardwareOperationRecovery(ctx)

	// v42 hardware foundation (CONTRACT h): backfill the typed-hardware tables
	// (vm_nics, vm_disks.bus, vm_pci_intent) and record each owned VM's adoption
	// verdict, THEN mark this node hardware_v2-advertise-ready. Started here —
	// AFTER the schema is applied (InitSchema, above) and the operation-protocol
	// config/latch is wired (hardware mutations depend on the crash-safe
	// operation journal) — but run in the BACKGROUND, because the pass waits for
	// this node's replica to catch up: it publishes rows for the VMs the local
	// replica says this host owns, and a replica back from a fence still names
	// VMs failover has moved away (RunHardwareBackfill). Until it succeeds the
	// readiness flag advertisedCapabilities gates hardware_v2 on stays false, so
	// no peer reads hardware_v2 from this node early. A failed pass DEGRADES
	// (logged and retried) rather than crashing the daemon.
	go svc.RunHardwareBackfill(ctx)
	// Continuous legacy→vm_nics bridge: mirrors vm_interfaces writes an OLD peer
	// makes during the rolling-upgrade window into vm_nics (one-directional; old
	// peers ignore vm_nics), converging the read overlay toward vm_nics completeness.
	go svc.RunHardwareBridge(ctx)

	// Now that the split-brain gate is FULLY wired (activation latch + SetPeerPinger
	// for cluster-wide capability confirmation) and every reconciler/vmChecker
	// callback is set, start the runtime loops. Launching them here — not at
	// construction — guarantees no automated runtime start (reschedule, restart
	// policy, onboot autostart) ever runs in the window before the gate can confirm
	// capability, closing the fail-open race for a should-enforce node.
	// distributed firewall: poll cluster security_groups +
	// sg_rules every 30s and atomically replace this host's nftables
	// table. The applier short-circuits when the rendered ruleset
	// hasn't changed, so idle clusters cost ~one corrosion query/tick.
	fwApplier := firewall.NewApplier(firewall.NftBinary{})
	// Observe-mode evidence outlives every table reload and daemon restart
	// (re-review I-4): harvested before each replace, kept in data_dir.
	fwApplier.SetTally(firewall.NewWouldDropTally(filepath.Join(d.cfg.DataDir, "firewall-would-drop.json"), time.Now()))
	fwMetrics := metrics.NewFirewallMetrics()
	// VMs about to start or migrate in here, and NICs whose rows are not
	// written yet: rendered ahead of their rows (firewall.Arming).
	fwArming := firewall.NewArming()
	// Per-NIC rules need bridge connection tracking. Loaded once here; a host
	// that cannot load it renders the guards only and raises a health
	// condition (firewall.nic.unavailable), never an empty firewall.
	bridgeCT := firewall.BridgeConntrackAvailable(ctx, true)
	// Firewall logging needs the kernel to load a named limit and a log line
	// to an NFLOG group. Probed once here (nft -c, nothing committed); a host
	// that refuses renders no log line and raises firewall.log.unavailable.
	fwLogGroup := uint16(d.cfg.Firewall.LogGroup)
	fwLogErr := firewall.ProbeLogging(ctx, fwLogGroup)
	if fwLogErr != nil {
		slog.Warn("firewall: logging is unavailable on this host; no packet is logged here", "error", fwLogErr)
	}
	svc.RecordFirewallLogAvailability(ctx, fwLogErr)
	// Log lines are rendered only while this daemon's listener holds the
	// group (firewallLogging); each bind change runs passes. The listener
	// starts below, once d.fwReconciler exists.
	fwLogging := newFirewallLogging(ctx, fwLogGroup, fwLogErr,
		func(c context.Context) error { return d.fwReconciler.Reconcile(c) },
		func(err error) { svc.RecordFirewallLogListener(ctx, err) })
	// SYN-flood protection needs the kernel's per-source meters (nft_limit).
	// Probed once here, check only; a host whose kernel refuses renders none
	// and raises a health condition (firewall.synflood.unavailable).
	synFloodProbe := firewall.ProbeSynFlood(ctx)
	if synFloodProbe.V4 != nil || synFloodProbe.V6 != nil {
		slog.Warn("firewall: the kernel refused a SYN-flood probe; that family gets no SYN-flood protection on guest NICs here",
			"ipv4", synFloodProbe.V4, "ipv6", synFloodProbe.V6)
	}
	fwLoader := firewall.CorrosionPlanLoader(d.db, d.cfg.HostName, firewall.Plan{},
		firewall.LoaderOptions{RunningTaps: d.virt.RunningDomainTaps, OnDuplicateSGs: fwMetrics.SetDuplicateSGNICs,
			OnTagGroupMembers:    fwMetrics.SetTagGroupMembers,
			OnDuplicateAddresses: firewall.NewDuplicateAddressReporter(d.db, d.cfg.HostName).Report,
			BridgeConntrack:      func() bool { return bridgeCT }, Arming: fwArming,
			Logging:       fwLogging.Logging,
			SynFloodProbe: func() firewall.SynFloodProbeResult { return synFloodProbe }})
	d.fwReconciler = firewall.NewReconciler(fwLoader, fwApplier, 30*time.Second)
	d.fwReconciler.SetArming(fwArming)
	// Every domain start — an API start, a restart policy, a failover
	// reschedule, a restore — first puts the VM's NIC firewall in force here,
	// its guards above all, and a guarded VM whose guards cannot be is not
	// started (re-review I-10).
	d.virt.SetStartGuard(svc.NICStartGuard(ctx))
	d.fwReconciler.SetStateHook(svc.RecordFirewallState)
	// Firewall logging: the listener reads the NFLOG group every rendered log
	// line sends to into a bounded store (docs/firewall.md, "Logging").
	fwLogStore := openFirewallLogStore(d.cfg, fwMetrics)
	svc.SetFirewallLogStore(fwLogStore)
	if fwLogErr == nil {
		go (&firewall.LogListener{Group: fwLogGroup, Store: fwLogStore,
			Resolve: d.fwReconciler.ResolveLogDevice,
			OnBind:  fwLogging.OnBind}).Run(ctx)
	}
	go pruneFirewallLog(ctx, fwLogStore)
	// Whether this host enforces NIC guards, after every pass, the boot pass
	// included (re-review m8, m2, m5): the label carries this build's
	// version while the last pass put the per-NIC table in force, so a host
	// rolled back to an older build — which reports its own version and
	// knows nothing of the label — stops counting, and so does one whose
	// kernel refuses the table or whose pass failed or ran out of time. Until
	// every host enforces them, a guarded VM is placed only on such a host.
	d.fwReconciler.SetPassHook(nicGuardLabelHook(d.db, d.cfg.HostName, d.cfg.Version))
	// Upgrade migration: once the reconciler renders a bridge's NAT/isolation into
	// litevirt-fw, clear the pre-consolidation out-of-band rules (old iptables
	// masquerade + `inet litevirt` chains) a prior binary left for it.
	d.fwReconciler.SetLegacyCleanup(network.RemoveLegacyBridgeFirewall)
	svc.SetFirewallReconciler(d.fwReconciler)
	// This build's units, before the first per-NIC table is loaded: the main
	// unit's ExecStartPre removes that table when a build that does not own it
	// starts, so a rollback leaves no stale per-NIC rules enforcing. An upgrade
	// only ever installs the OLD binary's units.
	grpcapi.EnsureSystemdUnits()
	// One pass now, before any runtime start: the tables a host boots with
	// are empty (re-review R2-I2). Bounded (m3): a hung nft must not hold the
	// whole daemon start; a guarded start arms its own pass.
	if err := bootFirewallPass(ctx, d.fwReconciler, bootFirewallPassBudget); err != nil {
		slog.Warn("firewall: the first pass failed; starts arm their own", "error", err)
	}
	d.fwReconciler.Start(ctx)
	go svc.RecordExistingTrunkVLANsLoop(ctx, 0)
	// A guest handed over paused for its NIC guards runs once they are in
	// force here, even when the source's resume never arrives (re-review
	// R3-I2).
	go svc.RunHeldGuestResumer(ctx, 0)

	go vmChecker.Start(ctx)
	// The partition pauser is built here, before the reconciler starts, so
	// settle's guard is wired before any pass reads it (its destroy of a
	// paused copy runs under the pauser's mark lock); the rest of its wiring
	// and its Start come below.
	pauser := health.NewPartitionPauser(d.cfg.HostName, d.cfg.DataDir, d.db)
	pauser.SetVMBackend(d.virt)
	reconciler.SetPauseGuard(pauser.SettleDestroy) // settle destroys a paused copy only under its mark lock
	go reconciler.Start(ctx)
	// Finish any drain cold move a previous process died in the middle of: the
	// VM was running, was (or was about to be) shut down for the move, and must
	// run again on exactly one host. It starts VMs, so it runs with the runtime
	// loops above — after the startup recovery barrier has restored host
	// networks and every late setter has run — and in its own goroutine,
	// because finishing one can wait for a guest's shutdown or for the target.
	go svc.RunDrainColdMoveRecovery(ctx)
	// Remove the owner-epoch markers of VMs deleted while this host was not
	// asked (in maintenance, unreachable), each time it becomes active.
	go svc.RunDeletedVMMarkerSweep(ctx)
	// Quarantine a live firmware move's target hold whose move was abandoned,
	// and name a hold held too long.
	go svc.RunFirmwareHoldSweep(ctx)
	// Retry a live firmware move's source cleanup that stopped, and remove its
	// retained firmware bundle 24 h on, never while a record names it.
	go svc.RunFirmwareRetainedSweep(ctx)
	// Remember the clock skews this host sees past their rows' retention: the
	// margin lv image prune keeps a deleted image's file within reads them.
	go svc.RunImageSkewRecorder(ctx)
	// Record a release feature's use found in replicated data with none
	// recorded (one written through a daemon that predates the gate), on the
	// failover lease holder, so a later rollback below the release still
	// quarantines.
	go svc.RunReleaseUseSweep(ctx)
	// Remove the replicas, and retire the checkpoint rows, of a replication
	// schedule removed or a VM deleted more than a day ago (replica_orphans.go).
	go svc.RunReplicaOrphanSweep(ctx)
	// Autostart onboot VMs once, in startup_order (#10). Runs only for VMs not
	// already running in libvirt, so a daemon restart (qemu kept alive by
	// KillMode=process) is a no-op while a host reboot brings them up in order;
	// one its operator stopped only when the kernel's boot ID says the host
	// booted (health/onboot_boot.go).
	go reconciler.StartOnbootVMs(ctx)

	// Rebalance executor: leader-gated loop that applies operator-approved
	// migration proposals (rc above only *proposes*). Reuses the rebalancer's
	// leader lease so exactly one node executes; honors the cluster rebalance
	// budget. Needs svc for the in-process live-migration call.
	go grpcapi.NewRebalanceExecutor(svc, d.cfg.HostName, d.db).Start(ctx)

	// Start stack deletion reconciler — retries cleanup for stacks stuck in "deleting" state.
	stackReconciler := health.NewStackReconciler(d.cfg.HostName, d.db)
	stackReconciler.SetCleaner(svc)
	stackReconciler.SetReplicaFreshness(d.db.ReplicaCaughtUp)
	go stackReconciler.Start(ctx)

	// Re-apply LB configs (haproxy + keepalived) that should run on this host.
	// These are child processes that die when the daemon restarts.
	svc.ReconcileLBs(ctx)
	// Keep litevirt_lb_keepalived_up tracking live keepalived state, not just
	// the last apply.
	go svc.RunLBMetricsRefresher(ctx, 30*time.Second)
	// Periodically re-apply this host's LBs whose keepalived is dead — recovers a sole VIP
	// holder after a restart/upgrade (the one-shot boot ReconcileLBs above is refused during
	// warmup / while 'upgrading') and a self-demoted VIP on quorum heal. Only touches dead LBs.
	go svc.RunLBReconciler(ctx, 30*time.Second)

	// Split-brain Phase 2: minority VIP self-demotion. On sustained local quorum
	// loss, an isolated LB host drops its own VIPs (stop keepalived + remove the
	// address). This runs WITHOUT a hardware watchdog — the minority stops answering
	// its own VIP regardless. A watchdog is an OPTIONAL backstop: if the demote can't
	// be confirmed AND a verified watchdog is armed, the node self-fences; otherwise it
	// keeps retrying + raises HA-degraded and the majority holds in the safe gap.
	// Inert until vip_demote_v1 is enforced cluster-wide (validate on an ephemeral
	// partition before flipping).
	vipDemoter := health.NewVIPDemoter(d.checker, time.Duration(d.cfg.QuorumLossDemoteAfterSec)*time.Second)
	keepalivedStopTimeout := time.Duration(d.cfg.KeepalivedStopTimeoutSec) * time.Second
	vipDemoter.SetDemoteLocalVIPs(func(ctx context.Context) (bool, error) {
		// Runtime-driven: demote whatever keepalived is actually configured/running on
		// THIS host (not the possibly-stale DB view), using the exact rendered tuple.
		return lb.NewManager().DemoteAll(keepalivedStopTimeout)
	})
	// A demotion FAILURE self-fences only when a verified watchdog is armed; without one
	// the demoter stays up + raises HA-degraded (safe gap). SetArmed feeds that decision.
	vipDemoter.SetSelfFence(watchdogCtrl.SelfFence)
	vipDemoter.SetArmed(watchdogCtrl.Armed)
	// Active when vip_demote_v1 is ENFORCED CLUSTER-WIDE (the durable Enforced() latch —
	// every enforcement-relevant member advertises it, latched so a later partition can't
	// un-arm it). NO watchdog gate: routing through the same latch as Phase 1 means the
	// flip doesn't activate a lone rolled node before the whole cluster can participate,
	// but a watchdog-less node still self-demotes (only its failure-handling differs).
	vipDemoter.SetEnabled(func(ctx context.Context) bool {
		// Config kill-switch AND the cluster-wide latch (HA monitor drives it while
		// healthy). Flag false ⇒ never self-demote (legacy: keepalived VRRP handles it).
		return d.cfg.Enforcement.VIPSelfDemote && d.checker.Enforced(ctx, capabilities.VIPDemoteV1)
	})
	vipDemoter.SetRefusedObserver(gateMetrics.Refused)
	// Surface an unfenced demotion failure (demote failed + no verified self-fence) as a
	// durable HA-degraded condition so an operator can provide a fence / intervene.
	vipDemoter.SetDemotionUnfencedObserver(svc.SetDemotionUnfenced)
	// On quorum heal after a self-demotion, re-apply this host's LBs — DemoteAll stopped
	// keepalived + removed the VIP, and nothing else recovers it otherwise.
	vipDemoter.SetOnQuorumRestored(svc.ReconcileLBs)
	// Once this node self-fences it de-advertises ALL split-brain capabilities — it is
	// committed to rebooting, so it stops presenting as a healthy member for the
	// fence-timeout window (defense-in-depth; reclaim still gates on VIPAssigned/fence-proof).
	// Wired BEFORE the goroutines below: the HA-health monitor self-Pings into
	// advertisedCapabilities, which reads this predicate. (Storage is atomic, so a late wire
	// is race-free regardless, but wiring first means a self-fence is honored immediately.)
	svc.SetWatchdogFenced(watchdogCtrl.Fenced)
	// A rolled-back node stops advertising capabilities, so the cluster cannot
	// latch anything further across a member that could not honour it, and peers
	// raise ha_degraded against it.
	// Quarantined below a latched token found at startup, OR since startup by
	// a use of a newer release's feature arriving by replication.
	// A rollback quarantine or a tripped release use — never a release
	// probation, which is not a rollback below anything known to be used and
	// must not get this node isolated by its peers (N1).
	svc.SetWALQuarantined(func() bool {
		return len(d.rolledBackTokens) > 0 || d.db.WALQuarantined()
	})
	go vipDemoter.Start(ctx)
	// Partition pause (docs/design/partition-pause.md): on losing the execution
	// quorum for T_pause, suspend/freeze every workload the majority would
	// recover elsewhere, recorded under <data_dir>/partition-pause; resume on a
	// majority's confirmation. Runs on the flag alone — a node advertises
	// partition_pause_v1 only while it already acts on it — and whether or not
	// a watchdog is armed; a verified watchdog is only the backstop for a
	// pause that fails.
	pauser.SetQuorum(d.checker.ExecutionQuorum)
	pauser.SetEnabled(func() bool { return d.cfg.Enforcement.PartitionPause })
	pauser.SetRecordFailure(d.cfg.Enforcement.PartitionPauseRecordFailure)
	pauser.SetCaptureRegistry(d.captureReg) // the pause wins over a memory snapshot
	pauser.SetContainerRuntime(lxcRunner)
	pauser.SetResumeConfirmer(svc.CheckPartitionResume)
	pauser.SetSettleVerifier(svc.VerifySettleProof)
	pauser.SetPeerRuntimeChecker(svc.CheckPeerContainerRuntime)
	pauser.SetSelfFence(watchdogCtrl.Armed, watchdogCtrl.SelfFence)
	d.wirePauserLiveness(pauser)
	go pauser.Start(ctx)
	// Persistent HA-degraded surface (unsupported member / unfenced demotion failure / VIP
	// with no holder) — a durable alertable status + transition events.
	go svc.RunHAHealthMonitor(ctx, 15*time.Second)

	// Read-only report of this host's pending OS package updates (host_updates).
	go svc.RunHostUpdateLoop(ctx)
	// Leader-gated dual-run detector: alert-only cross-check that no workload/VIP runs on
	// two hosts and no DB owner disagrees with runtime. One node (the lease holder) does
	// the work so the fleet pages once, not N times.
	go svc.RunDualRunDetector(ctx, 60*time.Second)
	// Per-host disk SMART health: gauges + a notification on a failing/prefail disk.
	if iv := parseSMARTInterval(d.cfg.SMART.Interval); iv > 0 {
		go svc.RunSMARTMonitor(ctx, iv)
	}
	go svc.RunSharedLUNDetector(ctx, 60*time.Second)
	// The holds this host keeps on iSCSI LUNs whose claims its rebuilds and
	// recreates moved: released only on positive evidence, re-judged here.
	go svc.RunLUNHoldResolver(ctx, 0)
	// Effective-capacity sampler: every host publishes what it is ACTUALLY
	// carrying (union of DB and runtime workloads), so placement counts rogue
	// runtimes and refuses hosts whose observation is stale or incomplete.
	go svc.RunCapacitySampler(ctx, 60*time.Second)

	// Start periodic IP scanner — discovers VM IPs via ARP/DHCP and broadcasts FDB entries.
	ipScanner := grpcapi.NewIPScanner(svc)
	go ipScanner.Start(ctx)

	svc.SetAntiEntropy(ae) // `lv cluster converge` kicks an immediate debounced pass
	// Record the founder's genesis decision of the per-NIC enforcement mode
	// (enforce) once it can; a cluster with no mode recorded observes. And keep
	// dnsmasq's host reservations in step with the NICs guarded on its
	// networks.
	go svc.SeedFirewallEnforcementLoop(ctx, 0, filepath.Join(d.cfg.DataDir, firewallInitialModeName))
	go svc.SeedFirewallSynfloodLoop(ctx, 0, filepath.Join(d.cfg.DataDir, firewallSynfloodDecisionName))
	svc.StartDHCPReservations(ctx, 0)

	// Converge this host's network devices on the replicated networks table
	// every 30s: a network created elsewhere is provisioned here, a deleted
	// one is torn down here. Started after the firewall reconciler so a pass
	// that records NAT/isolation intent has something to apply it.
	svc.StartNetworkReconciler(ctx, 0)

	// tenancy + billing engine. The webhook URL is empty
	// for most clusters; the emitter resolves to a no-op in that
	// case so production-without-billing is the zero-config default.
	tenancyEngine := tenancy.NewEngine(d.db, billing.NewWebhookEmitter(d.cfg.BillingWebhookURL))
	svc.SetTenancyEngine(tenancyEngine)

	// Seed the default notification webhook from config (#5), if any.
	d.seedNotificationDefaults(ctx)

	// wire the LXC runtime so the Containers RPCs work.
	// We always wire it — when lxc-* binaries aren't installed, the
	// individual RPCs surface the error from the binary lookup, which
	// is more useful than a blanket "container runtime not wired".
	// lxcRunner was created above (shared with the metrics collector).
	svc.SetContainerRuntime(grpcapi.NewLXCRuntimeAdapter(lxcRunner))
	// The runtime-inventory collector reads owner-epoch markers from the same
	// root the container checker converges them into.
	svc.SetContainersRoot(filepath.Join(d.cfg.DataDir, "containers"))
	// An LB's TLS files are read as root; never from litevirt's own keys.
	lb.SetProtectedDirs(d.cfg.PKIDir, d.cfg.DataDir)

	// Advertise the host's capabilities as labels so placement puts a workload
	// only on a host that can run it:
	//   - LXC (strict: litevirt.lxc=true, see corrosion.HostRunsContainers). The
	//     runtime is always wired, but the lxc-* binaries may be absent — probe
	//     for lxc-create.
	//   - vTPM (G1): both swtpm_setup and swtpm are needed to START a vTPM VM —
	//     libvirt runs swtpm_setup to initialize state, then swtpm. (The first
	//     G1 drill failed in swtpm_setup with swtpm alone present.)
	//     The label is also held false until a pass over the swtpm tree
	//     (vtpm_state_sync) has completed, so placement offers vTPM here only
	//     after the attempt to make its state synchronous; a pass that cannot
	//     raises vtpm_state_not_durable instead. The pass runs in its own
	//     goroutine and the probe waits at most vtpmPassWait for it.
	//   - Secure Boot: the secboot/MS OVMF pair (resolved above).
	// Asserted now, before the container checker starts, and re-asserted every
	// capabilityLabelInterval (keepCapabilityLabels says why).
	tpmAvailable := func() bool {
		_, errSwtpm := exec.LookPath("swtpm")
		_, errSetup := exec.LookPath("swtpm_setup")
		return errSwtpm == nil && errSetup == nil
	}
	capabilityLabels := []capabilityLabel{
		{key: corrosion.LabelLXCCapable, capable: lxc.Available},
		{key: corrosion.LabelTPMCapable, capable: tpmCapable},
		{key: corrosion.LabelSecureBootCapable, capable: firmwarePaths.SecureBootAvailable},
		// The live firmware move label holds a target to vTPM's own label
		// (tpmReady: swtpm present and this cycle's vtpm_state_sync pass completed); a
		// move's Prepare re-checks presence only (tpmAvailable), since the
		// label already gated it and a pass per Prepare would walk the tree
		// on every move.
		{key: corrosion.LabelFwLiveMigrate, capable: newFwLiveLabel(d.cfg.Migration, d.fwStore, firmwarePaths, d.virt.LibvirtVersion, tpmReady, vtpmSync.vtpmDurableErr)},
	}
	// A live firmware move's target re-checks the label's conditions itself,
	// live, in Prepare.
	// Prepare re-reads the last vTPM pass at move time: a label a cycle
	// stale never lets a move target a host whose vTPM state is not durable.
	svc.SetLiveFirmwareHost(newFwLiveHostCheck(d.cfg.Migration, d.fwStore, firmwarePaths, d.virt.LibvirtVersion, tpmAvailable, vtpmSync.vtpmDurableErr))
	asserted, err := assertCapabilityLabels(ctx, d.db, d.cfg.HostName, capabilityLabels)
	if err != nil {
		slog.Warn("set capability host labels failed; retrying in the background", "labels", asserted, "error", err)
		asserted = nil // nothing this daemon published stands on the row yet
	}
	go keepCapabilityLabels(ctx, d.db, d.cfg.HostName, capabilityLabels, asserted, capabilityLabelInterval)

	// Container reconciler + restart engine: every cycle, sync each locally-owned
	// container's cluster row to the LXC runtime's reality and auto-restart one
	// that stopped unexpectedly per its restart policy. Shares the runtime wired
	// above; operator-stopped containers are left alone (state_detail).
	ctChecker := health.NewContainerChecker(d.cfg.HostName, d.db, lxcRunner)
	ctChecker.SetDaemonDirs(d.cfg.DataDir, d.cfg.PKIDir)
	ctChecker.SetContainersRoot(filepath.Join(d.cfg.DataDir, "containers"))
	ctChecker.SetEventBus(svc.EventBus())
	// Runtime container re-key (Phase 4): corroborate a locally-running container
	// whose only live DB row points elsewhere against every workload-capable peer
	// before reclaiming it (a PK re-key).
	ctChecker.SetPeerContainerRuntimeChecker(svc.CheckPeerContainerRuntime)
	// Guarded v44 re-key WAL is emitted only after the operation protocol's
	// config kill-switch is on and both the operation + dependent capacity
	// capabilities have latched cluster-wide. Until then modern authority fails
	// closed; pre-authority rows retain the exact v1.3 envelope.
	ctChecker.SetGuardedContainerRekeyActive(func() bool {
		return d.cfg.Enforcement.OperationProtocol &&
			d.checker.Latched(capabilities.OperationProtocolV1) &&
			d.checker.Latched(capabilities.CapacityAdmissionV1)
	})
	ctChecker.SetContainerRekeyObserver(func(_, result string) { runtimeRepairMetrics.OwnerAssert("ct", result) })
	ctChecker.SetOrphanRuntimeObserver(observeOrphans)
	ctChecker.SetReplicaFreshness(d.db.ReplicaCaughtUp)
	// Split-brain safety gate (Phase 1): a container re-key needs local quorum once
	// enforced — wired before the container reconcile loop starts.
	ctChecker.SetGate(d.checker)
	ctChecker.SetRecoveryClaimGate(svc.RecoveryClaimGateForPendingProof)
	ctChecker.SetGateRefusedObserver(gateMetrics.Refused)
	ctChecker.SetStateWriteFailObserver(stateWriteMetrics.Failed)
	// The sweep holds the same per-container lock as this host's container
	// operations, so it never reconciles a container mid-create/start/stop.
	ctChecker.SetContainerLock(svc.TryLockContainer)
	go ctChecker.Start(ctx)

	// wire the libvirt blockdev-mirror driver so MoveVolume
	// supports running VMs without stopping them.
	svc.SetLiveMover(grpcapi.NewLibvirtLiveMover(d.virt))

	// (content rewrite): wire the guest-content backup engine.
	// Reads the guest disk over qemu's NBD pull-backup export (not the
	// qcow2 container), so full + incremental + the dirty bitmap all share
	// the guest-virtual address space — the correct, consistent model.
	// nil-safe: if BeginBackup fails, BackupSnapshot falls back to a full
	// container backup.
	svc.SetBackupSource(grpcapi.NewLibvirtBackupSource(d.virt))
	// Point-in-time copies fall back to an external disk-only snapshot when
	// no backup session opens (grpcapi/pit_copy.go, layer 2).
	svc.SetPointInTimeSnapshotter(d.virt)
	// A daemon that died while a layer-2 copy was in its window left the VM
	// on the overlay with no event: settle every such overlay now.
	go svc.SweepPITOverlays(ctx, svc.PITSweepReady(ctx))

	// wire the WebAuthn second-factor engine. Empty
	// rp_id disables — the gRPC handlers then return Unimplemented
	// instead of a confusing "missing config" surface.
	if d.cfg.WebAuthn.RPID != "" {
		wa, err := auth.NewWebAuthnService(d.db, auth.WebAuthnConfig{
			RPDisplayName: d.cfg.WebAuthn.RPDisplayName,
			RPID:          d.cfg.WebAuthn.RPID,
			RPOrigins:     d.cfg.WebAuthn.RPOrigins,
		})
		if err != nil {
			return fmt.Errorf("webauthn init: %w", err)
		}
		svc.SetWebAuthnService(wa)
	}

	// snapshot scheduler runner — built after `svc` exists so it
	// can reuse lockVM + pickDisk. Backup repo names resolve through
	// `backup_repos:` in config; an empty map disables the scheduler
	// effectively (every schedule errors with ErrNoRepoConfigured until
	// the operator adds a repo).
	d.snapScheduler.Runner = grpcapi.BackupRunnerForScheduler(svc, d.cfg.BackupRepos)
	svc.SetBackupRepos(d.cfg.BackupRepos) // let RPC handlers resolve repo names
	// Per-repo backup bandwidth limits. LoadConfig already refused a bad value.
	if bw, err := d.cfg.BackupBandwidthLimits(); err == nil {
		svc.SetBackupBandwidthLimits(bw)
	} else {
		slog.Error("backup_bwlimits", "error", err)
	}
	// Restore VMs a previous daemon left running (a crash, a restart, an
	// upgrade) are killed whether or not file restore is still enabled.
	frRunDir := fileRestoreRunDir(d.cfg.DataDir)
	frUIDBase := d.cfg.FileRestore.UIDBase
	if frUIDBase == 0 {
		frUIDBase = filerestore.DefaultUIDBase
	}
	if n := filerestore.SweepStale(frRunDir, frUIDBase, d.cfg.Containers.ContainerIDRange()); n > 0 {
		slog.Warn("file restore: killed restore VMs a previous daemon left running", "count", n)
	}
	if fr := d.cfg.FileRestore; fr.On() {
		if err := filerestore.EnsureRestoreUser(); err != nil {
			// File restore then refuses, naming the missing user.
			slog.Warn("file restore: no restore VM user", "error", err)
		}
		// Round-1 builds kept the boot files in data_dir, owned by qemu's
		// user; they are never read again.
		_ = os.RemoveAll(filepath.Join(d.cfg.DataDir, "file-restore", "cache"))
		idle := time.Duration(fr.IdleTimeoutSec) * time.Second
		if idle <= 0 {
			idle = 5 * time.Minute
		}
		svc.SetFileRestore(grpcapi.FileRestoreOptions{
			Launcher: filerestore.NewLauncher(filerestore.Config{
				QEMU: fr.QEMU, Kernel: fr.Kernel, ModulesDir: fr.ModulesDir,
				MemoryMiB: fr.MemoryMiB, RunAs: fr.RunAs,
				CacheDir: fileRestoreCacheDir(d.cfg.DataDir),
				RunDir:   frRunDir,
				OnTamper: svc.FileRestoreTampered,
				// The agent outlives the host's idle timeout by a minute, so
				// it only ever powers off on its own when the host is gone.
				AgentIdle: idle + time.Minute,
				Unsandboxed: filerestore.Barriers{
					Seccomp: fr.AllowUnsandboxed.Seccomp, MAC: fr.AllowUnsandboxed.MAC, Root: fr.AllowUnsandboxed.Root,
				},
				AllowSharedRunAs: fr.AllowSharedRunAs,
				UIDBase:          frUIDBase,
				ContainerIDs:     d.cfg.Containers.ContainerIDRange(),
			}),
			IdleTimeout:     idle,
			MaxSessions:     fr.MaxSessions,
			MaxExtractions:  fr.MaxExtractions,
			MaxExtractBytes: fr.ExtractLimit(),
		})
	}
	// While a key that lifts a restore VM barrier is set, this host carries
	// an informational file_restore_unsandboxed condition (resolved once it
	// is not).
	svc.ReconcileFileRestoreCondition(ctx, d.cfg.FileRestore.ReducedBarrierKeys())
	svc.SweepTransferStaging()                          // clear orphaned peer-transfer staging repos from a prior incarnation
	blockedCIDRs, _ := d.cfg.ImagePullBlockedPrefixes() // already validated in LoadConfig
	svc.SetImageLimits(d.cfg.MaxImageBytes, time.Duration(d.cfg.ImagePullTimeoutSec)*time.Second, blockedCIDRs)
	d.snapScheduler.ReplRunner = svc // *grpcapi.Server implements RunReplication
	go d.snapScheduler.Run(ctx)

	// Sweep staging temp files leaked by a prior hard crash (SIGKILL skips the
	// deferred cleanup of replicate/upload/import/restore temps — they'd
	// otherwise accumulate and fill the pool/image dirs). Then retry the
	// pool-file records marks SweepStaleStaging wrote until the replicated
	// rows are writable: on a new cluster failover_scope_v1 latches after the
	// first start (pool_records.go). Both in the background: they read every
	// pool directory, and one on an NFS mount whose server does not answer
	// blocked this start for good (lab 2 F-1; startup_bound.go).
	startStorageSweeps(ctx, svc)
	startLegacyImageProvenance(ctx, svc)

	// Now that the gRPC server exists, wire it as the failover coordinator's
	// replica promoter (auto_promote recovery) and start the coordinator.
	fc.Promoter = svc // *grpcapi.Server implements failover.ReplicaPromoter
	fc.Restorer = svc // implements failover.ContainerRestorer (tier-2 relocate-from-backup)
	fc.RelocateRestoreTimeout = time.Duration(d.cfg.ContainerRestoreTimeoutSec) * time.Second
	fc.OnFence = svc.NotifyHostFenced                                   // operator notification on fence (#5)
	fc.OnDiskStranded = svc.NotifyVMDiskStranded                        // a VM restarted elsewhere left its host-local disk behind
	fc.OnRootfsStranded = svc.NotifyCTRootfsStranded                    // a relocated container left its own rootfs behind
	fc.OnRecoveryStalled = svc.NotifyRecoveryStalled                    // a fenced host's recovery that is not proceeding
	fc.Events = svc.EventBus()                                          // a stopped workload left on a failed host
	fc.Metrics = metrics.NewFailoverMetrics()                           // structured failover counters (U9)
	fc.SafeFenceEnforce = d.cfg.Enforcement.SafeFenceDefault            // safe-fence kill-switch (config AND SafeFenceDefaultV1)
	fc.SharedStorageFenceEnforce = d.cfg.Enforcement.SharedStorageFence // decide-side shared-disk fence kill-switch (config AND SharedStorageFenceV1)
	// The coordinator half of lease-term enforcement: a local precheck that
	// refuses to stamp a superseded term. svc.SetLeaseTermEnforce above is the
	// executor half, and both read this one flag so the source and the enforcer
	// can never disagree about whether enforcement is on.
	fc.LeaseTermEnforce = d.cfg.Enforcement.LeaseTerm
	// Recovery claims (docs/design/recovery-claims.md §3.13): the coordinator
	// claims through the server's proposer before it mints a reschedule or
	// relocate proof (the server claims a promote itself, once it knows the
	// replica's host), and reads the server's enforcement predicate, so the
	// mint side and the executor side on this node read one answer.
	fc.Claimer = svc
	fc.RecoveryClaimEnforced = svc.RecoveryClaimEnforced
	// A VM recorded migrating on a failed host is recovered only once the
	// migration's target says it has no copy; one it runs is re-pointed there.
	fc.SettleMigratingRows = svc.SettleFailedSourceMigrations
	// The recovery-claim health conditions (ha.claim.stranded,
	// ha.voter.unavailable) and host.address_shared are the lease holder's to
	// write, like genesis.
	fc.ClaimHealth = svc.RecoveryClaimHealthTick
	// host.pressure is the lease holder's to write too, from each host's
	// probe answer, so a host whose disk is full is still described.
	fc.PressureHealth = svc.PressureHealthTick
	// Partition pause, the majority side: rely on a host's pause only with this
	// node's flag on AND partition_pause_v1 latched (every voter pauses), and
	// anchor the deadline on the later of the decision and the last contact.
	fc.PartitionPauseEnforced = func(ctx context.Context) bool {
		return d.cfg.Enforcement.PartitionPause && d.checker.Enforced(ctx, capabilities.PartitionPauseV1)
	}
	fc.LastContact = d.checker.LastContact
	fc.PeerClockSkew = d.checker.MeasuredClockSkew
	fc.PeerVoterGeneration = svc.PeerVoterGeneration
	fc.PeerPausesOnLoss = svc.PeerPausesOnLoss
	// Once pit_overlay is used, no VM recovery onto a peer whose Ping says it
	// is WAL-quarantined, or that does not answer (it may be a build that
	// knows nothing of overlays).
	fc.PeerRecoveryExclusions = svc.PeerRecoveryExclusions
	// A coordinator that was itself cut off moments ago decides no new fence
	// on the failure rows the cut left behind (a fleet-wide blip).
	fc.QuorumRegain = d.checker.InQuorumRegainGraceFor
	// Split-brain safety gate (Phase 1): the coordinator gates the reschedule
	// decide site + writes a durable proof; the reconciler validates/claims it
	// before start. Both are enforced only once split_brain_gate_v1 is
	// cluster-wide (fail-open/log-only until then).
	fc.Gate = d.checker // reconciler + svc gates were wired earlier (before their runtime work)
	fc.SetGateRefusedObserver(gateMetrics.Refused)
	// A self-fenced coordinator stops driving failover during the fence-timeout window.
	fc.SelfFenced = watchdogCtrl.Fenced
	// A coordinator that was itself suspended or starved a moment ago decides no
	// fence until it has watched for a full grace window (health/stall.go).
	fc.LocalStall = d.checker.InStallGrace
	// Automatic voter genesis runs on the leader-lease holder's tick
	// (docs/design/recovery-claims.md §4.2). Inert until voter_config_v1 has
	// durably latched, and once any voter generation exists.
	fc.VoterGenesis = svc.VoterGenesisTick
	// Cluster HA disarm: the peers' HA answers for the coordinator, the fence
	// candidates for the HA policy handler, the cache Ready answers from, and
	// the lease holder's first-use record of ha_disarm.
	d.wirePeerHAState(fc, svc)
	d.wireFenceCandidates(svc)
	d.startHAPolicyCache(ctx, svc)
	d.startHADisarmPreRecord(ctx, fc)
	d.startReturningBootPreRecord(ctx, fc)
	// Give each project created before project_incarnation_v1 latched its
	// stable incarnation, once release_2027_01_v1 has latched (project_adoption).
	d.startProjectAdoption(ctx)
	go fc.Start(ctx)
	// Adopt each decided voter generation once its certificate verifies,
	// importing claim state first where this node is a member of it (§4.4).
	go d.runVoterAdoption(ctx, svc)

	// The global ISO library in sync mode: bring this host's copy of every
	// library file to the recorded version (iso_library.go).
	go d.runISOLibrarySync(ctx, svc)

	// Certificates this node serves: re-record a host certificate renewed in
	// place, export expiry, and notify ahead of it (cert_watch.go).
	d.certWatch = newCertWatch(d.cfg.HostName, d.cfg.PKIDir, d.db, svc, metrics.NewCertMetrics())
	go d.certWatch.run(ctx)

	// Peer self-upgrade: a daemon that comes back on an old binary (e.g. it was
	// down during a cluster upgrade) pulls the newer binary from a healthy peer
	// and re-execs. Default on; disable with auto_upgrade.from_peer: false.
	if d.cfg.AutoUpgrade.FromPeerEnabled() {
		go svc.RunSelfUpgradeWatcher(ctx, d.cfg.AutoUpgrade.Interval())
	} else {
		slog.Info("peer self-upgrade disabled (auto_upgrade.from_peer: false)")
	}

	// Reap orphaned auto DNS records (VMs deleted without their A-record being
	// removed). Runs an initial sweep shortly after start (clears pre-existing
	// orphans on upgrade) then periodically. Idempotent + grace-windowed, so
	// safe to run on every node.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(90 * time.Second):
		}
		svc.ReapOrphanDNSRecords(ctx)
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				svc.ReapOrphanDNSRecords(ctx)
			}
		}
	}()

	// refresh group caches from external realms (LDAP /
	// OIDC) every 5 min. Errors are per-realm and logged but not fatal
	// — one IdP being down doesn't take the cluster offline.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if errs := d.realmRegistry.SyncAll(ctx); len(errs) > 0 {
					for name, err := range errs {
						slog.Warn("realm sync failed", "realm", name, "error", err)
					}
				}
			}
		}
	}()

	rpcMetrics := metrics.NewRPCMetrics()
	// Established connections are re-judged every few seconds (pki.ConnTracker):
	// one made with a certificate since revoked, or with a host certificate a
	// renewal replaced, drains and is closed, and its client re-handshakes. The
	// auth interceptors refuse a new RPC on such a connection at once, without
	// waiting for a sweep (Server.connIdentityGate).
	connTracker := pki.NewConnTracker(d.cfg.PKIDir)
	go connTracker.Run(ctx, connSweepInterval, func() func(pki.TrackedConn) pki.Verdict { return svc.ConnJudge(ctx) })
	grpcOpts := []grpc.ServerOption{
		grpc.Creds(connTracker.ServerCreds(credentials.NewTLS(tlsCfg))),
		grpc.StatsHandler(connTracker.StatsHandler()),
		grpc.ChainUnaryInterceptor(serverUnaryInterceptors(rpcMetrics, svc)...),
		grpc.ChainStreamInterceptor(serverStreamInterceptors(rpcMetrics, svc)...),
		// Defense-in-depth for the legacy unary state-dump/replication paths: the
		// 4 MiB gRPC default silently failed a large full-state dump (the bug
		// StreamStateDump fixes), and a big PushMutations batch could trip it too.
		// StreamStateDump itself stays well under this; this only backstops the
		// non-chunked paths during/after a mixed-version rollout.
		grpc.MaxRecvMsgSize(grpcMaxMsgSize),
		grpc.MaxSendMsgSize(grpcMaxMsgSize),
	}
	// otelgrpc server handler (only when tracing is active): creates a server span
	// per RPC and extracts inbound W3C trace context, so a peer-mesh call
	// (migrate/failover/replicate) continues the caller's trace. Empty when off —
	// no otel in the serve path unless an OTLP endpoint is configured.
	grpcOpts = append(grpcOpts, obs.ServerOptions()...)
	// Keepalive: permit the pings peers send (pki.PeerDial), and detect a
	// client that died with a call open.
	grpcOpts = append(grpcOpts, pki.PeerServerOptions()...)
	d.grpcSrv = grpc.NewServer(grpcOpts...)

	// Every setter has run: the firmware moves locked at the journal barrier
	// are recovered from here (review D2-13 N-1). Then, every minute, a
	// parked move's blocked call is retried, fence resolution tried, and
	// each owed DISCARD sent (spec §8.1).
	svc.MarkStartupWired()
	go svc.RunFirmwareMoveRecovery(ctx)

	pb.RegisterLiteVirtServer(d.grpcSrv, svc)

	lis, err := d.listenGRPC()
	if err != nil {
		return err
	}

	slog.Info("litevirtd starting",
		"host", d.cfg.HostName,
		"grpc", fmt.Sprintf("0.0.0.0:%d", d.cfg.GRPCPort),
		// From the metrics server, not reassembled: this line said 0.0.0.0
		// unconditionally, so a host that had applied metrics_bind: 127.0.0.1
		// got two startup lines asserting opposite things, and the louder one
		// was wrong. Reads "disabled" when metrics_port is 0.
		"metrics", d.metricsAddrForBanner(),
		"ui", fmt.Sprintf("%s:%d", d.cfg.UIBind, d.cfg.UIPort),
	)

	// Start web UI (connects back to local gRPC as a client).
	go func() {
		// Recycled when this host's certificate is renewed: the connection
		// made with the replaced one accepts no new RPC (pki.RecyclingConn).
		localConn, err := d.localRecyclingConn()
		if err != nil {
			slog.Warn("UI gRPC dial failed", "error", err)
			return
		}
		uiClient := pb.NewLiteVirtClient(localConn)
		uiSrv, err := ui.NewServer(uiClient, d.cfg.HostName)
		if err != nil {
			slog.Warn("UI server init failed", "error", err)
			return
		}
		// hand the UI a corrosion DB handle so read-only
		// pages (security-groups, etc.) can query cluster state without
		// adding a dedicated gRPC RPC for every list view.
		uiSrv.SetCorrosionDB(d.db)
		uiSrv.SetBackupRepos(d.cfg.BackupRepos)
		uiSrv.SetWSOriginPatterns(d.cfg.UIAllowedOrigins)
		// Validated at LoadConfig; a parse error here cannot happen.
		proxies, _ := auth.ParseTrustedProxies(d.cfg.TrustedProxies)
		uiSrv.SetTrustedProxies(proxies)
		// UI TLS (acme.go): a custom certificate (`lv host ui-cert set`), else
		// ACME (HTTP-01 on :80, or DNS-01), else the cluster certificate. The
		// listener re-decides TLS vs plain HTTP while running, so installing or
		// clearing a custom certificate needs no restart.
		uiTLS, challenge := d.buildUITLS(ctx)
		startACMEChallengeServer(ctx, challenge)
		d.certWatch.addUI(uiTLS)
		uiAddr := fmt.Sprintf("%s:%d", d.cfg.UIBind, d.cfg.UIPort)
		warnPlainUI(d.cfg.UIBind, uiTLS.wantTLS())
		warnOIDCBehindProxy(d.cfg)
		uiSrv.StartCollector(ctx)
		if err := uiSrv.ServeSupervised(ctx, uiAddr, uiTLS.tlsConfig(), uiTLS.wantTLS, 5*time.Second); err != nil {
			slog.Warn("UI server stopped", "error", err)
		}
	}()

	// Start REST API gateway.
	if d.cfg.RESTPort > 0 {
		go func() {
			restConn, err := d.localRecyclingConn()
			if err != nil {
				slog.Warn("REST gRPC dial failed", "error", err)
				return
			}
			restClient := pb.NewLiteVirtClient(restConn)
			restSrv := restapi.NewServer(restClient, "")
			proxies, _ := auth.ParseTrustedProxies(d.cfg.TrustedProxies)
			restSrv.SetTrustedProxies(proxies)
			restAddr := fmt.Sprintf("127.0.0.1:%d", d.cfg.RESTPort)
			if err := restSrv.ListenAndServe(restAddr); err != nil {
				slog.Warn("REST API server stopped", "error", err)
			}
		}()
	}

	// Handle shutdown, re-exec, and uninstall signals.
	shutdownDone := make(chan struct{})
	grpcStopped := make(chan struct{})
	reexecRequested := false
	uninstalled := false
	go func() {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			// A graceful stop (SIGTERM from `systemctl restart/stop`) must not
			// look like a host failure: flag ourselves 'upgrading' so peers skip
			// fence candidacy during the brief downtime. We set 'active' again on
			// healthy startup; the failover coordinator still fences a host stuck
			// 'upgrading' past its timeout, so a host that never returns fails
			// over. (Re-exec already runs under 'upgrading'; uninstall is removing
			// the host, so neither needs this.)
			d.markRestarting()
		case <-svc.ReExecCh:
			slog.Info("re-exec requested after upgrade")
			reexecRequested = true
		case <-svc.ShutdownCh:
			slog.Info("shutdown requested by uninstall")
			uninstalled = true
		}
		// Bounded whatever the RPCs in flight do: one stuck on storage that
		// does not answer must not hold the restart (stopGRPC). stopServing
		// closes grpcStopped as soon as that stop returns or is given up on.
		stopServing(d.grpcSrv, svc, grpcGracefulStop, grpcForcedStop, grpcStopped, func() {
			// A vfio-pci unbind still blocked in the kernel keeps this process alive
			// past every step below; name the devices so an operator knows which
			// holder to stop.
			vfio.LogStuckUnbinds()
			// A drain returns before its failback records are written, and this
			// is the host it drained: give them a moment to land while the
			// replicator still runs, and name every VM whose record is lost.
			svc.FinishDrainRecords(grpcapi.DrainRecordStopWait)
		})
		if d.fwReconciler != nil {
			// No log line outlives the listener: once this process exits,
			// another program could take the group.
			stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			fwLogging.Stop(stopCtx)
			cancel()
			d.fwReconciler.Stop()
		}
		if d.snapScheduler != nil {
			d.snapScheduler.Stop()
		}
		repl.Stop()
		// The database closes first: closing libvirt fails the calls still
		// waiting on it, and their error paths would otherwise write what
		// that failure is not (a held start recorded failed over a domain
		// libvirtd goes on to start).
		d.closeDatabase()
		d.virt.Close()
		close(shutdownDone)
	}()

	serveErrs := make(chan error, 1)
	go func() { serveErrs <- d.grpcSrv.Serve(lis) }()
	// Serve returns only once a stop has finished, and a stop can wait on a
	// handler stuck in the kernel: once the shutdown's stop is over, Serve
	// is waited on only briefly (awaitServe).
	serveErr := awaitServe(serveErrs, grpcStopped, serveReturnBound)

	// Wait for cleanup to finish (replicator, libvirt, DB) before returning,
	// but cap at 15s so we don't hang longer than systemd's stop timeout.
	select {
	case <-shutdownDone:
	case <-time.After(15 * time.Second):
		slog.Warn("shutdown cleanup timed out after 15s, exiting anyway")
	}

	if reexecRequested {
		return ErrReExec
	}
	// Uninstall has already removed the unit files and the binary. Under
	// Restart=always systemd would restart a unit whose ExecStart no longer
	// exists, so this exit has to be distinguishable from an ordinary one — the
	// unit's RestartPreventExitStatus pins the status the caller exits with.
	if uninstalled {
		return ErrUninstalled
	}

	// Serve returns ErrServerStopped on graceful shutdown — not a real error.
	if serveErr != nil && serveErr != grpc.ErrServerStopped {
		return fmt.Errorf("gRPC serve: %w", serveErr)
	}
	return nil
}

// ErrReExec is returned by Run when the daemon should re-exec itself
// after a binary upgrade.
var ErrReExec = fmt.Errorf("re-exec requested")

// ErrUninstalled is returned by Run after an uninstall removed this node. The
// caller must exit with systemdunit.UninstallExitCode so Restart=always does not
// restart a unit that no longer has a binary to run.
var ErrUninstalled = fmt.Errorf("uninstalled")

func (d *Daemon) registerHost(ctx context.Context) error {
	// Get system resources from libvirt
	cpus, memMiB, err := d.virt.NodeInfo()
	if err != nil {
		return err
	}

	// Get disk total summed across all configured storage pools.
	diskTotalGiB := d.sumPoolDiskTotalGiB(ctx)

	// Get cert serial
	serial, err := pki.CertSerial(d.cfg.PKIDir + "/host.crt")
	if err != nil {
		serial = "unknown"
	}

	addr := d.hostAddress()

	return corrosion.RegisterHost(ctx, d.db, corrosion.HostRecord{
		Name:          d.cfg.HostName,
		Address:       addr,
		SSHUser:       "root",
		SSHPort:       22,
		GRPCPort:      d.cfg.GRPCPort,
		State:         "active",
		CertSerial:    serial,
		CPUTotal:      cpus,
		MemTotal:      memMiB,
		DiskTotal:     diskTotalGiB,
		FenceStrategy: "best-effort",
		Version:       d.cfg.Version,
	})
}

// ensureClusterRecord derives the `cluster` row from this node's CA certificate
// when the cluster does not have one yet.
//
// Nothing else ever wrote that row: `lv host init` mints the PKI, the daemon
// applies the schema and registers a host, and no path anywhere inserted it. So
// every reader of it — the cluster fingerprint that is the first component of
// every NetBox identity litevirt mints, and the cluster name — found nothing on
// a real installation, and the whole NetBox integration was inert outside tests
// that seeded the row by hand.
//
// The WRITE is local-only, because this call is unconditional and reaches every
// installation on the first start after an upgrade: a replicated first-ever
// `cluster` statement shape would stall the replication stream of every peer
// still on the previous build. The ROW is still replicated — anti-entropy
// carries the table, and every node derives the same value from the shared CA.
// See corrosion.EnsureClusterRecord.
//
// A failure is LOGGED, not fatal. This is a heal, not a precondition: a node
// with no CA on disk yet, or a database that refused one read, must still boot —
// the paths that need the row already refuse fail-closed without it, and the
// next start heals again.
func (d *Daemon) ensureClusterRecord(ctx context.Context) {
	if err := corrosion.EnsureClusterRecord(ctx, d.db, d.cfg.PKIDir); err != nil {
		slog.Warn("could not derive the cluster record from this node's CA; "+
			"NetBox identities cannot be minted until it exists", "error", err)
	}
}

// reconcileHostAddress rewrites this host's address when the row disagrees with
// what the daemon now believes its address to be.
//
// registerHost cannot do it: InsertHost is a plain INSERT, so on every start
// after the first it is a no-op and the address recorded at bootstrap is
// permanent. That address comes from getOutboundIP() when advertise_address is
// unset — the source IP toward the DEFAULT route, which on a multi-homed host is
// the wrong interface. Setting advertise_address afterwards is the documented fix
// for exactly that, and without this it changed nothing.
//
// It matters beyond this node. Peers dial hosts.address, and `lv host add` seeds
// the new node's join_peers from ListHosts, so one wrong row is copied into the
// gossip configuration of every host added after it. In the lab that produced four
// nodes advertising the same NAT address, each dialling itself.
//
// Only on a real change, so an unchanged address cannot restamp updated_at on
// every restart and win LWW against a genuine concurrent write from another node.
func (d *Daemon) reconcileHostAddress(ctx context.Context) error {
	if err := d.db.OwnRowWritable(d.cfg.HostName); err != nil {
		return nil // held: the own-row reconcile runs this again when it opens
	}
	want := d.hostAddress()
	h, err := corrosion.GetHost(ctx, d.db, d.cfg.HostName)
	if err != nil || h == nil || h.Address == want {
		return err
	}
	slog.Warn("correcting this host's recorded address; peers dial this value and it is "+
		"copied into the gossip configuration of hosts added later",
		"host", d.cfg.HostName, "was", h.Address, "now", want)
	return d.db.Execute(ctx,
		`UPDATE hosts SET address = ?, updated_at = ? WHERE name = ?`,
		want, d.db.NowTS(), d.cfg.HostName)
}

// statfsFn is syscall.Statfs, held in a variable so a test can give distinct
// paths distinct filesystems — every temp dir a test can make sits on one.
var statfsFn = syscall.Statfs

// poolStatfs is statfsFn under storage.Bounded. A pool's directory can be on
// an NFS mount (an nfs pool's --target, a dir pool on an fstab mount) whose
// server does not answer, and a statfs there blocks in the kernel until it
// does: at daemon start that held the gRPC server from ever serving, and the
// peers fenced the host (lab 2 F-1). It returns an error a caller treats as a
// statfs that failed.
func poolStatfs(path string, st *syscall.Statfs_t) error {
	statfs := statfsFn
	got, err := storage.Bounded("statfs (pool)", path, func() (syscall.Statfs_t, error) {
		var s syscall.Statfs_t
		err := statfs(path, &s)
		return s, err
	})
	if err != nil {
		return err
	}
	*st = got
	return nil
}

// sumPoolDiskTotalGiB returns this host's disk capacity in GiB: the statfs
// total of every filesystem holding one of its storage pools, each filesystem
// counted once. It is the hosts.disk_total recorded at startup, and the
// fallback pb.Host reports before any pool row carries capacity.
//
// The pools are the config pools (or the data directory when config names
// none, as registerStoragePools does) PLUS this host's file-based rows in the
// replicated storage_pools table. Walking config alone left out every pool
// created through the API, which never appears in config.yaml: a host with a
// 7 TiB API pool reported its 438 GiB root filesystem as its whole capacity
// (colonelpanik/litevirt#142).
//
// A config pool also has a row of its own, and two pools on different paths
// can share one filesystem, so targets are deduplicated by the filesystem
// statfs reports (fsid), not by path. A filesystem reporting no fsid falls
// back to its cleaned path, so missing identities never collapse distinct
// paths into one.
func (d *Daemon) sumPoolDiskTotalGiB(ctx context.Context) int {
	var targets []string
	if len(d.cfg.StoragePools) == 0 {
		targets = append(targets, d.cfg.DataDir)
	}
	for _, p := range d.cfg.StoragePools {
		if p.Target != "" {
			targets = append(targets, p.Target)
		}
	}
	if d.db != nil {
		rows, err := corrosion.ListStoragePoolsForHost(ctx, d.db, d.cfg.HostName)
		if err != nil {
			slog.Warn("host disk total: list storage pools; counting config pools only", "error", err)
		}
		for _, p := range rows {
			if fileBasedPoolDriver(p.Driver) && p.Target != "" {
				targets = append(targets, p.Target)
			}
		}
	}

	type fsKey struct {
		fsid syscall.Fsid
		path string
	}
	seen := make(map[fsKey]bool)
	var totalBytes uint64
	for _, t := range targets {
		var st syscall.Statfs_t
		if err := poolStatfs(t, &st); err != nil {
			continue
		}
		key := fsKey{fsid: st.Fsid}
		if st.Fsid == (syscall.Fsid{}) {
			key = fsKey{path: filepath.Clean(t)}
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		totalBytes += st.Blocks * uint64(st.Bsize)
	}
	return int(totalBytes / (1024 * 1024 * 1024))
}

// registerStoragePools upserts all configured storage pools into the cluster DB
// with current capacity from syscall.Statfs.
func (d *Daemon) registerStoragePools(ctx context.Context) {
	pools := d.cfg.StoragePools
	if len(pools) == 0 {
		pools = []StoragePoolConfig{{
			Name:   "default",
			Driver: "local",
			Target: d.defaultPoolDir(ctx),
		}}
	}
	// <data_dir>/disks on NFS is an export no pool on any host may hold:
	// every row this host registers records it (storage.DataDisksExportOption).
	disksExp, disksErr := nfsExportOfDirPool(d.cfg.DataDir, StoragePoolConfig{Driver: "dir", Target: filepath.Join(d.cfg.DataDir, "disks")})
	configured := map[string]bool{}
	for _, p := range pools {
		configured[p.Name] = true
		rec := corrosion.StoragePoolRecord{
			HostName: d.cfg.HostName,
			Name:     p.Name,
			Driver:   p.Driver,
			Source:   p.Source,
			Target:   p.Target,
			State:    "active",
		}
		// What the row records now, kept where it cannot be judged afresh.
		cur, curFound, curErr := corrosion.GetStoragePool(ctx, d.db, d.cfg.HostName, p.Name)
		if curErr != nil {
			curFound = false
		}
		// A directory pool on an NFS mount records the export it is on, so
		// other hosts compare their pools against it (storage.NFSExportOption).
		// One whose directory does not resolve in time (its NFS server does
		// not answer) keeps the export it recorded, never loses it.
		opts := map[string]string{}
		exp, expErr := nfsExportOfDirPool(d.cfg.DataDir, p)
		if expErr != nil && curFound {
			exp = cur.Options[storage.NFSExportOption]
		}
		if exp != "" {
			opts[storage.NFSExportOption] = exp
		}
		dexp := disksExp
		if disksErr != nil && curFound {
			dexp = cur.Options[storage.DataDisksExportOption]
		}
		if dexp != "" {
			opts[storage.DataDisksExportOption] = dexp
		}
		// A ceph pool's row carries this host's key fingerprint, which the
		// pool's other hosts compare theirs against (grpcapi/ceph_secrets.go).
		if strings.EqualFold(p.Driver, "ceph") {
			if fp, ok, err := storage.CephKeyFingerprintOf(p.Options); err == nil && ok {
				opts[storage.CephKeyFPOption] = fp
			}
		}
		if len(opts) > 0 {
			rec.Options = opts
		}
		// An iscsi pool's state is its session's, which the session reconcile
		// records (grpcapi.ReconcileISCSISessions): kept, not reset to active.
		if strings.EqualFold(p.Driver, "iscsi") {
			if curFound && strings.EqualFold(cur.Driver, "iscsi") && cur.State != "" {
				rec.State = cur.State
			}
		}
		// An nfs pool's degraded is its mount's, which the mount reconcile
		// records (grpcapi.ReconcileNFSMounts): kept, not reset to active —
		// an unmounted mount point is a local directory statfs measures.
		if strings.EqualFold(p.Driver, "nfs") {
			if curFound && strings.EqualFold(cur.Driver, "nfs") && cur.State == grpcapi.PoolStateDegraded {
				rec.State = cur.State
			}
		}
		if p.Target != "" {
			var st syscall.Statfs_t
			if err := poolStatfs(p.Target, &st); err == nil {
				rec.TotalBytes = int64(st.Blocks * uint64(st.Bsize))
				rec.UsedBytes = int64((st.Blocks - st.Bavail) * uint64(st.Bsize))
			} else {
				rec.State = "error"
				if storage.IsFSNoAnswer(err) && curFound {
					// Not measured: the last measurement stands.
					rec.TotalBytes, rec.UsedBytes = cur.TotalBytes, cur.UsedBytes
				}
				slog.Warn("storage pool statfs failed", "pool", p.Name, "target", p.Target, "error", err)
			}
		}
		if err := corrosion.UpsertStoragePool(ctx, d.db, rec); err != nil {
			slog.Warn("failed to register storage pool", "pool", p.Name, "error", err)
		}
	}
	d.refreshDirPoolExports(ctx, configured)
	d.ensureGlobalISOLibrary(ctx)
}

// ensureGlobalISOLibrary gives this host the built-in global ISO library pool
// ("isos", no project, <data_dir>/pools/isos) when it has no pool of that name. An
// operator who puts the library on shared storage replaces the row with
// `lv pool create isos --driver nfs ... --option content=iso` on each host,
// which this then leaves alone.
func (d *Daemon) ensureGlobalISOLibrary(ctx context.Context) {
	if d.db == nil {
		return
	}
	if rec, ok, err := corrosion.GetStoragePool(ctx, d.db, d.cfg.HostName, grpcapi.GlobalISOLibraryName); err != nil || ok {
		if ok && rec.Project != "" {
			slog.Warn("global ISO library: this host has a project-owned pool named isos, so it has no global library; rename that pool",
				"host", d.cfg.HostName, "project", rec.Project)
		} else if ok && !corrosion.IsBuiltinISOLibraryRow(rec) {
			slog.Info("global ISO library: this host's isos pool is not the daemon's (shared storage, say); it is the global library only in shared mode",
				"host", d.cfg.HostName, "target", rec.Target)
		}
		return
	}
	dir := filepath.Join(d.cfg.DataDir, storage.ISOLibraryDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		slog.Warn("global ISO library: create directory", "dir", dir, "error", err)
		return
	}
	if err := corrosion.UpsertStoragePool(ctx, d.db, corrosion.StoragePoolRecord{
		HostName: d.cfg.HostName,
		Name:     grpcapi.GlobalISOLibraryName,
		Driver:   "dir",
		Target:   dir,
		Options:  grpcapi.GlobalISOLibraryOptions(),
		State:    "active",
	}); err != nil {
		slog.Warn("global ISO library: register pool", "error", err)
	}
}

// runISOLibrarySync runs a sync pass of the global ISO library every 30s, and,
// on a ticker of its own (a sync pass can wait long on hashing), sweeps this
// host's installer-ISO records of VMs that no longer exist every 5 minutes.
func (d *Daemon) runISOLibrarySync(ctx context.Context, svc *grpcapi.Server) {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := svc.SweepISOIdentities(ctx); err != nil {
					slog.Warn("installer ISO records: sweep", "error", err)
				}
			}
		}
	}()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := svc.SyncISOLibrary(ctx); err != nil {
				slog.Warn("global ISO library: sync", "error", err)
			}
		}
	}
}

// refreshDirPoolExports records, on this host's directory pools created
// through the API, the export each one's directory is on now (or drops a
// recorded one that no longer holds): read at start from the mount table, so
// a pool created by an older build, or whose fstab mount has changed, is
// compared on other hosts by what it is today. Only rows whose record
// differs are written.
func (d *Daemon) refreshDirPoolExports(ctx context.Context, configured map[string]bool) {
	rows, err := corrosion.ListStoragePoolsForHost(ctx, d.db, d.cfg.HostName)
	if err != nil {
		slog.Warn("storage pools: cannot refresh recorded NFS exports", "error", err)
		return
	}
	for _, r := range rows {
		switch strings.ToLower(r.Driver) {
		case "", "local", "dir", "btrfs":
		default:
			continue
		}
		if configured[r.Name] {
			continue
		}
		exp, err := nfsExportOfDirPool(d.cfg.DataDir, StoragePoolConfig{Driver: r.Driver, Source: r.Source, Target: r.Target})
		if err != nil {
			// Its directory did not resolve in time: the recorded export
			// stands until it can be judged.
			slog.Warn("storage pools: cannot judge which NFS export a pool is on; its record is kept", "pool", r.Name, "error", err)
			continue
		}
		if r.Options[storage.NFSExportOption] == exp {
			continue
		}
		opts := make(map[string]string, len(r.Options)+1)
		for k, v := range r.Options {
			opts[k] = v
		}
		if exp == "" {
			delete(opts, storage.NFSExportOption)
		} else {
			opts[storage.NFSExportOption] = exp
		}
		r.Options = opts
		if err := corrosion.UpsertStoragePool(ctx, d.db, r); err != nil {
			slog.Warn("storage pools: cannot record a pool's NFS export", "pool", r.Name, "error", err)
		}
	}
}

// defaultPoolDir is where the built-in default pool lives: where this host's
// registered default pool already is when that is <data_dir>/disks (an older
// cluster's — it is not moved), otherwise <data_dir>/pools/default, its own
// directory.
func (d *Daemon) defaultPoolDir(ctx context.Context) string {
	legacy := filepath.Join(d.cfg.DataDir, "disks")
	if rec, ok, err := corrosion.GetStoragePool(ctx, d.db, d.cfg.HostName, "default"); err == nil && ok &&
		rec.Driver == "local" && (rec.Target == legacy || rec.Target == "") {
		return legacy
	}
	defDir := filepath.Join(d.cfg.DataDir, "pools", "default")
	if err := os.MkdirAll(defDir, 0o755); err != nil {
		slog.Warn("create default pool directory", "dir", defDir, "error", err)
	}
	return defDir
}

// nfsExportOfDirPool is the export a configured directory pool's directory is
// on ("" when on none, or not a directory pool). An error: it cannot be told
// (the directory did not resolve in time, storage.NFSBackingOf), and the
// caller keeps what it recorded.
func nfsExportOfDirPool(dataDir string, p StoragePoolConfig) (string, error) {
	var dir string
	switch strings.ToLower(p.Driver) {
	case "", "local":
		dir = p.Target
		if dir == "" {
			dir = filepath.Join(dataDir, "disks")
		}
	case "dir":
		dir = p.Target
	case "btrfs":
		dir = p.Source
	default:
		return "", nil
	}
	if dir == "" {
		return "", nil
	}
	mt, err := storage.ReadMountTable()
	if err != nil {
		return "", nil
	}
	b, err := mt.NFSBackingOf(dir)
	if storage.IsFSNoAnswer(err) {
		return "", err
	}
	if err != nil || b == nil {
		return "", nil
	}
	return b.Export.String(), nil
}

// hardenNFSPoolMounts hardens in place, at start, every NFS pool of this host
// whose own export is mounted without nosuid,nodev,noexec,nosymfollow (by
// hand, or by an earlier build): a bind remount changes only that mount's
// flags, so the VMs running from it are untouched. It reports, at ERROR, a
// pool whose mount point holds another export, or whose remount failed: the
// server's pool check refuses such a pool until that is fixed.
func (d *Daemon) hardenNFSPoolMounts(ctx context.Context) {
	var cfgs []storage.Config
	for _, p := range d.cfg.StoragePools {
		cfgs = append(cfgs, storage.Config{Driver: p.Driver, Source: p.Source, Target: p.Target, Options: p.Options})
	}
	if rows, err := corrosion.ListStoragePoolsForHost(ctx, d.db, d.cfg.HostName); err == nil {
		for _, p := range rows {
			cfgs = append(cfgs, storage.Config{Driver: p.Driver, Source: p.Source, Target: p.Target, Options: p.Options})
		}
	}
	for _, c := range cfgs {
		if !strings.EqualFold(c.Driver, "nfs") {
			continue
		}
		if err := storage.CheckNFSMountHardened(d.cfg.DataDir, c); err != nil {
			slog.Error("NFS pool's mount point holds another export, or its export is mounted without nosuid,nodev,noexec,nosymfollow and could not be hardened in place; the pool is refused",
				"source", c.Source, "target", c.Target, "error", err)
		}
	}
}

// refreshStoragePools periodically updates storage pool capacity in the DB.
func (d *Daemon) refreshStoragePools(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.registerStoragePools(ctx)
			d.refreshDBPoolCapacity(ctx)
		}
	}
}

// cephSecretReconcileInterval is how often the ceph pools' libvirt secrets are
// checked: a libvirtd restart drops them (they are ephemeral), and a keyring
// rotated on disk changes the value they must hold.
const cephSecretReconcileInterval = 30 * time.Second

// runCephSecretReconcile keeps the ceph pools' libvirt secrets defined and
// current until ctx is cancelled (grpcapi.ReconcileCephSecrets), and scans
// the pools' trash for leftovers no purge here tracks — at start, and every
// grpcapi.CephTrashScanInterval after (grpcapi.ScanCephTrash). Here, not in
// Run's synchronous first reconcile: a cluster that does not answer must not
// hold the daemon's start.
func (d *Daemon) runCephSecretReconcile(ctx context.Context) {
	ticker := time.NewTicker(cephSecretReconcileInterval)
	defer ticker.Stop()
	var lastScan time.Time
	scan := func() {
		if d.svc != nil && time.Since(lastScan) >= grpcapi.CephTrashScanInterval {
			lastScan = time.Now()
			d.svc.ScanCephTrash(ctx)
		}
	}
	scan()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if d.svc != nil {
				scan()
				d.svc.ReconcileCephSecrets(ctx)
			}
		}
	}
}

// runISCSISessionReconcile checks this host's iscsi pools' sessions at once,
// then every grpcapi.ISCSISessionReconcileInterval, until ctx is cancelled.
func (d *Daemon) runISCSISessionReconcile(ctx context.Context) {
	if d.svc == nil {
		return
	}
	d.svc.ReconcileISCSISessions(ctx)
	ticker := time.NewTicker(grpcapi.ISCSISessionReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.svc.ReconcileISCSISessions(ctx)
		}
	}
}

// runMACCollisionReconcile looks for NICs of two workloads on one MAC at
// once, then every grpcapi.MACCollisionReconcileInterval, until ctx is
// cancelled.
func (d *Daemon) runMACCollisionReconcile(ctx context.Context) {
	if d.svc == nil {
		return
	}
	d.svc.ReconcileMACCollisions(ctx)
	ticker := time.NewTicker(grpcapi.MACCollisionReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.svc.ReconcileMACCollisions(ctx)
		}
	}
}

// runNFSMountReconcile checks this host's nfs pools' mounts at once, then
// every grpcapi.NFSMountReconcileInterval, until ctx is cancelled.
func (d *Daemon) runNFSMountReconcile(ctx context.Context) {
	if d.svc == nil {
		return
	}
	d.svc.ReconcileNFSMounts(ctx)
	ticker := time.NewTicker(grpcapi.NFSMountReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.svc.ReconcileNFSMounts(ctx)
		}
	}
}

// refreshDBPoolCapacity updates total/used bytes for every file-based storage
// pool registered for THIS host in the DB — including pools created at runtime
// via `lv pool create`. registerStoragePools only scans cfg.StoragePools, so
// runtime-created pools (not in config) were never statfs'd and showed 0B/0B.
func (d *Daemon) refreshDBPoolCapacity(ctx context.Context) {
	pools, err := corrosion.ListStoragePoolsForHost(ctx, d.db, d.cfg.HostName)
	if err != nil {
		slog.Warn("refresh pool capacity: list pools", "error", err)
		return
	}
	for _, p := range pools {
		if !fileBasedPoolDriver(p.Driver) || p.Target == "" {
			continue
		}
		var st syscall.Statfs_t
		if err := poolStatfs(p.Target, &st); err != nil {
			slog.Warn("refresh pool capacity: statfs", "pool", p.Name, "target", p.Target, "error", err)
			p.State = "error"
			_ = corrosion.UpsertStoragePool(ctx, d.db, p)
			continue
		}
		p.TotalBytes = int64(st.Blocks * uint64(st.Bsize))
		p.UsedBytes = int64((st.Blocks - st.Bavail) * uint64(st.Bsize))
		// An nfs pool's degraded is its mount's (grpcapi.ReconcileNFSMounts),
		// kept: the statfs above measured the local directory under it.
		if !strings.EqualFold(p.Driver, "nfs") || p.State != grpcapi.PoolStateDegraded {
			p.State = "active"
		}
		if err := corrosion.UpsertStoragePool(ctx, d.db, p); err != nil {
			slog.Warn("refresh pool capacity: upsert", "pool", p.Name, "error", err)
		}
	}

	// Refresh the gRPC server's in-memory pool map from config + the
	// storage_pools table so pools created at runtime via `lv pool create`
	// (table-only, never in config.yaml) become resolvable by move/replicate
	// and compose volume lookups. Previously the map was loaded once at
	// startup from config alone, so runtime pools were invisible to those
	// paths even though `lv pool ls`/the UI showed them active.
	if d.svc != nil {
		refs := d.storagePoolRefs() // config pools first — they carry driver Options
		for _, p := range pools {
			if _, ok := refs[p.Name]; ok {
				continue // config definition wins
			}
			refs[p.Name] = grpcapi.StoragePoolRef{
				Driver:  p.Driver,
				Source:  p.Source,
				Target:  p.Target,
				Options: p.Options,
			}
		}
		d.svc.SetStoragePoolsByName(refs)
	}
}

// pressureSink is where startPressure wires the sampler: the gRPC server,
// whose Ready reports it.
type pressureSink interface {
	SetPressureSource(grpcapi.PressureSource)
}

// startPressure starts this host's resource-pressure sampler and wires it
// into sink, with newObserver's observer (metrics) seeing every sample. With
// pressure.enabled false it does nothing: peers then read this host's
// pressure as unknown.
func (d *Daemon) startPressure(ctx context.Context, sink pressureSink, newObserver func() func(pressure.Report)) {
	if !d.cfg.Pressure.Enabled {
		return
	}
	ps := pressure.NewSampler(d.cfg.Pressure, d.cfg.DataDir, pressure.Options{Pools: d.pressurePools()})
	ps.SetObserver(newObserver())
	sink.SetPressureSource(ps)
	d.pressure = ps
	ps.Start(ctx)
}

// closeDatabase closes the database once the workers that read it outside
// the replicator are stopped and joined: the pressure sampler, whose pool
// read uses d.db. Their contexts are not enough: on re-exec and uninstall the
// daemon's own context is still live here.
func (d *Daemon) closeDatabase() {
	if d.pressure != nil {
		d.pressure.Stop()
	}
	d.db.Close()
}

// pressurePoolsRefresh is how often the pressure sampler re-reads which pools
// this host has; between reads it grades the last list.
const pressurePoolsRefresh = time.Minute

// pressurePools lists this host's file-based pools for the pressure sampler:
// the config pools and this host's rows in storage_pools, as
// sumPoolDiskTotalGiB walks them. The replicated read is cached for
// pressurePoolsRefresh, and a failed read keeps the last list. Its context does
// not bound it (Query takes the client lock first), so the sampler runs it off
// its sampling path and abandons a read that does not return
// (Sampler.currentPools); one at a time, so this closure's state is not shared.
// A stopped sampler waits for the read (Sampler.Stop), and a read whose context
// has ended does not touch the database.
func (d *Daemon) pressurePools() func(context.Context) []pressure.Pool {
	var (
		last []pressure.Pool
		read time.Time
	)
	return func(ctx context.Context) []pressure.Pool {
		if !read.IsZero() && time.Since(read) < pressurePoolsRefresh {
			return last
		}
		seen := map[string]bool{}
		var out []pressure.Pool
		add := func(name, target string) {
			if name == "" || target == "" || seen[name] {
				return
			}
			seen[name] = true
			out = append(out, pressure.Pool{Name: name, Path: target})
		}
		for _, p := range d.cfg.StoragePools {
			if fileBasedPoolDriver(p.Driver) {
				add(p.Name, p.Target)
			}
		}
		if ctx.Err() != nil {
			// The sampler is stopping and the database may be closing.
			return last
		}
		if d.db != nil {
			list := d.listHostPools
			if list == nil {
				list = corrosion.ListStoragePoolsForHost
			}
			rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			rows, err := list(rctx, d.db, d.cfg.HostName)
			cancel()
			if err != nil {
				slog.Warn("resource pressure: list storage pools; grading the last list", "error", err)
				if last != nil {
					return last
				}
			}
			for _, p := range rows {
				if fileBasedPoolDriver(p.Driver) {
					add(p.Name, p.Target)
				}
			}
		}
		last, read = out, time.Now()
		return out
	}
}

// fileBasedPoolDriver reports whether a driver's Target is a local filesystem
// path that syscall.Statfs can measure.
func fileBasedPoolDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "", "local", "dir", "nfs", "btrfs":
		return true
	}
	return false
}

// hostAddress is the address this daemon registers itself at — the address peers
// will dial. The configured advertise address wins when set: it is the SAME
// value handed to gossip, and the two must agree or peers dial an address the
// host certificate does not cover. Falling back to getOutboundIP only reports
// the source IP toward the default route, which is the wrong answer on a
// multi-homed host whose cluster network is not the default one.
//
// It is also this host's VXLAN tunnel endpoint (newServer): one rule,
// netutil.HostAddress, for all three.
func (d *Daemon) hostAddress() string {
	return netutil.HostAddress(d.cfg.AdvertiseAddress)
}

func getOutboundIP() string {
	return netutil.HostAddress("")
}

// newServer builds the gRPC server with what its first network pass needs
// already wired. The daemon runs that pass (ReconcileNetworksOnce) a few steps
// later, at startup, and a vxlan network provisioned there takes its tunnel
// endpoint from both: this host's address, and the release gate, whose latch
// decides whether that address is in use yet (network.ResolveVTEP). Wired any
// later, the pass would find neither, and the server refuses a vxlan network
// with no address rather than guess one.
func (d *Daemon) newServer() *grpcapi.Server {
	var svc *grpcapi.Server
	if d.buildServer != nil {
		svc = d.buildServer()
	} else {
		svc = grpcapi.NewServer(d.cfg.HostName, d.cfg.DataDir, d.cfg.PKIDir, d.db, d.virt, d.images)
	}
	d.wireServer(svc)
	return svc
}

// wireServer is newServer's wiring, on a server already built.
func (d *Daemon) wireServer(svc *grpcapi.Server) {
	svc.SetHostAddress(d.hostAddress())
	svc.SetNetworkDeviceStatePath(grpcapi.DefaultNetworkDeviceStatePath)
	// Release features (capabilities.Feature) open through the checker's
	// WithFeature: the release token's latch plus the replicated used bit.
	svc.SetReleaseFeatureGate(d.checker)
}

// runPCIScan performs the initial PCI device scan and stores results in the DB.
func (d *Daemon) runPCIScan(ctx context.Context) {
	scan := pci.Scan
	if d.pciScanOverride != nil {
		scan = d.pciScanOverride
	}
	devices, err := scan()
	if err != nil {
		slog.Warn("PCI scan failed", "error", err)
		return
	}

	interesting := pci.FilterInteresting(devices)
	for _, dev := range interesting {
		if err := corrosion.ObservePCIDevice(ctx, d.db, corrosion.PCIDeviceRecord{
			HostName:      d.cfg.HostName,
			Address:       dev.Address,
			VendorID:      dev.VendorID,
			DeviceID:      dev.DeviceID,
			VendorName:    dev.VendorName,
			DeviceName:    dev.DeviceName,
			Type:          dev.Type,
			IOMMUGroup:    dev.IOMMUGroup,
			SRIOVCapable:  dev.SRIOVCapable,
			SRIOVVFsTotal: dev.SRIOVVFsTotal,
			SRIOVVFsFree:  dev.SRIOVVFsFree,
			Driver:        dev.Driver,
			NUMANode:      dev.NUMANode,
			PCIeRootPort:  dev.PCIeRootPort,
			PCIeBridge:    dev.PCIeBridge,
			LinkClique:    dev.LinkClique,
			LinkPeers:     strings.Join(dev.LinkPeers, ","),
		}); err != nil {
			slog.Warn("failed to store PCI device", "address", dev.Address, "error", err)
		}
	}
	slog.Info("PCI startup scan complete", "interesting_devices", len(interesting), "total_scanned", len(devices))

	// The observe loop above revives a tombstoned row with its vm_name intact
	// (deliberately: a transient scan drop must not free in-use hardware), so
	// after a reboot a device whose VM was deleted meanwhile comes back still
	// assigned to it. Reclaim those here, as RescanHost does, rather than
	// leaving them stranded until an operator runs `lv host rescan` (#218).
	if freed, err := corrosion.SweepStrandedPCIOwnership(ctx, d.db, d.cfg.HostName,
		corrosion.DefaultPCIOwnershipSweepAge); err != nil {
		slog.Warn("PCI scan: stranded-ownership sweep failed", "error", err)
	} else if len(freed) > 0 {
		slog.Info("PCI scan: reclaimed devices whose owning VM no longer exists", "addresses", freed)
	}

	// NVMe namespace discovery (informational log for now).
	namespaces, err := pci.ScanNVMeNamespaces()
	if err != nil {
		slog.Warn("NVMe namespace scan failed", "error", err)
	} else if len(namespaces) > 0 {
		slog.Info("NVMe namespaces discovered", "count", len(namespaces))
	}
}

// parsePCIRescanInterval parses the pci.rescan_interval config value.
// Returns 0 if disabled (empty or "0").
func (d *Daemon) parsePCIRescanInterval() time.Duration {
	s := d.cfg.PCI.RescanInterval
	if s == "" || s == "0" {
		return 0
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		slog.Warn("invalid pci.rescan_interval", "value", s, "error", err)
		return 0
	}
	return dur
}

// parseSMARTInterval parses smart.interval: empty = 1h default, "0"/"off" = disabled,
// an unparseable value falls back to the default with a warning.
func parseSMARTInterval(s string) time.Duration {
	switch s {
	case "":
		return time.Hour
	case "0", "off":
		return 0
	}
	dur, err := time.ParseDuration(s)
	if err != nil || dur < 0 {
		slog.Warn("invalid smart.interval; using 1h", "value", s, "error", err)
		return time.Hour
	}
	if dur == 0 {
		return 0
	}
	if dur < minSMARTInterval {
		slog.Warn("smart.interval below the floor; clamped", "value", s, "floor", minSMARTInterval)
		return minSMARTInterval
	}
	return dur
}

// minSMARTInterval is the shortest smart.interval: smartctl forks per disk per
// pass and a sub-minute interval would run it continuously.
const minSMARTInterval = 10 * time.Minute

// parseDurationOr parses a Go duration string, returning fallback when empty
// or unparseable (logging a warning in the latter case).
func parseDurationOr(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		slog.Warn("invalid session-timeout duration in config; using default", "value", s, "error", err)
		return fallback
	}
	return d
}

const adminPasswordFile = "/etc/litevirt/admin-password"

// genesisMarkerName is the founder marker in data_dir. `lv host init` writes it,
// and only while the data dir holds no state.db; every other provisioning path
// removes it. seedAdminUser mints the cluster's first admin credential only
// while it exists, and deletes it once that credential is written.
const genesisMarkerName = "genesis-pending"

// firewallInitialModeName is the founder's genesis decision of the cluster's
// per-NIC firewall mode, in data_dir, consumed once recorded
// (grpcapi.SeedFirewallEnforcementLoop).
const firewallInitialModeName = "firewall-initial-mode"

// firewallSynfloodDecisionName is the founder's genesis decision to protect
// guest NICs from SYN floods, in data_dir, consumed once recorded
// (grpcapi.SeedFirewallSynfloodLoop).
const firewallSynfloodDecisionName = "firewall-synflood-decision"

// wireActivationMarker points the health checker at this node's durable
// capability latches (health.ActivationMarkerBase), loading any already there.
// They are written only after a daemon has run as a member and survive a
// state.db loss, so seedAdminUser treats any of them as proof this node is not
// founding a cluster. The setup script's genesisMarkerScript matches the same
// name.
func (d *Daemon) wireActivationMarker() {
	d.checker.SetActivationMarker(health.ActivationMarkerBase(d.cfg.DataDir))
}

// seedAdminUser creates a default admin user with a random password if this node
// is founding a cluster and no users exist. The password is written to
// adminPasswordPath (adminPasswordFile by default) with mode 0600.
//
// A node JOINING a cluster mints nothing and writes no password file — its admin
// credential replicates in. See the join_peers guard below for why an empty
// `users` table is not proof that the cluster has no admin.
func (d *Daemon) seedAdminUser(ctx context.Context) error {
	// Tombstones count. ListUsers filters `deleted_at IS NULL`, so a deliberately
	// deleted admin would read as an empty cluster — and InsertUser reactivates a
	// soft-deleted row rather than inserting, so seeding here would un-delete a
	// revoked account, give it a fresh password, and replicate that cluster-wide.
	everExisted, err := corrosion.UsersEverExisted(ctx, d.db)
	if err != nil {
		return fmt.Errorf("check whether any user row exists: %w", err)
	}
	if everExisted {
		return nil
	}

	// An empty `users` table is not proof that the cluster has no admin. On a
	// joining node it only means replication has not started yet: this runs 163
	// lines before repl.Start, so a joiner reads nothing, mints an `admin` row
	// with a current updated_at, and publishes it the moment replication comes up.
	//
	// Nothing in the replication layer will stop that row, on either lane.
	// `users` resolves under policyChain() — [ruleTombstone(),
	// ruleUnresolved(TieCategoryPolicy)] — which reads like a fail-to-human guard
	// and is not one here, because it is a TIE chain: lwwOrder settles every
	// non-tie conflict itself and only an exact-instant tie ever reaches
	// resolveTie (corrosion/sync.go, `lwwOrder` and mergeChunk). A freshly minted
	// row is strictly NEWER, so anti-entropy applies it on the `ord < 0`
	// fall-through without consulting the resolver at all, and the WAL lane
	// applies it through applyLWWGated. The cluster's credential is replaced
	// silently, on every node ever added — which is exactly why the mint must not
	// happen here.
	//
	// join_peers is the one thing on disk that tells a joiner from a founder
	// before replication can answer. `lv host add` writes the cluster's gossip
	// peers into the new node's config.yaml and refuses outright to provision with
	// an empty list; `lv host init` leaves it empty. It is populated on founder
	// nodes too, but only once something was added TO them — long after their own
	// first start, and a founder that already seeded returned above.
	if len(d.cfg.JoinPeers) > 0 {
		// Says what did NOT happen and where the credential is instead. Naming a
		// password file here would send the operator looking for one this branch
		// never writes, and from there to `lv user reset-admin` — which only resets
		// a live admin, so on a node that has not converged yet it refuses with "no
		// live admin account" and reads as a second failure.
		slog.Info("this node is joining an existing cluster (join peers are configured and "+
			"no admin user has replicated in yet), so no admin account is created and no "+
			"password file is written here; the credential replicates in from the cluster. "+
			"`lv user reset-admin` resets an existing account and creates none, so it "+
			"refuses on this node until the credential has replicated in",
			"join_peers", len(d.cfg.JoinPeers))
		return nil
	}

	// An empty join_peers is an absence, and absences are not proof of founding.
	// A founder driven from a workstation keeps join_peers [] for life, so losing
	// its state.db put it straight back on the mint path; so did re-running
	// `lv host init` against a member, or restoring a config from a template.
	// Founding is a positive fact instead: `lv host init` writes the marker, and
	// only while the data dir holds no state.db.
	marker := filepath.Join(d.cfg.DataDir, genesisMarkerName)
	if _, err := os.Stat(marker); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("check founder marker %s: %w", marker, err)
		}
		slog.Warn("no admin account exists and this node was not founded by `lv host init` "+
			"(no founder marker in data_dir), so no admin account is created and no password "+
			"file is written here. If this node belongs to a cluster, the credential "+
			"replicates in once it converges; do not run `lv user reset-admin` here, it "+
			"resets an existing account and creates none. Only if this node is founding a "+
			"NEW cluster that was set up without `lv host init`: create the marker by hand "+
			"and restart the daemon",
			"marker", marker)
		return nil
	}

	// A marker does not outrank evidence of earlier membership. Capability
	// latches exist only once a daemon has run as a member, and survive a
	// state.db loss; a marker beside one was written by hand or by a setup that
	// could not see the latch, and minting here replaces the cluster's admin.
	latches, err := health.ActivationMarkersOnDisk(d.cfg.DataDir)
	if err != nil {
		return fmt.Errorf("check for capability latches: %w", err)
	}
	if len(latches) > 0 {
		slog.Warn("a founder marker is present but this node holds capability latches, so it "+
			"has run as a cluster member before; no admin account is created. Its credential "+
			"replicates in from the cluster. A brand-new cluster has to start from an empty "+
			"data_dir",
			"marker", marker, "latches", len(latches))
		return nil
	}

	password, err := generatePassword()
	if err != nil {
		return fmt.Errorf("generate password: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := corrosion.InsertUser(ctx, d.db, "admin", "admin", string(hash)); err != nil {
		return fmt.Errorf("insert admin: %w", err)
	}
	// Genesis: this replica founded the cluster, so there is no earlier history
	// it could lack (corrosion/audit_seeded.go).
	if err := d.db.MarkAuditSeeded(ctx, "founded the cluster (genesis)"); err != nil {
		slog.Warn("could not record the founder's replica as seeded; `lv host add` through this node "+
			"is refused until it is", "error", err)
	}

	// Genesis is also the one moment the cluster is known to be new, so it is
	// where "a fresh cluster enforces its per-NIC firewall rules" is decided
	// (re-review I-3, m-j): the seed loop records this once the
	// cluster_policies gate opens. No other host ever decides; with nothing
	// recorded a cluster observes.
	if err := os.WriteFile(filepath.Join(d.cfg.DataDir, firewallInitialModeName),
		[]byte(corrosion.FirewallEnforce+"\n"), 0o600); err != nil {
		slog.Warn("could not record the new cluster's initial firewall mode; it observes until `lv firewall enforce on`",
			"error", err)
	}
	// And that it protects guest NICs from SYN floods (spec §1.4): its own
	// decision, recorded by its own loop once the release latch forms.
	if err := os.WriteFile(filepath.Join(d.cfg.DataDir, firewallSynfloodDecisionName),
		[]byte(corrosion.SynfloodOn+"\n"), 0o600); err != nil {
		slog.Warn("could not record the new cluster's SYN-flood protection; it stays off until `lv firewall synflood on`",
			"error", err)
	}

	// The marker licenses exactly one mint, and that mint has now happened: the
	// row exists, so a restart returns at the ever-existed check. Consume it
	// before the password file, so a failed file write cannot leave the licence
	// behind for the day this state.db is lost.
	if err := os.Remove(marker); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("could not remove the founder marker after seeding the admin account; "+
			"delete it by hand, or a later state.db rebuild on this node mints a new "+
			"credential over the cluster's", "marker", marker, "error", err)
	}

	pwFile := d.adminPasswordPath
	if pwFile == "" {
		pwFile = adminPasswordFile
	}
	// secretfile, not os.WriteFile: this is the cluster admin's plaintext
	// password, and a WriteFile over a file left loose by a restore would keep the
	// loose mode — while a Chmod afterwards is too late, the secret is already in
	// the readable inode.
	if err := secretfile.Write(pwFile, []byte(password+"\n"), 0600); err != nil {
		return fmt.Errorf("write password file: %w", err)
	}

	slog.Info("seeded admin user", "password_file", pwFile)
	return nil
}

// generatePassword returns a random 32-character hex string.
func generatePassword() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// storagePoolRefs converts config pools into grpcapi-friendly references keyed by name.
func (d *Daemon) storagePoolRefs() map[string]grpcapi.StoragePoolRef {
	pools := d.cfg.StoragePools
	if len(pools) == 0 {
		pools = []StoragePoolConfig{{
			Name:   "litevirt",
			Driver: "local",
			Target: filepath.Join(d.cfg.DataDir, "disks"),
		}}
	}
	refs := make(map[string]grpcapi.StoragePoolRef, len(pools))
	for _, p := range pools {
		refs[p.Name] = grpcapi.StoragePoolRef{
			Driver:  p.Driver,
			Source:  p.Source,
			Target:  p.Target,
			Options: p.Options,
		}
	}
	return refs
}

// ensureStoragePools creates libvirt storage pools from config, or a default
// local pool if none are configured.
func (d *Daemon) ensureStoragePools() {
	pools := d.cfg.StoragePools
	if len(pools) == 0 {
		pools = []StoragePoolConfig{{
			Name:   "litevirt",
			Driver: "local",
			Target: filepath.Join(d.cfg.DataDir, "disks"),
		}}
	}
	for _, p := range pools {
		if err := d.virt.EnsureStoragePool(p.Name, p.Driver, p.Source, p.Target, p.Options); err != nil {
			slog.Warn("failed to ensure storage pool", "pool", p.Name, "error", err)
		} else {
			slog.Info("storage pool ready", "pool", p.Name, "driver", p.Driver)
		}
	}
}

// runPeriodicPCIScan runs the PCI scan on a recurring timer until ctx is cancelled.
func (d *Daemon) runPeriodicPCIScan(ctx context.Context, interval time.Duration) {
	slog.Info("PCI periodic rescan enabled", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Debug("running periodic PCI rescan")
			d.runPCIScan(ctx)
		}
	}
}

// runVMEventPrune periodically trims this host's vm_events rows to the
// configured retention. Each host prunes only its own rows (host_name = self),
// so it's idempotent and needs no cluster lease; the DELETEs replicate. An
// initial run shortly after startup clears anything stale from a prior crash.
func (d *Daemon) runVMEventPrune(ctx context.Context) {
	interval := time.Duration(d.cfg.VMEventPruneHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	prune := func() {
		if err := corrosion.PruneVMEvents(ctx, d.db, d.cfg.HostName,
			d.cfg.VMEventRetentionDays, d.cfg.VMEventErrorRetentionDays, d.cfg.VMEventMaxPerVM); err != nil {
			slog.Warn("vm_events prune", "error", err)
		} else {
			slog.Debug("vm_events prune complete")
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
		prune()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}

// runOperationRecovery is the F1 startup recovery barrier: it reduces the
// host-local operation journal against replicated state before runtime loops and
// API serving begin. Cleanup/supersede entries are removed; a resume entry is
// logged for the resource coordinator; a corrupt journal is logged loudly (the
// host is degraded for the affected mutations). Best-effort and defensive — it
// never blocks startup on a transient error.
func (d *Daemon) runOperationRecovery(ctx context.Context) {
	if d.opJournal == nil {
		return
	}
	lookup := func(opID string) (bool, int64, bool, error) {
		op, err := corrosion.GetOperation(ctx, d.db, opID)
		if err != nil {
			return false, 0, false, err
		}
		if op == nil {
			return false, 0, false, nil // GC'd → supersede
		}
		epoch, ok, err := corrosion.GetVMOwnerEpoch(ctx, d.db, op.ResourceID)
		if err != nil {
			return false, 0, false, err
		}
		if !ok {
			return false, 0, false, nil // VM gone → not owned → supersede
		}
		state, _, err := corrosion.OperationCurrentState(ctx, d.db, opID, op.VMOwnerEpoch, corrosion.OperationKind(op.OperationKind))
		if err != nil {
			return false, 0, false, err
		}
		return true, epoch, corrosion.IsOperationTerminal(state), nil
	}
	plan, corrupt, err := d.opJournal.PlanRecovery(lookup)
	if err != nil {
		slog.Error("operation recovery: plan failed", "error", err)
		return
	}
	if len(corrupt) > 0 {
		slog.Error("operation recovery: CORRUPT journal entries — host degraded for affected mutations", "files", corrupt)
	}
	for _, p := range plan {
		// device_lease entries are not operation-table ops; they're recovered
		// (with device rollback) by grpcapi.RecoverDeviceLeases, not here.
		if p.Entry.Kind == "device_lease" {
			continue
		}
		switch p.Action {
		case opjournal.RecoveryCleanup, opjournal.RecoverySupersede:
			if err := d.opJournal.Remove(p.Entry.OperationID); err != nil {
				slog.Warn("operation recovery: remove entry", "op", p.Entry.OperationID, "action", p.Action.String(), "error", err)
			} else {
				slog.Info("operation recovery", "op", p.Entry.OperationID, "action", p.Action.String())
			}
		case opjournal.RecoveryResume:
			slog.Warn("operation recovery: needs resume (deferred to resource coordinator)",
				"op", p.Entry.OperationID, "vm", p.Entry.ResourceID, "stage", p.Entry.Stage)
		}
	}
}

// authEngineReloadInterval is the backstop cadence for refreshing the RBAC
// engine from replicated state. Local grants reload synchronously and local
// revokes apply as in-memory deltas, so this backstop exists to pick up
// peer-originated mutations (which arrive via WAL/AE) and to recover from any
// missed local reload. The effective bound on a peer mutation taking effect is
// one successful interval AFTER it becomes locally visible — not 30s from the
// original mutation (replication lag and a failed-reload gap both add latency).
const authEngineReloadInterval = 30 * time.Second

// runAuthEngineReload periodically reloads the RBAC engine so peer-replicated
// role/binding mutations take effect without a restart. On failure it logs and
// retains the prior snapshot (Reload only swaps on success); the next tick
// retries. A stalled reload service is observable via the engine's
// last-successful-reload timestamp.
func (d *Daemon) runAuthEngineReload(ctx context.Context) {
	if d.authEngine == nil {
		return
	}
	ticker := time.NewTicker(authEngineReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.authEngine.Reload(ctx); err != nil {
				slog.Warn("auth engine periodic reload failed; retaining prior snapshot", "error", err)
			}
		}
	}
}

// runSupersededDiskSweep removes, hourly, the disk copies a failover set
// aside on this host (<path>.superseded-<time>) once they are older than
// superseded_disk_retention_days and the VM they came from no longer exists
// (health.PurgeSupersededDisks): while it exists, only an operator removes
// them. 0 keeps every copy. The reconciler's firmware quarantines
// (<data_dir>/fwmig-quarantine/<vm>-reconciled-<unix>/) follow the same rule
// (health.SweepSetAside).
func (d *Daemon) runSupersededDiskSweep(ctx context.Context) {
	days := d.cfg.SupersededDiskRetentionDays
	if days <= 0 {
		slog.Info("superseded disk copies and reconciled firmware quarantines are kept until removed by hand (superseded_disk_retention_days: 0)")
		return
	}
	retention := time.Duration(days) * 24 * time.Hour
	sweep := func() {
		health.SweepSetAside(ctx, d.db, d.cfg.DataDir, retention, time.Now())
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
		sweep()
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// runSupersededGC periodically hard-deletes provably-inert superseded/orphaned
// auth + LB rows (local-only, deterministic per node — see
// corrosion.GCSupersededRows). Hourly, with an initial delay after startup.
func (d *Daemon) runSupersededGC(ctx context.Context, m *metrics.GCMetrics) {
	core := time.Duration(d.cfg.TombstoneGCRetentionHours) * time.Hour
	if core <= 0 {
		core = 24 * time.Hour
	}
	orphan := time.Duration(d.cfg.TombstoneGCOrphanRetentionHours) * time.Hour
	if orphan <= 0 {
		orphan = 7 * 24 * time.Hour
	}
	gc := func() {
		counts, err := corrosion.GCSupersededRows(ctx, d.db, core, orphan)
		if err != nil {
			slog.Warn("superseded-row GC", "error", err)
		} else {
			for tbl, n := range counts {
				m.RowsDeleted(tbl, n)
				if n > 0 {
					slog.Info("GC reclaimed superseded rows", "table", tbl, "count", n)
				}
			}
		}
		// Split-brain runtime_action_proofs: a REPLICATED monotone tombstone of spent
		// (terminal) proofs past the core retention. This bounds the consumable set; row
		// reclamation is intentionally deferred (needs real convergence evidence, not
		// replicated hosts.state — see ReapSpentProofs). No-op until the gate is flipped.
		if tombstoned, perr := corrosion.ReapSpentProofs(ctx, d.db, core); perr != nil {
			slog.Warn("proof reaper", "error", perr)
		} else if tombstoned > 0 {
			slog.Info("proof reaper", "tombstoned", tombstoned)
		}
		// F1 operation journal (v41): tombstone terminal operations + their steps
		// once past the core retention (which exceeds the WAL/AE repair horizon) and
		// no VM barrier still references them. Replicated monotone tombstone —
		// tombstone-dominance in the immutable merge keeps a delayed copy from
		// resurrecting a reaped operation.
		d.reapTerminalOperations(ctx, core)
		// Authority still held by projects that no longer exist. Retiring on delete
		// is forward-only, so anything deleted before that landed keeps live
		// authority forever — nothing else collects it, because an authority row
		// never becomes terminal on its own. A recreated name would inherit it.
		if retired, perr := corrosion.ReconcileOrphanedProjectAuthority(ctx, d.db); perr != nil {
			slog.Warn("orphaned project-authority reconcile", "error", perr)
		} else if retired > 0 {
			slog.Info("retired authority held by deleted projects", "count", retired)
		}
		// Resolved health conditions past their 30-day retention. Tombstoned, not
		// hard-deleted, so replicas that have not yet seen the resolution converge
		// to the tombstone instead of resurrecting the row.
		if removed, perr := corrosion.TombstoneResolvedHealthConditions(ctx, d.db, time.Now()); perr != nil {
			slog.Warn("resolved health-condition retention", "error", perr)
		} else if removed > 0 {
			slog.Info("tombstoned resolved health conditions past retention", "count", removed)
		}
		// Orphaned admission leases (F2). A reserve-then-verify lease lives for one
		// RPC, so anything this old is a crash between reserve and release — which
		// the terminal reaper above can never collect, because an abandoned lease
		// never becomes terminal and would consume headroom forever. Scoped to
		// capacity leases so it can never expire a long resize/migration whose
		// reservation IS backed by a committed spec.
		if expired, perr := corrosion.ExpireStaleCapacityReservations(ctx, d.db, capacityLeaseMaxAge); perr != nil {
			slog.Warn("capacity lease expiry", "error", perr)
		} else if expired > 0 {
			slog.Warn("capacity lease expiry: released orphaned admission leases", "count", expired)
		}
		// Idempotency keys: hard-delete records past their TTL (v39). Ephemeral +
		// bounded by expires_at; a resurrected expired copy never matches, so a
		// plain local delete is safe.
		if reaped, perr := corrosion.ReapExpiredIdempotencyKeys(ctx, d.db); perr != nil {
			slog.Warn("idempotency-key reaper", "error", perr)
		} else if reaped > 0 {
			slog.Info("idempotency-key reaper", "reaped", reaped)
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
		gc()
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gc()
		}
	}
}

// metricsAddrForBanner is what the startup banner prints for the metrics
// endpoint: the address the listener will actually bind, or "disabled".
//
// The banner used to hardcode 0.0.0.0, which contradicted both metrics_bind and
// the exposure warning the metrics server logs a few lines later.
func (d *Daemon) metricsAddrForBanner() string {
	if d.cfg.MetricsPort <= 0 {
		return "disabled"
	}
	if d.metrics == nil {
		return fmt.Sprintf("%s:%d", d.cfg.MetricsBind, d.cfg.MetricsPort)
	}
	return d.metrics.Addr()
}

// wireLeaseTermLedgerGate lets corrosion mint a leader-lease term only once
// lease_term_ledger_v1 is DURABLY latched.
//
// The mint is the first replicated statement shape leader_lease_terms ever had,
// and an unregistered shape back-pressures a previous-release peer's whole
// replication stream instead of degrading — so the write waits for a latch that
// cannot form while such a peer is still listening. No config flag (the token
// has no kill switch): terms begin on their own once the roll completes.
//
// Extracted from Run so a test can reach it. Its absence is SILENT: this is the
// one injected predicate on the corrosion client that fails CLOSED, so an
// unwired gate mints nothing forever and looks exactly like a legitimate
// mid-roll — the same signature as a starved latch. Deleting this call left the
// corrosion, grpcapi and daemon suites all green, because every test injects the
// gate directly and the test constructors hardcode it open.
// wireCredentialsSplitGate lets corrosion write the sensitive credential
// tables only once credentials_split_v1 is DURABLY latched.
//
// Their statement shapes are the first those tables ever had, so a write
// before the latch back-pressures a previous-release peer's replication
// stream. No config flag: the split begins on its own once the roll completes.
// Unwired, the gate fails closed and every secret stays in its old column,
// which is the previous release's behaviour.
func (d *Daemon) wireCredentialsSplitGate() {
	d.db.SetCredentialsSplitGate(func() bool {
		return d.checker.DurablyLatched(capabilities.CredentialsSplitV1)
	})
}

// CredentialsSplitLatchedOnDisk is the credentials_split_v1 gate for a process
// that is NOT the daemon — `lv user reset-admin` opens the local database
// directly and has no health checker to ask. It reads the same durable
// activation marker Checker.DurablyLatched is backed by, so the CLI writes the
// credential table exactly when the daemon on that node would.
func CredentialsSplitLatchedOnDisk(dataDir string) func() bool {
	path := health.ActivationMarkerPath(dataDir, capabilities.CredentialsSplitV1)
	return func() bool {
		_, err := os.Stat(path)
		return err == nil
	}
}

// wireCredentialsClearGate lets corrosion EMPTY the old secret columns once
// credentials_clear_v1 is DURABLY latched (corrosion.MayClearCredentialColumns
// also requires the split gate, so a node never empties its only copy).
//
// No config flag: the clear begins on its own once every replication
// recipient runs a build that never needs the old columns. Unwired, the gate
// fails closed and every old column keeps its secret, which is the dual-write
// build's behaviour.
func (d *Daemon) wireCredentialsClearGate() {
	d.db.SetCredentialsClearGate(func() bool {
		return d.checker.DurablyLatched(capabilities.CredentialsClearV1)
	})
}

// CredentialsClearLatchedOnDisk is the credentials_clear_v1 gate for a process
// that is NOT the daemon — `lv user reset-admin` opens the local database
// directly. It reads the same durable activation marker Checker.DurablyLatched
// is backed by, so the CLI empties the old column exactly when the daemon on
// that node would.
func CredentialsClearLatchedOnDisk(dataDir string) func() bool {
	path := health.ActivationMarkerPath(dataDir, capabilities.CredentialsClearV1)
	return func() bool {
		_, err := os.Stat(path)
		return err == nil
	}
}

// credentialsSplitInterval is how often the daemon re-runs the credentials
// split. Each pass is a few indexed reads when there is nothing to do.
const credentialsSplitInterval = time.Minute

// runCredentialsSplit runs corrosion.SplitCredentials at start and then every
// credentialsSplitInterval. Every pass is a no-op until the gate opens, and
// idempotent after.
func (d *Daemon) runCredentialsSplit(ctx context.Context) {
	t := time.NewTicker(credentialsSplitInterval)
	defer t.Stop()
	for {
		if rep, err := d.db.SplitCredentials(ctx); err != nil {
			slog.Warn("credentials split: pass failed", "error", err)
		} else if rep.Copied > 0 || rep.Cleared > 0 {
			slog.Info("credentials split: moved secrets onto the sensitive lane",
				"copied", rep.Copied, "cleared", rep.Cleared)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// wireHostMembershipGate lets corrosion write host_membership only once
// host_membership_split_v1 is DURABLY latched.
//
// It reads the durable activation marker on disk rather than asking the health
// checker, because it must be wired before the checker exists: the daemon
// writes this host's boot state first. The marker is exactly what
// Checker.DurablyLatched is backed by. No config flag: the split begins on its
// own once the roll completes. Unwired, the gate fails closed and every state
// change goes to hosts.state, the previous release's behaviour.
func (d *Daemon) wireHostMembershipGate() {
	d.db.SetHostMembershipGate(HostMembershipLatchedOnDisk(d.cfg.DataDir))
}

// wireHostMembershipRetireGate stops the state and isolation writers writing
// the hosts copy once host_membership_retire_v1 has durably latched. Read from
// the marker on disk, like wireHostMembershipGate, because the boot state is
// written before the checker exists. No config flag. Unwired, the gate fails
// closed and both homes keep being written, the dual-write build's behaviour.
func (d *Daemon) wireHostMembershipRetireGate() {
	d.db.SetHostMembershipRetireGate(HostMembershipRetireLatchedOnDisk(d.cfg.DataDir))
}

// HostMembershipRetireLatchedOnDisk reports whether host_membership_retire_v1
// has durably latched on the node whose data directory is dataDir.
func HostMembershipRetireLatchedOnDisk(dataDir string) func() bool {
	path := health.ActivationMarkerPath(dataDir, capabilities.HostMembershipRetireV1)
	return func() bool {
		_, err := os.Stat(path)
		return err == nil
	}
}

// HostMembershipLatchedOnDisk reports whether host_membership_split_v1 has
// durably latched on the node whose data directory is dataDir.
func HostMembershipLatchedOnDisk(dataDir string) func() bool {
	path := health.ActivationMarkerPath(dataDir, capabilities.HostMembershipSplitV1)
	return func() bool {
		_, err := os.Stat(path)
		return err == nil
	}
}

// hostMembershipSplitInterval is how often the daemon re-runs the membership
// split. Shorter than the credentials split's minute: until a node's first
// pass its readers read hosts, not host_membership. Each pass is one join over
// the hosts table when there is nothing to do.
const hostMembershipSplitInterval = 10 * time.Second

// runHostMembershipSplit runs corrosion.SplitHostMembership at start and then
// every hostMembershipSplitInterval. A no-op until the gate opens, idempotent
// after.
func (d *Daemon) runHostMembershipSplit(ctx context.Context) {
	t := time.NewTicker(hostMembershipSplitInterval)
	defer t.Stop()
	for {
		if rep, err := d.db.SplitHostMembership(ctx); err != nil {
			slog.Warn("host membership split: pass failed", "error", err)
		} else if rep.Copied > 0 {
			slog.Info("host membership split: moved host state onto its own row",
				"copied", rep.Copied)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// wireHostRuntimeGate lets corrosion write host_runtime only once
// host_runtime_split_v1 is DURABLY latched. Read from the marker on disk, like
// wireHostMembershipGate, because the boot report is written before the
// checker exists. No config flag. Unwired, the gate fails closed and every
// runtime report goes to the hosts columns alone, the previous release's
// behaviour.
func (d *Daemon) wireHostRuntimeGate() {
	d.db.SetHostRuntimeGate(HostRuntimeLatchedOnDisk(d.cfg.DataDir))
}

// wireHostRuntimeRetireGate stops the pure runtime writers writing the hosts
// copy once host_runtime_retire_v1 has durably latched. Read from the marker
// on disk, like wireHostRuntimeGate, because the boot report is written before
// the checker exists. No config flag. Unwired, the gate fails closed and both
// homes keep being written, the dual-write build's behaviour.
func (d *Daemon) wireHostRuntimeRetireGate() {
	path := health.ActivationMarkerPath(d.cfg.DataDir, capabilities.HostRuntimeRetireV1)
	d.db.SetHostRuntimeRetireGate(func() bool {
		_, err := os.Stat(path)
		return err == nil
	})
}

// HostRuntimeLatchedOnDisk reports whether host_runtime_split_v1 has durably
// latched on the node whose data directory is dataDir.
func HostRuntimeLatchedOnDisk(dataDir string) func() bool {
	path := health.ActivationMarkerPath(dataDir, capabilities.HostRuntimeSplitV1)
	return func() bool {
		_, err := os.Stat(path)
		return err == nil
	}
}

// runHostRuntimeSplit runs corrosion.SplitHostRuntime at start and then every
// hostMembershipSplitInterval. A no-op until the gate opens, idempotent after.
func (d *Daemon) runHostRuntimeSplit(ctx context.Context) {
	t := time.NewTicker(hostMembershipSplitInterval)
	defer t.Stop()
	for {
		if rep, err := d.db.SplitHostRuntime(ctx); err != nil {
			slog.Warn("host runtime split: pass failed", "error", err)
		} else if rep.Copied > 0 {
			slog.Info("host runtime split: moved host runtime reports onto their own row",
				"copied", rep.Copied)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// wireClusterPolicyGate lets corrosion write cluster_policies (the
// failover_scope policy) only once failover_scope_v1 is DURABLY latched: the
// table's statements stall a previous-release peer's stream, and the policy
// means nothing to a coordinator that does not honour it. Unwired, the gate
// fails closed and `lv cluster failover-scope` refuses to change anything.
func (d *Daemon) wireClusterPolicyGate() {
	d.db.SetClusterPolicyGate(func() bool {
		return d.checker.DurablyLatched(capabilities.FailoverScopeV1)
	})
	// The relay demotion rows ride in cluster_policies, and are also unread by
	// a previous-release peer, which would elect a different relay set: they
	// wait for relay_health_v1 as well (corrosion/relay_health.go).
	d.db.SetRelayHealthGate(func() bool {
		return d.checker.DurablyLatched(capabilities.RelayHealthV1)
	})
}

// wireCorrosionGates wires every gate corrosion consults before emitting a
// statement shape or a row a peer relies on. One function, so the daemon and
// its test wire the same set: a gate left unwired fails closed and looks
// exactly like a cluster mid-roll, so nothing else would notice it missing.
func (d *Daemon) wireCorrosionGates() {
	d.wireLeaseTermLedgerGate()
	d.wireLeaseMintClearance()
	d.wireCredentialsSplitGate()
	d.wireCredentialsClearGate()
	d.wireClusterPolicyGate()
	d.wireVoterConfigGate()
	d.wireRecoveryClaimGate()
	d.wireSpecConflictGate()
	d.wireNetBoxRepointGate()
	d.wireUserIncarnationGate()
	d.wireProjectIncarnationGate()
}

// wireProjectIncarnationGate tells corrosion when project_incarnation_v1 has
// DURABLY latched: a project birth then writes a fresh incarnation, in two
// statements a previous-release peer has no ledger entry for, and grants and
// quotas under a project are bound to it. Mandatory, no config flag; unwired,
// the gate reads false and the node writes as the previous release.
func (d *Daemon) wireProjectIncarnationGate() {
	d.db.SetProjectIncarnationGate(func() bool {
		return d.checker.DurablyLatched(capabilities.ProjectIncarnationV1)
	})
}

// wireUserIncarnationGate tells corrosion when user_incarnation_v1 has
// DURABLY latched: users rows are then deleted and re-created by incarnation,
// in two statements a previous-release peer has no ledger entry for, and
// anti-entropy keeps a tombstone over its own incarnation. Durable, so a
// restart does not return a node to the previous release's merge while its
// peers keep the new one. Mandatory, no config flag; unwired, the gate reads
// false and the node behaves as the previous release.
func (d *Daemon) wireUserIncarnationGate() {
	d.db.SetUserIncarnationGate(func() bool {
		return d.checker.DurablyLatched(capabilities.UserIncarnationV1)
	})
}

// wireNetBoxRepointGate lets corrosion re-point a lease at a re-created NetBox
// address only once netbox_ip_repoint_v1 has DURABLY latched: the re-point is a
// shape a previous-release peer has no ledger entry for. Mandatory, no config
// flag; unwired, the gate fails closed and the mirror skips a dead address and
// reports the pass unconverged, as the previous release did.
func (d *Daemon) wireNetBoxRepointGate() {
	d.db.SetNetBoxRepointGate(func() bool {
		return d.checker.DurablyLatched(capabilities.NetBoxIPRepointV1)
	})
}

// wireSpecConflictGate tells corrosion when spec_conflict_v1 has DURABLY
// latched: spec edits then carry their owner epoch, a shape a
// previous-release peer cannot decode, and a conflict at one generation is
// resolved alike on every replica (corrosion/spec_conflict.go). Durable, so
// a restart does not return a node to the previous release's resolution
// while its peers keep the new one. Mandatory, no config flag; unwired, the
// gate reads false and the node behaves as the previous release.
func (d *Daemon) wireSpecConflictGate() {
	d.db.SetSpecConflictGate(func() bool {
		return d.checker.DurablyLatched(capabilities.SpecConflictV1)
	})
}

// wireLeaseMintClearance makes every new lease term wait for the quorum
// high-water read (grpcapi.Server.LeaseMintClearance): a node must not mint
// term N+1 from its own replica while a peer already holds N+1, which is what a
// restarted or reconnected node's stale ledger otherwise does — nor take over a
// lease a peer still sees live, which is what a stale leader_election row
// otherwise does.
//
// Wired BEFORE any lease holder starts, and answering "not yet" until the gRPC
// server and its gate exist. The rebalancer starts ahead of the server, and a
// daemon's first seconds are exactly when its ledger is stalest, so an unwired
// window here would be the bug itself.
func (d *Daemon) wireLeaseMintClearance() {
	d.db.SetLeaseMintClearance(func(ctx context.Context, req corrosion.LeaseMintRequest) (bool, string) {
		svc := d.mintClearance.Load()
		if svc == nil {
			return false, "daemon starting: the lease-term quorum read is not wired yet"
		}
		return svc.LeaseMintClearance(ctx, req)
	})
	// A lease seen held — a renewal, a mint, a peer's live lease — resolves a
	// no-majority stall the server raised for it.
	d.db.SetLeaseLiveObserver(func(ctx context.Context, key string) {
		if svc := d.mintClearance.Load(); svc != nil {
			svc.NoteLeaseLive(ctx, key)
		}
	})
	// A lease poll that stood down for want of the voter majority, over a
	// lease with no live holder, is a stalled takeover like a claim with no
	// majority.
	d.db.SetLeaseNoMajorityObserver(func(ctx context.Context, ev corrosion.LeaseNoMajority) {
		if svc := d.mintClearance.Load(); svc != nil {
			svc.NoteLeaseNoMajority(ctx, ev)
		}
	})
}

// wireVoterConfigGate lets corrosion write voter_configs only once
// voter_config_v1 is DURABLY latched. Its statement shapes are the first that
// table ever had, so a write before the latch back-pressures a
// previous-release peer's replication stream. Mandatory, no config flag;
// unwired, the gate fails closed and no voter generation is ever written, which
// is the previous release's behaviour.
func (d *Daemon) wireVoterConfigGate() {
	d.db.SetVoterConfigGate(func() bool {
		return d.checker.DurablyLatched(capabilities.VoterConfigV1)
	})
}

// wireRecoveryClaimGate lets corrosion emit the claim_certificate column's
// statement shapes (schema v60) only once recovery_claim_v1 is DURABLY
// latched. The token is replication-gated, so the latch proves every host
// this one replicates to decodes them; unwired, the gate fails closed and a
// certified proof is refused as not yet emittable — which, under
// enforcement, refuses the recovery rather than shipping a shape a peer
// cannot resolve.
func (d *Daemon) wireRecoveryClaimGate() {
	d.db.SetRecoveryClaimGate(func() bool {
		return d.checker.DurablyLatched(capabilities.RecoveryClaimV1)
	})
	// claim_incarnation_v1 (docs/design/recovery-claims.md §10 item 37):
	// lets a pre-epoch container relocation take the guarded row shape, which
	// keeps the source's created_at over a stale tombstone on the target.
	d.db.SetClaimIncarnationGate(func() bool {
		return d.checker.DurablyLatched(capabilities.ClaimIncarnationV1)
	})
}

// voterAdoptionInterval is how often the daemon adopts newly replicated voter
// generations. A pass with nothing new is one indexed read.
const voterAdoptionInterval = 5 * time.Second

// runVoterAdoption adopts decided voter generations as they replicate in.
func (d *Daemon) runVoterAdoption(ctx context.Context, svc *grpcapi.Server) {
	t := time.NewTicker(voterAdoptionInterval)
	defer t.Stop()
	var lastErr string
	for {
		if _, err := svc.AdoptVoterConfigs(ctx); err != nil {
			if err.Error() != lastErr {
				slog.Warn("voter set: adoption pass did not complete", "error", err)
			}
			lastErr = err.Error()
		} else {
			lastErr = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (d *Daemon) wireLeaseTermLedgerGate() {
	d.db.SetLeaseTermLedgerGate(func() bool {
		return d.checker.DurablyLatched(capabilities.LeaseTermLedgerV1)
	})
}

// startWaitNeeded is the predicate RequireStartGuard waits on (re-review
// m3): a start waits for the start guard only when its VM has a NIC guard
// on, or whether it has one cannot be read. A VM with none starts as it did
// before guards. creating names the incarnation a create on this host is
// starting (grpcapi.Server.CreatingIncarnation): such a start waits only for
// that incarnation's guards.
func startWaitNeeded(db *corrosion.Client, creating func(name string) string) func(name string) bool {
	return func(name string) bool {
		gctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		macs, err := corrosion.GuardedMACsOfIncarnation(gctx, db, name, creating(name))
		return err != nil || len(macs) > 0
	}
}

// nicGuardLabelHook sets host's NIC-guard label after every firewall pass
// (firewall.Reconciler.SetPassHook): version while the pass put the per-NIC
// table in force, "" otherwise (re-review m5). The write has its own
// deadline, so a pass that ran out of time still clears the label.
func nicGuardLabelHook(db *corrosion.Client, host, version string) func(context.Context, bool) {
	return func(ctx context.Context, enforcing bool) {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := corrosion.SetHostLabel(lctx, db, host, corrosion.LabelNICGuards,
			grpcapi.NICGuardLabelValue(version, enforcing)); err != nil {
			slog.Warn("could not set the NIC-guard host label", "enforcing", enforcing, "error", err)
		}
	}
}

// bootFirewallPassBudget bounds the daemon's first firewall pass (re-review m3).
const bootFirewallPassBudget = 60 * time.Second

// bootFirewallPass runs the first firewall pass at boot under budget: it runs
// before every start source and before the gRPC server, so a pass that hangs
// (an nft that never returns) must not hold the daemon's start.
func bootFirewallPass(ctx context.Context, r interface{ Reconcile(context.Context) error }, budget time.Duration) error {
	bctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return r.Reconcile(bctx)
}

// checkMigrationNetwork refuses a migration.network that would send migration
// data out the uplink or the cluster interface (grpcapi.CheckMigrationNetwork):
// one outside the private ranges, or containing this host's cluster address or
// its default-route source address.
func (d *Daemon) checkMigrationNetwork() error {
	if d.cfg.Migration.Network == "" {
		return nil
	}
	n, err := grpcapi.ParseMigrationNetwork(d.cfg.Migration.Network)
	if err != nil {
		return err
	}
	if err := grpcapi.CheckMigrationNetwork(n, d.cfg.Migration.AllowAnyNetwork,
		net.ParseIP(netutil.OutboundIP()), net.ParseIP(d.cfg.AdvertiseAddress)); err != nil {
		return err
	}
	// migration.address must be this host's own: a down NIC would send the data
	// out by the default route, and an address copied from another host's config
	// would send every source to the wrong host.
	if a := net.ParseIP(d.cfg.Migration.Address); a != nil {
		addrs, _ := net.InterfaceAddrs()
		for _, x := range addrs {
			if ipn, ok := x.(*net.IPNet); ok && ipn.IP.Equal(a) {
				return nil
			}
		}
		return fmt.Errorf("migration.address %s is not an address of this host: check the interface is up, "+
			"and that the value was not copied from another host's config", a)
	}
	return nil
}

// fileRestoreCacheDir holds the restore VM's boot files: outside data_dir
// (whose contents production qemus may be granted), root-owned, 0750 to the
// restore user's group.
func fileRestoreCacheDir(dataDir string) string {
	if os.Geteuid() == 0 {
		return "/var/cache/litevirt-restore"
	}
	return filepath.Join(dataDir, "file-restore", "boot-cache")
}

// fileRestoreRunDir is where restore VM sessions keep their NBD socket and
// pidfile: under /run for a root daemon, outside data_dir, so a session never
// shares a filesystem with state.db.
func fileRestoreRunDir(dataDir string) string {
	if os.Geteuid() == 0 {
		return "/run/litevirt/file-restore"
	}
	return filepath.Join(dataDir, "file-restore", "run")
}
