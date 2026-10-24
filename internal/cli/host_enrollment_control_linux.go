package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/systemdunit"
)

type enrollmentUtilityExecution struct {
	directory   string
	environment []string
	resolve     func(string) (string, []string, error)
}

type enrollmentWorkerProfile struct {
	record                                                  func(enrollmentWorkerProof) error
	image, stage, unitPrefix, claimPath, markerPath, pkiDir string
	parentImage                                             string
	launcherArgs, workerArgs, environment                   []string
	utilities                                               enrollmentUtilityExecution
}

func defaultEnrollmentWorkerProfile(stage string) enrollmentWorkerProfile {
	image := systemdunit.EnrollmentControlImagePath
	return enrollmentWorkerProfile{image: image, stage: stage, parentImage: filepath.Join(stage, "litevirt"), unitPrefix: "litevirt-enrollment-", claimPath: addLock, markerPath: addInstalledMarker, pkiDir: "/etc/litevirt/pki", launcherArgs: []string{image, "host-enroll-control", "launcher"}, workerArgs: []string{image, "host-enroll-control", "worker"}, environment: os.Environ()}
}

func runEnrollmentWorkerUtilities(ctx context.Context, kind enrollmentWorkerKind, execution enrollmentUtilityExecution) error {
	if kind != "prepare" && kind != "apparmor" {
		return errors.New("unsupported fixed worker kind")
	}
	lookup := execution.resolve
	if lookup == nil {
		lookup = func(name string) (string, []string, error) { path, err := exec.LookPath(name); return path, nil, err }
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline, bounded := ctx.Deadline()
		if !bounded {
			return errors.New("fixed utilities require original absolute deadline")
		}
		if time.Until(deadline) <= 0 {
			return context.DeadlineExceeded
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	run := func(name string, args []string, ignore bool) error {
		if err := check(); err != nil {
			return err
		}
		path, prefix, err := lookup(name)
		// Lookup may perform filesystem work or return after parent retirement.
		// Its result never grants a fresh start budget.
		if canceled := check(); canceled != nil {
			return canceled
		}
		if err != nil {
			if ignore {
				return nil
			}
			return err
		}
		command := exec.Command(path, append(append([]string{}, prefix...), args...)...)
		command.Dir = execution.directory
		command.Env = enrollmentUtilityEnvironment(execution.environment, kind)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		// No CommandContext kill: a direct parent's death cannot prove capable
		// descendants gone. PID1's selected unit retains their actual custody.
		if err := check(); err != nil {
			return err
		}
		if err := command.Start(); err != nil {
			if ignore {
				return nil
			}
			return err
		}
		waited := make(chan error, 1)
		go func() { waited <- command.Wait() }()
		var waitErr error
		select {
		case waitErr = <-waited:
		case <-ctx.Done():
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case waitErr = <-waited:
			case <-timer.C:
				return fmt.Errorf("utility %s pid%d still belongs to known worker custody; result unknown: %w", name, command.Process.Pid, ctx.Err())
			}
		}
		fmt.Fprintf(os.Stderr, "enrollment fixed utility %s pid=%d Wait=%v\n", name, command.Process.Pid, waitErr)
		if err := check(); err != nil {
			return errors.Join(err, waitErr)
		}
		if ignore {
			return nil
		}
		return waitErr
	}
	if kind == "apparmor" {
		return run("apparmor_parser", []string{"-r", "/etc/apparmor.d/libvirt/TEMPLATE.qemu"}, true)
	}
	if _, _, err := lookup("apt-get"); err == nil {
		initial := []string{"install", "-y", "-qq", "qemu-system-x86", "qemu-utils", "libvirt-daemon-system", "genisoimage", "bridge-utils", "haproxy", "keepalived"}
		if err := run("apt-get", initial, false); err != nil {
			if canceled := check(); canceled != nil {
				return errors.Join(canceled, err)
			}
			if err := run("apt-get", []string{"update", "-qq", "-o", "Dir::Etc::sourcelist=/dev/null", "-o", "Dir::Etc::sourceparts=/dev/null"}, true); err != nil {
				return err
			}
			if err := run("apt-get", []string{"install", "-y", "-qq", "qemu-system-x86", "libvirt-daemon-system", "genisoimage", "bridge-utils", "haproxy", "keepalived"}, false); err != nil {
				return err
			}
		}
	} else if _, _, err := lookup("dnf"); err == nil {
		if err := run("dnf", []string{"install", "-y", "qemu-kvm-core", "libvirt-daemon-kvm", "genisoimage", "bridge-utils", "haproxy", "keepalived"}, false); err != nil {
			return err
		}
	}
	return run("modprobe", []string{"vfio-pci"}, true)
}

func enrollmentUtilityEnvironment(environment []string, kind enrollmentWorkerKind) []string {
	result := make([]string, 0, len(environment)+4)
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if key == "NOTIFY_SOCKET" || key == "INVOCATION_ID" || key == "MANAGERPID" || strings.HasPrefix(key, "LISTEN_") || strings.HasPrefix(key, "WATCHDOG_") || strings.HasPrefix(key, "DBUS_") || strings.HasPrefix(key, "LITEVIRT_ENROLLMENT_") || strings.HasPrefix(key, "SYSTEMD_") {
			continue
		}
		if kind == "prepare" && (key == "NEEDRESTART_SUSPEND" || key == "NEEDRESTART_MODE" || key == "DEBIAN_FRONTEND") {
			continue
		}
		result = append(result, entry)
	}
	if kind == "prepare" {
		result = append(result, "SYSTEMD_OFFLINE=1", "NEEDRESTART_SUSPEND=1", "NEEDRESTART_MODE=l", "DEBIAN_FRONTEND=noninteractive")
	}
	return result
}

// RunEnrollmentControl is the fixed local helper entry. No caller can supply
// a command, script, policy body, file path or additional operation kind.
func RunEnrollmentControl(ctx context.Context, purpose string) error {
	switch purpose {
	case "rollback", "launcher", "worker":
	default:
		return fmt.Errorf("unsupported enrollment control purpose %q", purpose)
	}
	if os.Geteuid() != 0 {
		return errors.New("enrollment control requires root")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if purpose == "rollback" {
		return errors.New("controlled rollback dispatch is not implemented")
	}
	stage, err := os.Getwd()
	if err != nil {
		return err
	}
	return runEnrollmentControl(ctx, purpose, defaultEnrollmentWorkerProfile(stage))
}

// Bootstrap is derived from our actual manager-owned unit and its fixed cwd;
// neither environment deadlines nor a header confers enrollment authority.
func enrollmentControlBootstrap(ctx context.Context, profile enrollmentWorkerProfile) (*enrollmentManager, enrollmentHandoff, *enrollmentWorkerUnit, error) {
	fail := func(err error) (*enrollmentManager, enrollmentHandoff, *enrollmentWorkerUnit, error) {
		return nil, enrollmentHandoff{}, nil, err
	}
	current, err := os.Getwd()
	if err != nil || current != profile.stage {
		return fail(errors.Join(errors.New("fixed worker staging changed"), err))
	}
	stage, err := openEnrollmentWorkerStage(current, 0)
	if err != nil {
		return fail(err)
	}
	if err = stage.close(); err != nil {
		return fail(err)
	}
	observer, err := openEnrollmentObserver(ctx)
	if err != nil {
		return fail(err)
	}
	refuse := func(e error) (*enrollmentManager, enrollmentHandoff, *enrollmentWorkerUnit, error) {
		end, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return fail(errors.Join(e, observer.retire(end)))
	}
	var path dbus.ObjectPath
	if err = observer.do(ctx, func() error {
		return observer.bus.Object(observer.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".GetUnitByPID", 0, uint32(os.Getpid())).Store(&path)
	}); err != nil {
		return refuse(err)
	}
	var properties map[string]dbus.Variant
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") {
		return refuse(errors.New("current worker has no actual unit"))
	}
	if err = observer.do(ctx, func() error {
		return observer.bus.Object(observer.owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.systemd1.Unit").Store(&properties)
	}); err != nil {
		return refuse(err)
	}
	unit, err := enrollmentProperty[string](properties, "Id")
	if err != nil {
		return refuse(err)
	}
	association, err := enrollmentWorkerAssociation(unit, profile.unitPrefix)
	if err != nil {
		return refuse(err)
	}
	state, err := observer.readWorker(ctx, unit, profile)
	if err != nil {
		return refuse(err)
	}
	if state == nil || state.Path != path || len(state.Invocation) != 16 || bytes.Equal(state.Invocation, make([]byte, 16)) {
		return refuse(errors.New("current worker incarnation not bound"))
	}
	invocation := os.Getenv("INVOCATION_ID")
	if len(invocation) != 32 || fmt.Sprintf("%x", state.Invocation) != invocation {
		return refuse(errors.New("actual worker invocation environment mismatch"))
	}
	body, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !enrollmentProcessGroup(body, state.Group) {
		return refuse(errors.Join(errors.New("current worker cgroup mismatch"), err))
	}
	return observer, association, state, nil
}
func runEnrollmentControl(parent context.Context, purpose string, profile enrollmentWorkerProfile) (result error) {
	if purpose != "launcher" && purpose != "worker" {
		return errors.New("unsupported fixed controlled worker purpose")
	}
	if os.Geteuid() != 0 {
		return errors.New("fixed worker requires root")
	}
	bounds, err := parseEnrollmentWorkerBounds(profile.environment)
	if err != nil {
		return err
	}
	ctx, cancel, err := bounds.context(parent, false)
	if err != nil {
		return err
	}
	defer cancel()
	handoff, stopHandoff, err := bounds.context(ctx, true)
	if err != nil {
		return err
	}
	defer stopHandoff()
	observer, association, initial, err := enrollmentControlBootstrap(handoff, profile)
	if err != nil {
		return err
	}
	retired := false
	retire := func() error {
		if retired {
			return nil
		}
		end, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		e := observer.retire(end)
		if e == nil {
			retired = true
		}
		return e
	}
	defer func() { result = errors.Join(result, retire()) }()
	if purpose == "launcher" {
		if err = enrollmentProcessImage(uint32(os.Getpid()), profile.image, profile.launcherArgs); err != nil {
			return err
		}
		if err = handoff.Err(); err != nil {
			return err
		}
		if err = retire(); err != nil {
			return err
		}
		command := exec.Command(profile.image, profile.workerArgs[1:]...)
		command.Dir = profile.stage
		command.Env = profile.environment
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err = command.Start(); err != nil {
			return err
		}
		// Intentional fork-provider protocol: this launcher exits normally; PID1
		// subsequently adopts/reaps the waiting worker. No utility executes here.
		return command.Process.Release()
	}
	if err = enrollmentProcessImage(uint32(os.Getpid()), profile.image, profile.workerArgs); err != nil {
		return err
	}
	stage, err := openEnrollmentWorkerStage(profile.stage, 0)
	if err != nil {
		return err
	}
	defer stage.close()
	socket, err := os.Lstat(stage.address())
	if err != nil || socket.Mode()&os.ModeSocket == 0 {
		return errors.Join(errors.New("parent control socket missing"), err)
	}
	socketOwner, ok := socket.Sys().(*syscall.Stat_t)
	if !ok || socketOwner.Uid != 0 {
		return errors.New("parent control socket not root owned")
	}
	connection, err := (&net.Dialer{}).DialContext(handoff, "unixpacket", stage.address())
	if err != nil {
		return err
	}
	defer connection.Close()
	channel, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("fixed worker route is not seqpacket")
	}
	peer, err := enrollmentSocketPeer(channel)
	if err != nil {
		return err
	}
	if err = observer.authenticateEnrollmentParent(handoff, peer, profile); err != nil {
		return err
	}
	files, err := readEnrollmentPacket(handoff, channel, association, false)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, enrollmentCloseFiles(files)) }()
	for i, file := range files {
		canonical := profile.claimPath
		if i == 1 {
			canonical = filepath.Join(profile.pkiDir, ".active-domain.lock")
		}
		if err = validateEnrollmentCapability(file, canonical, 0); err != nil {
			return err
		}
	}
	state, err := observer.readWorker(handoff, association.Unit, profile)
	if err != nil {
		return err
	}
	if err = state.launchGate(0); err != nil {
		return err
	}
	if state.Group != initial.Group || !bytes.Equal(state.Invocation, initial.Invocation) {
		return errors.New("worker incarnation changed before actual FDSTORE")
	}
	current, err := os.Lstat(stage.address())
	if err != nil || !os.SameFile(socket, current) {
		return errors.Join(errors.New("parent socket inode changed"), err)
	}
	if err = storeEnrollmentCapabilities(handoff, os.Getenv("NOTIFY_SOCKET"), association.FDNames, files); err != nil {
		return err
	}
	ready := association
	ready.Ready = true
	if err = writeEnrollmentPacket(handoff, channel, ready, nil); err != nil {
		return err
	}
	if err = awaitEnrollmentParentGate(handoff, channel, association); err != nil {
		return err
	}
	if err = observer.authenticateEnrollmentParent(handoff, peer, profile); err != nil {
		return err
	}
	state, err = observer.readWorker(handoff, association.Unit, profile)
	if err != nil {
		return err
	}
	if err = state.launchGate(len(files)); err != nil {
		return err
	}
	if state.Group != initial.Group || !bytes.Equal(state.Invocation, initial.Invocation) {
		return errors.New("worker incarnation changed before utility gate")
	}
	if err = retire(); err != nil {
		return err
	}
	utilityCtx, stopUtilities := context.WithCancel(ctx)
	defer stopUtilities()
	// After the one ACK, the parent must send nothing else. EOF, extra DATA or
	// protocol/peer failure prevents any subsequent utility; current descendants
	// remain in PID1 custody. Close every unexpected delivered right.
	stopMonitor := monitorEnrollmentParent(ctx, channel, stopUtilities)
	execution := profile.utilities
	execution.directory = profile.stage
	execution.environment = profile.environment
	utilityErr := runEnrollmentWorkerUtilities(utilityCtx, association.Kind, execution)
	monitorErr := stopMonitor()
	if utilityErr != nil || monitorErr != nil || utilityCtx.Err() != nil {
		return errors.Join(utilityErr, monitorErr, utilityCtx.Err())
	}
	if err = stage.validate(); err != nil {
		return err
	}
	complete := association
	complete.Completed = true
	return writeEnrollmentPacket(ctx, channel, complete, nil)
}
func (m *enrollmentManager) authenticateEnrollmentParent(ctx context.Context, peer *unix.Ucred, profile enrollmentWorkerProfile) error {
	if peer == nil || peer.Uid != 0 || peer.Gid != 0 || peer.Pid <= 0 {
		return errors.New("worker parent is not actual root peer")
	}
	start, err := enrollmentProcessStart(uint32(peer.Pid))
	if err != nil {
		return err
	}
	if err = m.checkGeneration(ctx); err != nil {
		return err
	}
	var owner string
	var pid, uid uint32
	if err = m.do(ctx, func() error {
		if err := m.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, enrollmentWriterName).Store(&owner); err != nil {
			return err
		}
		if err := m.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixProcessID", 0, owner).Store(&pid); err != nil {
			return err
		}
		return m.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, owner).Store(&uid)
	}); err != nil {
		return err
	}
	if uid != 0 || pid != uint32(peer.Pid) || !strings.HasPrefix(owner, ":") {
		return errors.New("socket parent does not own the actual enrollment writer generation")
	}
	if err = enrollmentProcessImage(pid, profile.parentImage, nil); err != nil {
		return err
	}
	after, err := enrollmentProcessStart(pid)
	if err != nil || after != start {
		return errors.Join(errors.New("parent PID incarnation changed"), err)
	}
	// Full marker/absence+settle remains the canonical fd9 parent's authority;
	// no serial or native authority is manufactured by this waiting worker.
	return m.checkGeneration(ctx)
}
