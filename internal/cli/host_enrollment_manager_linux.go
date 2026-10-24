package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

var errEnrollmentManagerRetired = errors.New("enrollment manager generation retired")

// The socket is independently owned: godbus Close takes a lock that a blocked
// socket writer can retain. No library lock lies on interrupt's path.
type enrollmentManager struct {
	mu             sync.Mutex
	raw            *net.UnixConn
	bus            *dbus.Conn
	retired        bool
	retiredCh      chan struct{}
	serial         chan struct{}
	inflight       sync.WaitGroup
	closeOnce      sync.Once
	closed         chan struct{}
	closeErr       error
	interruptOnce  sync.Once
	interruptErr   error
	busID          string
	owner          string
	unique         string
	bootID         string
	pidStart       string
	managerPID     uint32
	observer       bool
	signals        chan *dbus.Signal
	subscribed     bool
	mainUnit       string
	mainExecutable string
	mainArguments  []string
	controls       chan struct{}
	observations   sync.WaitGroup
	mainStopped    *enrollmentMainProof
	mainStarted    *enrollmentMainProof
	mainKnown      *enrollmentMainProof
	workerFiles    []*os.File
}

func openEnrollmentManager(ctx context.Context) (*enrollmentManager, error) {
	return connectEnrollmentManager(ctx, false)
}

func openEnrollmentObserver(ctx context.Context) (*enrollmentManager, error) {
	return connectEnrollmentManager(ctx, true)
}

const enrollmentWriterName = "org.litevirt.EnrollmentControl1"
const enrollmentSystemdInterface = "org.freedesktop.systemd1.Manager"
const enrollmentSystemdPath dbus.ObjectPath = "/org/freedesktop/systemd1"

func enrollmentConnectionUnique(names []string) (string, error) {
	if len(names) == 0 || len(names[0]) < 2 || !strings.HasPrefix(names[0], ":") {
		return "", fmt.Errorf("system bus did not assign a unique connection identity: %q", names)
	}
	// v5.2.2 prepends Hello's unique name and also tracks NameAcquired in
	// its map. Depending on signal timing, the same unique appears twice.
	for _, name := range names[1:] {
		if name != names[0] {
			return "", fmt.Errorf("unexpected pre-RequestName connection identity: %q", names)
		}
	}
	return names[0], nil
}

func enrollmentProcessStart(pid uint32) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return "", errors.New("invalid manager process identity")
	}
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) <= 19 {
		return "", errors.New("incomplete manager process identity")
	}
	if n, err := strconv.ParseUint(fields[19], 10, 64); err != nil || n == 0 {
		return "", errors.New("invalid manager start time")
	}
	return fields[19], nil
}

// Every generation owns its actual socket. Neither the process-global bus nor
// DBUS_SYSTEM_BUS_ADDRESS participates in the privileged route.
func connectEnrollmentManager(ctx context.Context, observer bool) (*enrollmentManager, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("enrollment manager requires root")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("enrollment manager requires an absolute deadline")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return nil, err
	}
	raw, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("system bus is not a Unix connection")
	}
	control, err := raw.SyscallConn()
	var peer *syscall.Ucred
	var credentialErr error
	if err == nil {
		err = control.Control(func(fd uintptr) {
			peer, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
	}
	if err != nil || credentialErr != nil || peer == nil || peer.Uid != 0 || peer.Pid <= 0 {
		_ = raw.Close()
		return nil, fmt.Errorf("system bus root peer not established: %w", errors.Join(err, credentialErr))
	}
	bus, err := dbus.DialUnix(raw, dbus.WithAuth(dbus.AuthExternal("0")))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	m := newEnrollmentTransport(raw, bus)
	m.observer = observer
	fail := func(cause error) (*enrollmentManager, error) {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		return nil, errors.Join(cause, m.retire(end))
	}
	// Auth and Hello have background-context library implementations; do's real
	// socket bound and joined cancellation interrupter enclose both of them.
	if err := m.do(ctx, func() error { return bus.Auth([]dbus.Auth{dbus.AuthExternal("0")}) }); err != nil {
		return fail(err)
	}
	if !bus.SupportsUnixFDs() {
		return fail(errors.New("system bus did not negotiate Unix descriptors"))
	}
	if err := m.do(ctx, bus.Hello); err != nil {
		return fail(err)
	}
	names := bus.Names()
	m.unique, err = enrollmentConnectionUnique(names)
	if err != nil {
		return fail(err)
	}
	if err := m.do(ctx, func() error {
		return bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetId", 0).Store(&m.busID)
	}); err != nil {
		return fail(err)
	}
	if err := m.do(ctx, func() error {
		return bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, "org.freedesktop.systemd1").Store(&m.owner)
	}); err != nil {
		return fail(err)
	}
	if len(m.busID) != 32 || !strings.HasPrefix(m.owner, ":") {
		return fail(errors.New("invalid bus or system manager identity"))
	}
	var uid uint32
	if err := m.do(ctx, func() error {
		return bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, m.owner).Store(&uid)
	}); err != nil {
		return fail(err)
	}
	if err := m.do(ctx, func() error {
		return bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixProcessID", 0, m.owner).Store(&m.managerPID)
	}); err != nil {
		return fail(err)
	}
	if uid != 0 || m.managerPID != 1 {
		return fail(errors.New("system manager is not the root PID1 generation"))
	}
	m.pidStart, err = enrollmentProcessStart(m.managerPID)
	if err != nil {
		return fail(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fail(err)
	}
	m.bootID = strings.TrimSpace(string(boot))
	if len(m.bootID) != 36 {
		return fail(errors.New("invalid boot identity"))
	}
	if !observer {
		var result uint32
		if err := m.do(ctx, func() error {
			return bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.RequestName", 0, enrollmentWriterName, uint32(dbus.NameFlagDoNotQueue)).Store(&result)
		}); err != nil {
			return fail(err)
		}
		if result != uint32(dbus.RequestNameReplyPrimaryOwner) {
			return fail(errors.New("another enrollment manager owns the writer name"))
		}
	}
	// Register locally before acknowledged matching/subscription. Future finite
	// job submissions consume this same connection and these exact observations.
	m.signals = make(chan *dbus.Signal, 256)
	bus.Signal(m.signals)
	if err := m.do(ctx, func() error {
		return bus.AddMatchSignalContext(ctx, dbus.WithMatchSender(m.owner), dbus.WithMatchObjectPath(enrollmentSystemdPath), dbus.WithMatchInterface(enrollmentSystemdInterface))
	}); err != nil {
		return fail(err)
	}
	if err := m.do(ctx, func() error {
		return bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".Subscribe", 0).Err
	}); err != nil {
		return fail(err)
	}
	m.subscribed = true
	return m, nil
}

func newEnrollmentTransport(raw *net.UnixConn, bus *dbus.Conn) *enrollmentManager {
	m := &enrollmentManager{raw: raw, bus: bus, retiredCh: make(chan struct{}), serial: make(chan struct{}, 1), closed: make(chan struct{}), mainUnit: "litevirt.service", mainExecutable: "/usr/local/bin/litevirt", mainArguments: []string{"/usr/local/bin/litevirt", "daemon"}, controls: make(chan struct{}, 1)}
	m.serial <- struct{}{}
	m.controls <- struct{}{}
	return m
}

type enrollmentMainState struct {
	Path                            dbus.ObjectPath
	Unit, Active, Group, Executable string
	Arguments                       []string
	Invocation                      []byte
	MainPID, ControlPID, FDStore    uint32
	Job                             struct {
		ID   uint32
		Path dbus.ObjectPath
	}
}

type enrollmentMainProof struct {
	Before  enrollmentMainState
	Job     dbus.ObjectPath
	After   *enrollmentMainState
	Absence *dbus.Call // actual correlated StopUnit NoSuchUnit; never a synthetic job
}

func (m *enrollmentManager) orderedMainAbsence(call *dbus.Call) error {
	if call == nil || call.Destination != m.owner || call.Path != enrollmentSystemdPath || call.Method != enrollmentSystemdInterface+".StopUnit" || len(call.Args) != 2 || call.Args[0] != m.mainUnit || call.Args[1] != "replace" || call.ResponseSequence == dbus.NoSequence {
		return errors.New("absence was not a received reply to this ordered main stop")
	}
	// Pinned godbus finalizeWithError delivers a direct Error value for an
	// actual remote error. Transport/cancellation/wrapped outcomes are UNKNOWN.
	remote, ok := call.Err.(dbus.Error)
	if !ok || remote.Name != "org.freedesktop.systemd1.NoSuchUnit" {
		return errors.New("ordered main stop did not return typed NoSuchUnit")
	}
	return nil
}

func (m *enrollmentManager) knownMainIncarnation(current *enrollmentMainState, prior *enrollmentMainProof) (*enrollmentMainState, error) {
	var known *enrollmentMainState
	if prior != nil {
		if prior.Absence != nil {
			if err := m.orderedMainAbsence(prior.Absence); err != nil {
				return nil, err
			}
			if prior.Before.Group != "" {
				known = &prior.Before
			}
		} else {
			if _, err := enrollmentJobID(prior.Job); err != nil {
				return nil, err
			}
			known = &prior.Before
			if prior.After != nil && prior.After.MainPID != 0 {
				known = prior.After
			}
		}
		if known != nil {
			if _, err := enrollmentStoppedMain(*known, nil); err != nil {
				return nil, err
			}
		}
	}
	if current == nil {
		return known, nil
	} // still MUST submit the actual ordered stop
	if current.Unit != m.mainUnit || current.Executable != m.mainExecutable || !equalEnrollmentArguments(current.Arguments, m.mainArguments) {
		return nil, errors.New("current main source differs from retained unit")
	}
	if current.MainPID != 0 {
		if _, err := enrollmentStoppedMain(*current, nil); err != nil {
			return nil, err
		}
		if known != nil && known.Group != current.Group {
			return nil, errors.New("previous main cgroup not reconciled")
		}
		return current, nil
	}
	if known == nil {
		return nil, errors.New("loaded inactive/failed main has no actual prior incarnation/group; reconciliation required")
	}
	if _, err := enrollmentStoppedMain(*known, current); err != nil {
		return nil, err
	}
	return known, nil
}

type enrollmentManagerJob struct {
	ID                uint32
	Unit, Type, State string
	Path, UnitPath    dbus.ObjectPath
}

type enrollmentUnitProperty struct {
	Name  string
	Value dbus.Variant
}
type enrollmentExecCommand struct {
	Path   string
	Args   []string
	Ignore bool
}
type enrollmentWorkerUnit struct {
	enrollmentMainState
	OOMPolicy *string
}

func enrollmentWorkerProperties(profile enrollmentWorkerProfile, bounds enrollmentWorkerBounds, oom bool) []enrollmentUnitProperty {
	properties := []enrollmentUnitProperty{
		{"Description", dbus.MakeVariant("LiteVirt controlled enrollment worker")},
		{"Type", dbus.MakeVariant("forking")}, {"GuessMainPID", dbus.MakeVariant(false)}, {"PIDFile", dbus.MakeVariant("")},
		{"RemainAfterExit", dbus.MakeVariant(false)}, {"Restart", dbus.MakeVariant("no")}, {"NotifyAccess", dbus.MakeVariant("all")},
		{"FileDescriptorStoreMax", dbus.MakeVariant(uint32(2))}, {"RuntimeMaxUSec", dbus.MakeVariant(uint64(math.MaxUint64))},
		{"WatchdogUSec", dbus.MakeVariant(uint64(0))}, {"StopWhenUnneeded", dbus.MakeVariant(false)},
		{"Delegate", dbus.MakeVariant(false)}, {"KillMode", dbus.MakeVariant("process")},
		{"WorkingDirectory", dbus.MakeVariant(profile.stage)},
		{"Environment", dbus.MakeVariant(append(enrollmentUtilityEnvironment(profile.environment, ""), bounds.environment()...))},
		{"ExecStart", dbus.MakeVariant([]enrollmentExecCommand{{profile.image, profile.launcherArgs, false}})},
	}
	for _, name := range []string{"ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"} {
		properties = append(properties, enrollmentUnitProperty{name, dbus.MakeVariant([]enrollmentExecCommand{})})
	}
	if oom {
		properties = append(properties, enrollmentUnitProperty{"OOMPolicy", dbus.MakeVariant("continue")})
	}
	return properties
}

func decodeEnrollmentWorkerUnit(unit string, path dbus.ObjectPath, properties, service map[string]dbus.Variant, profile enrollmentWorkerProfile) (*enrollmentWorkerUnit, error) {
	fail := func() (*enrollmentWorkerUnit, error) {
		return nil, errors.New("worker unit source/properties changed or malformed")
	}
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") {
		return fail()
	}
	state := &enrollmentWorkerUnit{}
	state.Path = path
	var err error
	if state.Unit, err = enrollmentProperty[string](properties, "Id"); err != nil || state.Unit != unit {
		return fail()
	}
	if state.Active, err = enrollmentProperty[string](properties, "ActiveState"); err != nil {
		return fail()
	}
	if state.Invocation, err = enrollmentProperty[[]byte](properties, "InvocationID"); err != nil {
		return fail()
	}
	if state.Group, err = enrollmentProperty[string](service, "ControlGroup"); err != nil {
		return fail()
	}
	if state.MainPID, err = enrollmentProperty[uint32](service, "MainPID"); err != nil {
		return fail()
	}
	if state.ControlPID, err = enrollmentProperty[uint32](service, "ControlPID"); err != nil {
		return fail()
	}
	if state.FDStore, err = enrollmentProperty[uint32](service, "NFileDescriptorStore"); err != nil {
		return fail()
	}
	if properties["Job"].Value() == nil {
		return fail()
	}
	if err := dbus.Store([]any{properties["Job"].Value()}, &state.Job); err != nil {
		return fail()
	}
	if state.Job.ID == 0 {
		if state.Job.Path != "/" {
			return fail()
		}
	} else if id, err := enrollmentJobID(state.Job.Path); err != nil || id != state.Job.ID {
		return fail()
	}
	for name, want := range map[string]string{"Type": "forking", "PIDFile": "", "Restart": "no", "NotifyAccess": "all", "WorkingDirectory": profile.stage, "KillMode": "process"} {
		if got, err := enrollmentProperty[string](service, name); err != nil || got != want {
			return fail()
		}
	}
	for name, want := range map[string]bool{"GuessMainPID": false, "RemainAfterExit": false, "Delegate": false} {
		if got, err := enrollmentProperty[bool](service, name); err != nil || got != want {
			return fail()
		}
	}
	if got, err := enrollmentProperty[bool](properties, "StopWhenUnneeded"); err != nil || got {
		return fail()
	}
	if got, err := enrollmentProperty[uint32](service, "FileDescriptorStoreMax"); err != nil || got != 2 {
		return fail()
	}
	if got, err := enrollmentProperty[uint64](service, "RuntimeMaxUSec"); err != nil || got != math.MaxUint64 {
		return fail()
	}
	if got, err := enrollmentProperty[uint64](service, "WatchdogUSec"); err != nil || got != 0 && got != math.MaxUint64 {
		return fail()
	}
	decoder := &enrollmentManager{mainExecutable: profile.image, mainArguments: profile.launcherArgs}
	command, err := decoder.decodeMainExec(service["ExecStart"])
	if err != nil {
		return fail()
	}
	state.Executable, state.Arguments = command.Path, command.Args
	for _, name := range []string{"ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost", "ExecCondition"} {
		value, present := service[name]
		if !present {
			if name == "ExecCondition" {
				continue
			}
			return fail()
		}
		var commands []enrollmentMainExec
		if value.Value() == nil || dbus.Store([]any{value.Value()}, &commands) != nil || len(commands) != 0 {
			return fail()
		}
	}
	if value, present := service["OOMPolicy"]; present {
		policy, ok := value.Value().(string)
		if !ok {
			return fail()
		}
		state.OOMPolicy = &policy
	}
	return state, nil
}

func enrollmentProperty[T any](properties map[string]dbus.Variant, name string) (T, error) {
	value, ok := properties[name].Value().(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("invalid actual property %s", name)
	}
	return value, nil
}

func (state *enrollmentWorkerUnit) launchGate(expected int) error {
	if state == nil || expected < 0 || expected > 2 {
		return errors.New("invalid known worker gate")
	}
	if state.Active != "active" || state.MainPID != 0 || state.ControlPID != 0 || state.FDStore != uint32(expected) || state.Job.ID != 0 || len(state.Invocation) != 16 || bytes.Equal(state.Invocation, make([]byte, 16)) {
		return errors.New("worker active/no-main/no-control/FD-store/invocation gate incomplete")
	}
	if err := enrollmentMainGroup(state.Unit, state.Group); err != nil {
		return err
	}
	if state.OOMPolicy != nil && *state.OOMPolicy != "continue" {
		return errors.New("worker OOM policy did not read back continue")
	}
	return nil
}

func (m *enrollmentManager) workerOOMSupport(ctx context.Context) (bool, error) {
	if err := m.checkGeneration(ctx); err != nil {
		return false, err
	}
	var path dbus.ObjectPath
	if err := m.do(ctx, func() error {
		return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".GetUnit", 0, "dbus.service").Store(&path)
	}); err != nil {
		return false, err
	}
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") {
		return false, errors.New("capability service object malformed")
	}
	var properties map[string]dbus.Variant
	if err := m.do(ctx, func() error {
		return m.bus.Object(m.owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.systemd1.Service").Store(&properties)
	}); err != nil {
		return false, err
	}
	if properties == nil {
		return false, errors.New("capability Service map missing")
	}
	if err := m.checkGeneration(ctx); err != nil {
		return false, err
	}
	return enrollmentWorkerOOMPresence(properties)
}

func enrollmentWorkerOOMPresence(properties map[string]dbus.Variant) (bool, error) {
	if properties == nil {
		return false, errors.New("capability Service map missing")
	}
	if value, present := properties["OOMPolicy"]; present {
		if _, ok := value.Value().(string); !ok {
			return false, errors.New("capability OOMPolicy property malformed")
		}
		return true, nil
	}
	return false, nil
}

func (m *enrollmentManager) noPendingMainJob(ctx context.Context) error {
	var jobs []enrollmentManagerJob
	if err := m.do(ctx, func() error {
		return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".ListJobs", 0).Store(&jobs)
	}); err != nil {
		return err
	}
	if err := m.mainJobsTerminal(jobs); err != nil {
		return err
	}
	return m.checkGeneration(ctx)
}

func (m *enrollmentManager) mainJobsTerminal(jobs []enrollmentManagerJob) error {
	for _, job := range jobs {
		if job.Unit == m.mainUnit {
			return fmt.Errorf("main still has actual pending job %d/%s", job.ID, job.Path)
		}
	}
	return nil
}

// control registers the whole observation, including signal waits and physical
// cgroup reads. Retirement first prohibits registration and interrupts the real
// socket, then joins these operations as well as their individual bus calls.
func (m *enrollmentManager) control(ctx context.Context, fn func() error) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("controlled operation requires an absolute deadline")
	}
	m.mu.Lock()
	if m.retired {
		m.mu.Unlock()
		return errEnrollmentManagerRetired
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return errors.Join(err, m.interrupt())
	}
	m.observations.Add(1)
	m.mu.Unlock()
	defer m.observations.Done()
	select {
	case <-m.controls:
	case <-m.retiredCh:
		return errEnrollmentManagerRetired
	case <-ctx.Done():
		return errors.Join(ctx.Err(), m.interrupt())
	}
	defer func() { m.controls <- struct{}{} }()
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			m.interrupt()
		case <-stop:
		}
	}()
	err := func() error {
		select {
		case <-m.retiredCh:
			return errEnrollmentManagerRetired
		default:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn()
	}()
	close(stop)
	<-joined
	if ctx.Err() != nil {
		return errors.Join(errors.New("controlled outcome unknown"), ctx.Err(), m.interrupt())
	}
	select {
	case <-m.retiredCh:
		return errors.Join(err, errEnrollmentManagerRetired)
	default:
	}
	return err
}

func enrollmentJobID(path dbus.ObjectPath) (uint32, error) {
	const prefix = "/org/freedesktop/systemd1/job/"
	if !strings.HasPrefix(string(path), prefix) {
		return 0, errors.New("invalid accepted manager job path")
	}
	tail := strings.TrimPrefix(string(path), prefix)
	id, err := strconv.ParseUint(tail, 10, 32)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != tail {
		return 0, errors.New("invalid accepted manager job identity")
	}
	return uint32(id), nil
}

func enrollmentJobEvent(event *dbus.Signal, owner string, path dbus.ObjectPath, unit string) (bool, error) {
	id, err := enrollmentJobID(path)
	if err != nil {
		return false, err
	}
	if event == nil {
		return false, errors.New("manager signal stream closed")
	}
	if event.Name != enrollmentSystemdInterface+".JobRemoved" && event.Name != enrollmentSystemdInterface+".Reloading" {
		return false, nil
	}
	if event.Sender != owner || event.Path != enrollmentSystemdPath {
		return false, errors.New("manager observation has wrong generation or path")
	}
	if event.Name == enrollmentSystemdInterface+".Reloading" {
		return false, errors.New("manager reload invalidates controlled outcome")
	}
	if len(event.Body) != 4 {
		return false, errors.New("invalid JobRemoved arity")
	}
	gotID, a := event.Body[0].(uint32)
	gotPath, b := event.Body[1].(dbus.ObjectPath)
	gotUnit, c := event.Body[2].(string)
	result, d := event.Body[3].(string)
	if !a || !b || !c || !d {
		return false, errors.New("invalid JobRemoved types")
	}
	if gotPath != path {
		return false, nil
	}
	if gotID != id || gotUnit != unit || result != "done" {
		return false, fmt.Errorf("accepted job %s ended %q for %q", path, result, gotUnit)
	}
	return true, nil
}

func (m *enrollmentManager) waitMainJob(ctx context.Context, path dbus.ObjectPath) error {
	if _, err := enrollmentJobID(path); err != nil {
		return err
	}
	for {
		select {
		case event, ok := <-m.signals:
			if !ok {
				return errors.New("manager signal stream closed before terminal job")
			}
			done, err := enrollmentJobEvent(event, m.owner, path, m.mainUnit)
			if err != nil {
				return errors.Join(err, m.interrupt())
			}
			if done {
				return m.checkGeneration(ctx)
			}
		case <-m.retiredCh:
			return errEnrollmentManagerRetired
		case <-ctx.Done():
			return errors.Join(errors.New("accepted manager job outcome unknown"), ctx.Err(), m.interrupt())
		}
	}
}

type enrollmentMainExec struct {
	Path                                                       string
	Args                                                       []string
	Ignore                                                     bool
	StartRealtime, StartMonotonic, ExitRealtime, ExitMonotonic uint64
	PID                                                        uint32
	Code, Status                                               int32
}

// The only selectable target is the retained main unit. Tests map this private
// field to their independently owned unit; no runtime path/argv API is exposed.
func (m *enrollmentManager) readMain(ctx context.Context, load bool) (*enrollmentMainState, error) {
	if err := m.checkGeneration(ctx); err != nil {
		return nil, err
	}
	method := "GetUnit"
	if load {
		method = "LoadUnit"
	}
	var path dbus.ObjectPath
	err := m.do(ctx, func() error {
		return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+"."+method, 0, m.mainUnit).Store(&path)
	})
	if err != nil {
		var remote dbus.Error
		if errors.As(err, &remote) && remote.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return nil, nil
		}
		return nil, err
	}
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") {
		return nil, errors.New("invalid actual main unit object")
	}
	var unit, service map[string]dbus.Variant
	for _, query := range []struct {
		name   string
		result *map[string]dbus.Variant
	}{{"org.freedesktop.systemd1.Unit", &unit}, {"org.freedesktop.systemd1.Service", &service}} {
		if err := m.do(ctx, func() error {
			return m.bus.Object(m.owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, query.name).Store(query.result)
		}); err != nil {
			return nil, err
		}
	}
	info := &enrollmentMainState{Path: path}
	var ok bool
	if info.Unit, ok = unit["Id"].Value().(string); !ok || info.Unit != m.mainUnit {
		return nil, errors.New("main unit identity mismatch")
	}
	if info.Active, ok = unit["ActiveState"].Value().(string); !ok {
		return nil, errors.New("invalid actual main ActiveState")
	}
	if info.Invocation, ok = unit["InvocationID"].Value().([]byte); !ok {
		return nil, errors.New("invalid actual main invocation")
	}
	if info.Group, ok = service["ControlGroup"].Value().(string); !ok {
		return nil, errors.New("invalid actual main cgroup")
	}
	if info.MainPID, ok = service["MainPID"].Value().(uint32); !ok {
		return nil, errors.New("invalid actual main PID")
	}
	if info.ControlPID, ok = service["ControlPID"].Value().(uint32); !ok {
		return nil, errors.New("invalid actual main control PID")
	}
	if info.FDStore, ok = service["NFileDescriptorStore"].Value().(uint32); !ok {
		return nil, errors.New("invalid actual main FD store")
	}
	if err := dbus.Store([]any{unit["Job"].Value()}, &info.Job); err != nil {
		return nil, errors.New("invalid actual main pending job")
	}
	if info.Job.ID == 0 {
		if info.Job.Path != "/" {
			return nil, errors.New("main no-job observation has unexpected path")
		}
	} else if id, err := enrollmentJobID(info.Job.Path); err != nil || id != info.Job.ID {
		return nil, errors.New("main pending job identity mismatch")
	}
	mode, ok := service["KillMode"].Value().(string)
	delegate, delegatedOK := service["Delegate"].Value().(bool)
	if !ok || mode != "process" || !delegatedOK || delegate {
		return nil, errors.New("main process-custody unit properties changed")
	}
	command, err := m.decodeMainExec(service["ExecStart"])
	if err != nil {
		return nil, err
	}
	info.Executable, info.Arguments = command.Path, command.Args
	if err := m.checkGeneration(ctx); err != nil {
		return nil, err
	}
	return info, nil
}

func (m *enrollmentManager) decodeMainExec(value dbus.Variant) (enrollmentMainExec, error) {
	// The original systemd ABI is a(sasbttttuii). Call.Store's map copying
	// re-infers variant signatures, so decode its actual ten typed values.
	if value.Value() == nil {
		return enrollmentMainExec{}, errors.New("main executable property is missing")
	}
	var commands []enrollmentMainExec
	if err := dbus.Store([]any{value.Value()}, &commands); err != nil || len(commands) != 1 {
		return enrollmentMainExec{}, errors.New("main executable is not the one retained command")
	}
	command := commands[0]
	if command.Ignore || command.Path != m.mainExecutable || !equalEnrollmentArguments(command.Args, m.mainArguments) {
		return enrollmentMainExec{}, errors.New("main executable source or arguments changed")
	}
	return command, nil
}

func enrollmentMainGroup(unit, group string) error {
	if group == "" || filepath.Clean(group) != group || !strings.HasPrefix(group, "/") || !strings.HasSuffix(group, "/"+unit) {
		return errors.New("main cgroup is unknown or outside its bound unit")
	}
	return nil
}

func enrollmentCgroupEmpty(unit, group string) (bool, error) {
	if err := enrollmentMainGroup(unit, group); err != nil {
		return false, err
	}
	body, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(group, "/"), "cgroup.events"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	} // only the previously bound, nonempty group
	if err != nil {
		return false, err
	}
	return enrollmentCgroupPopulation(body)
}

func enrollmentCgroupPopulation(body []byte) (bool, error) {
	found, empty := false, false
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "populated ") {
			if found || line != "populated 0" && line != "populated 1" {
				return false, errors.New("invalid physical cgroup population")
			}
			found, empty = true, line == "populated 0"
		}
	}
	if !found {
		return false, errors.New("physical cgroup population is unproved")
	}
	return empty, nil
}

func enrollmentStoppedMain(before enrollmentMainState, after *enrollmentMainState) (bool, error) {
	if before.MainPID == 0 || len(before.Invocation) != 16 || bytes.Equal(before.Invocation, make([]byte, 16)) {
		return false, errors.New("main stop has no bound running invocation")
	}
	if err := enrollmentMainGroup(before.Unit, before.Group); err != nil {
		return false, err
	}
	if after == nil {
		return true, nil
	} // known incarnation; physical group gate still required
	if after.Unit != before.Unit || after.Path != before.Path || after.Executable != before.Executable || !equalEnrollmentArguments(after.Arguments, before.Arguments) || len(after.Invocation) != 0 && !bytes.Equal(after.Invocation, before.Invocation) || after.Group != "" && after.Group != before.Group || after.MainPID != 0 && after.MainPID != before.MainPID {
		return false, errors.New("main incarnation changed during controlled stop")
	}
	return after.MainPID == 0 && after.ControlPID == 0 && after.FDStore == 0 && after.Job.ID == 0 && (after.Active == "inactive" || after.Active == "failed"), nil
}

func equalEnrollmentArguments(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (m *enrollmentManager) requireWriter(ctx context.Context) error {
	if m.observer || !m.subscribed || m.unique == "" {
		return errors.New("observer or unregistered connection cannot submit main jobs")
	}
	if err := m.checkGeneration(ctx); err != nil {
		return err
	}
	var owner string
	if err := m.do(ctx, func() error {
		return m.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, enrollmentWriterName).Store(&owner)
	}); err != nil {
		return err
	}
	if owner != m.unique {
		return errors.Join(errors.New("main writer name changed; reconciliation required"), m.interrupt())
	}
	return nil
}

func (m *enrollmentManager) quiesceMain(ctx context.Context) error {
	return m.control(ctx, func() error {
		prior := m.mainKnown
		m.mainStopped, m.mainStarted = nil, nil
		if err := m.requireWriter(ctx); err != nil {
			return err
		}
		observed, err := m.readMain(ctx, false)
		if err != nil {
			return err
		}
		known, err := m.knownMainIncarnation(observed, prior)
		if err != nil {
			return err
		}
		var job dbus.ObjectPath
		var call *dbus.Call
		err = m.do(ctx, func() error {
			call = m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".StopUnit", 0, m.mainUnit, "replace")
			return call.Store(&job)
		})
		if err != nil {
			if _, direct := err.(dbus.Error); !direct {
				return err
			}
			if absent := m.orderedMainAbsence(call); absent != nil {
				return errors.Join(err, absent)
			}
			after, observeErr := m.readMain(ctx, false)
			if observeErr != nil {
				return observeErr
			}
			if after != nil {
				return errors.New("main became loaded after ordered NoSuchUnit; reconciliation required")
			}
			if err := m.noPendingMainJob(ctx); err != nil {
				return err
			}
			proof := &enrollmentMainProof{Before: enrollmentMainState{Unit: m.mainUnit}, Absence: call}
			if known != nil {
				empty, err := enrollmentCgroupEmpty(known.Unit, known.Group)
				if err != nil {
					return err
				}
				if !empty {
					return errors.New("known main descendants survive ordered manager absence")
				}
				proof.Before = *known
			}
			if err := m.requireWriter(ctx); err != nil {
				return err
			}
			m.mainStopped, m.mainKnown = proof, proof
			return nil // only manager barrier; the caller still MUST obtain real PKI EX
		}
		if _, err := enrollmentJobID(job); err != nil {
			return err
		}
		if known != nil {
			m.mainKnown = &enrollmentMainProof{Before: *known, Job: job}
		}
		if err := m.waitMainJob(ctx, job); err != nil {
			return err
		}
		if known == nil {
			return errors.New("actual stop job lacks a known capable invocation/group; reconciliation required")
		}
		for {
			after, err := m.readMain(ctx, false)
			if err != nil {
				return err
			}
			terminal, err := enrollmentStoppedMain(*known, after)
			if err != nil {
				return err
			}
			empty, err := enrollmentCgroupEmpty(known.Unit, known.Group)
			if err != nil {
				return err
			}
			if terminal && empty {
				if err := m.noPendingMainJob(ctx); err != nil {
					return err
				}
				if err := m.requireWriter(ctx); err != nil {
					return err
				}
				proof := &enrollmentMainProof{Before: *known, Job: job, After: after}
				m.mainStopped, m.mainKnown = proof, proof
				return nil
			}
			select {
			case <-ctx.Done():
				return errors.Join(ctx.Err(), m.interrupt())
			case <-m.retiredCh:
				return errEnrollmentManagerRetired
			case <-time.After(10 * time.Millisecond):
			}
		}
	})
}

func (m *enrollmentManager) startMain(ctx context.Context) error {
	return m.control(ctx, func() error {
		if err := m.requireWriter(ctx); err != nil {
			return err
		}
		proof := m.mainStopped
		if proof == nil {
			return errors.New("main start requires this generation's complete physical stop proof")
		}
		before, err := m.readMain(ctx, true)
		if err != nil {
			return err
		}
		if before == nil || before.MainPID != 0 || before.ControlPID != 0 || before.FDStore != 0 || before.Job.ID != 0 || (before.Active != "inactive" && before.Active != "failed") {
			return errors.New("main no longer stopped before controlled start")
		}
		if proof.Absence != nil {
			if err := m.orderedMainAbsence(proof.Absence); err != nil {
				return err
			}
		}
		if proof.Before.Group != "" {
			empty, err := enrollmentCgroupEmpty(proof.Before.Unit, proof.Before.Group)
			if err != nil {
				return err
			}
			if !empty {
				return errors.New("main descendants still populate stopped invocation")
			}
		} else if proof.Absence == nil {
			return errors.New("main start has neither ordered absence nor a known physical group")
		}
		if err := m.noPendingMainJob(ctx); err != nil {
			return err
		}
		// Consume before any submission: an unknown reset/start is never replayed.
		m.mainStopped = nil
		if before.Active == "failed" {
			if err := m.do(ctx, func() error {
				return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".ResetFailedUnit", 0, m.mainUnit).Err
			}); err != nil {
				return err
			}
		}
		var job dbus.ObjectPath
		if err := m.do(ctx, func() error {
			return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".StartUnit", 0, m.mainUnit, "replace").Store(&job)
		}); err != nil {
			return err
		}
		if err := m.waitMainJob(ctx, job); err != nil {
			return err
		}
		after, err := m.readMain(ctx, false)
		if err != nil {
			return err
		}
		if after == nil || after.Active != "active" || after.MainPID == 0 || after.ControlPID != 0 || after.FDStore != 0 || after.Job.ID != 0 || len(after.Invocation) != 16 || bytes.Equal(after.Invocation, make([]byte, 16)) || bytes.Equal(after.Invocation, proof.Before.Invocation) {
			return errors.New("controlled start lacks a fresh active main incarnation")
		}
		if err := enrollmentMainGroup(after.Unit, after.Group); err != nil {
			return err
		}
		if err := m.requireWriter(ctx); err != nil {
			return err
		}
		m.mainStarted = &enrollmentMainProof{Before: *before, Job: job, After: after}
		m.mainKnown = m.mainStarted
		return nil
	})
}

// These are actual fresh observations, never properties read with the
// library's background-context convenience methods.
func (m *enrollmentManager) checkGeneration(ctx context.Context) error {
	var busID, owner string
	var pid, uid uint32
	err := m.do(ctx, func() error {
		if err := m.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetId", 0).Store(&busID); err != nil {
			return err
		}
		if err := m.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, "org.freedesktop.systemd1").Store(&owner); err != nil {
			return err
		}
		if err := m.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixProcessID", 0, owner).Store(&pid); err != nil {
			return err
		}
		return m.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", 0, owner).Store(&uid)
	})
	if err != nil {
		return errors.Join(err, m.interrupt())
	}
	start, startErr := enrollmentProcessStart(pid)
	boot, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if startErr != nil || bootErr != nil || busID != m.busID || owner != m.owner || pid != m.managerPID || uid != 0 || start != m.pidStart || strings.TrimSpace(string(boot)) != m.bootID {
		return errors.Join(errors.New("enrollment bus or manager generation changed; reconciliation required"), startErr, bootErr, m.interrupt())
	}
	return nil
}

// Reload is a fixed prerequisite operation on an unnamed connection. It never
// appears implicitly in the named writer factory or submits a systemd job.
func reloadEnrollmentControlPolicy(ctx context.Context) (err error) {
	observer, err := openEnrollmentObserver(ctx)
	if err != nil {
		return err
	}
	defer func() {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		err = errors.Join(err, observer.retire(end))
	}()
	if err := observer.checkGeneration(ctx); err != nil {
		return err
	}
	if err := observer.do(ctx, func() error {
		return observer.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.ReloadConfig", 0).Err
	}); err != nil {
		return err
	}
	return observer.checkGeneration(ctx)
}

func (m *enrollmentManager) interrupt() error {
	// Every caller waits for the same actual interruption. Observing RETIRED
	// alone is not proof that another goroutine has yet closed the socket.
	m.interruptOnce.Do(func() {
		m.mu.Lock()
		m.retired = true
		close(m.retiredCh)
		m.mu.Unlock()
		deadlineErr := m.raw.SetDeadline(time.Now())
		closeErr := m.raw.Close()
		if errors.Is(deadlineErr, net.ErrClosed) {
			deadlineErr = nil
		}
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
		m.interruptErr = errors.Join(deadlineErr, closeErr)
	})
	return m.interruptErr
}

// do registers before a send can start, without retaining mu across socket I/O.
// A canceled call retires the whole generation; its result is never replayed.
func (m *enrollmentManager) do(ctx context.Context, fn func() error) error {
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return errors.New("enrollment manager operation requires an absolute deadline")
	}
	m.mu.Lock()
	if m.retired {
		m.mu.Unlock()
		return errEnrollmentManagerRetired
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("enrollment manager outcome unknown: %w", errors.Join(err, m.interrupt()))
	}
	m.inflight.Add(1)
	m.mu.Unlock()
	defer m.inflight.Done()
	select {
	case <-m.serial:
	case <-m.retiredCh:
		return errEnrollmentManagerRetired
	case <-ctx.Done():
		m.interrupt()
		return fmt.Errorf("enrollment manager outcome unknown: %w", ctx.Err())
	}
	defer func() { m.serial <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("enrollment manager outcome unknown: %w", errors.Join(err, m.interrupt()))
	}
	m.mu.Lock()
	if m.retired {
		m.mu.Unlock()
		return errEnrollmentManagerRetired
	}
	// Installing the bound and clearing it are ordered with OPEN -> RETIRED.
	err := m.raw.SetDeadline(deadline)
	m.mu.Unlock()
	if err != nil {
		m.interrupt()
		return fmt.Errorf("enrollment manager outcome unknown: %w", err)
	}
	stop := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			m.interrupt()
		case <-stop:
		}
	}()
	err = fn()
	close(stop)
	<-joined
	if ctx.Err() != nil {
		m.interrupt()
		return fmt.Errorf("enrollment manager outcome unknown: %w", ctx.Err())
	}
	if err != nil {
		// A decoded remote error is a known reply. Transport/decoder failures
		// cannot establish what the remote manager accepted.
		var remote dbus.Error
		if !errors.As(err, &remote) {
			m.interrupt()
			return fmt.Errorf("enrollment manager outcome unknown: %w", err)
		}
	}
	m.mu.Lock()
	if !m.retired {
		if clear := m.raw.SetDeadline(time.Time{}); clear != nil {
			m.mu.Unlock()
			m.interrupt()
			return fmt.Errorf("enrollment manager outcome unknown: %w", clear)
		}
	}
	m.mu.Unlock()
	return err
}

func (m *enrollmentManager) retire(ctx context.Context) error {
	// Raw interruption must precede both the sender join and library Close.
	interruptErr := m.interrupt()
	m.closeOnce.Do(func() {
		go func() {
			m.observations.Wait()
			m.inflight.Wait()
			busErr := m.bus.Close()
			if errors.Is(busErr, net.ErrClosed) {
				busErr = nil
			}
			m.mu.Lock()
			files := m.workerFiles
			m.workerFiles = nil
			m.mu.Unlock()
			m.closeErr = errors.Join(busErr, enrollmentCloseFiles(files))
			close(m.closed)
		}()
	})
	select {
	case <-m.closed:
		if errors.Is(m.closeErr, net.ErrClosed) {
			return interruptErr
		}
		return errors.Join(interruptErr, m.closeErr)
	case <-ctx.Done():
		// The original close remains owned by m.closed. No caller may yield
		// its claim/EX until that same operation has actually joined.
		return fmt.Errorf("enrollment retirement incomplete: %w", ctx.Err())
	}
}

// Ownership passes only on success; these are local duplicates, never caller leases.
func (m *enrollmentManager) ownWorkerFiles(files []*os.File) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retired {
		return errEnrollmentManagerRetired
	}
	if len(files) == 0 || len(files) > 2 || len(m.workerFiles) != 0 {
		return errors.New("invalid or already occupied local worker custody")
	}
	for _, f := range files {
		if f == nil {
			return errors.New("nil local worker capability")
		}
	}
	m.workerFiles = append([]*os.File{}, files...)
	return nil
}

// Normal release is inside the registered whole control observation; retirement
// must join it before reporting its own local custody disposition.
func (m *enrollmentManager) releaseWorkerFiles() error {
	m.mu.Lock()
	files := m.workerFiles
	m.workerFiles = nil
	m.mu.Unlock()
	return enrollmentCloseFiles(files)
}
func enrollmentCloseFiles(files []*os.File) error {
	var result error
	for _, f := range files {
		result = errors.Join(result, f.Close())
	}
	return result
}

func enrollmentWorkerTerminal(before enrollmentWorkerUnit, current *enrollmentWorkerUnit, empty bool) (bool, error) {
	if before.Unit == "" || len(before.Invocation) != 16 || bytes.Equal(before.Invocation, make([]byte, 16)) {
		return false, errors.New("no actual worker invocation bound")
	}
	if err := enrollmentMainGroup(before.Unit, before.Group); err != nil {
		return false, err
	}
	if current != nil {
		if current.Unit != before.Unit || current.Path != before.Path || current.Executable != before.Executable || !equalEnrollmentArguments(current.Arguments, before.Arguments) || len(current.Invocation) > 0 && !bytes.Equal(current.Invocation, before.Invocation) || current.Group != "" && current.Group != before.Group {
			return false, errors.New("known worker incarnation/source changed")
		}
		if current.Active != "inactive" && current.Active != "failed" || current.MainPID != 0 || current.ControlPID != 0 || current.FDStore != 0 || current.Job.ID != 0 {
			return false, nil
		}
	}
	return empty, nil
}
func enrollmentWorkerAssociation(unit, prefix string) (enrollmentHandoff, error) {
	for _, kind := range []enrollmentWorkerKind{"prepare", "apparmor"} {
		suffix := "-" + string(kind) + ".service"
		if strings.HasPrefix(unit, prefix) && strings.HasSuffix(unit, suffix) {
			attempt := strings.TrimSuffix(strings.TrimPrefix(unit, prefix), suffix)
			if enrollmentAttemptValid(attempt) {
				return enrollmentHandoff{Version: 1, Attempt: attempt, Unit: unit, Kind: kind, FDNames: enrollmentFDNames(kind)}, nil
			}
		}
	}
	return enrollmentHandoff{}, errors.New("actual unit is not a selected enrollment worker")
}

// These methods use the same owning connection and its already acknowledged
// subscription. No convenience getter may escape the original context.
func (m *enrollmentManager) readWorker(ctx context.Context, unit string, profile enrollmentWorkerProfile) (*enrollmentWorkerUnit, error) {
	if _, err := enrollmentWorkerAssociation(unit, profile.unitPrefix); err != nil {
		return nil, err
	}
	if err := m.checkGeneration(ctx); err != nil {
		return nil, err
	}
	var path dbus.ObjectPath
	err := m.do(ctx, func() error {
		return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".GetUnit", 0, unit).Store(&path)
	})
	if err != nil {
		var remote dbus.Error
		if errors.As(err, &remote) && remote.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return nil, m.checkGeneration(ctx)
		}
		return nil, err
	}
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") {
		return nil, errors.New("invalid worker unit object")
	}
	var properties, service map[string]dbus.Variant
	for _, q := range []struct {
		name   string
		result *map[string]dbus.Variant
	}{{"org.freedesktop.systemd1.Unit", &properties}, {"org.freedesktop.systemd1.Service", &service}} {
		if err = m.do(ctx, func() error {
			return m.bus.Object(m.owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, q.name).Store(q.result)
		}); err != nil {
			return nil, err
		}
	}
	state, err := decodeEnrollmentWorkerUnit(unit, path, properties, service, profile)
	if err != nil {
		return nil, err
	}
	if err = m.checkGeneration(ctx); err != nil {
		return nil, err
	}
	return state, nil
}
func (m *enrollmentManager) waitWorkerJob(ctx context.Context, path dbus.ObjectPath, unit string) error {
	if _, err := enrollmentJobID(path); err != nil {
		return err
	}
	for {
		select {
		case event, ok := <-m.signals:
			if !ok {
				return errors.New("worker job signal stream closed")
			}
			done, err := enrollmentJobEvent(event, m.owner, path, unit)
			if err != nil {
				return errors.Join(err, m.interrupt())
			}
			if done {
				return m.checkGeneration(ctx)
			}
		case <-m.retiredCh:
			return errEnrollmentManagerRetired
		case <-ctx.Done():
			return errors.Join(errors.New("worker job outcome unknown"), ctx.Err(), m.interrupt())
		}
	}
}
func (m *enrollmentManager) noWorkerJobs(ctx context.Context, units ...string) error {
	var jobs []enrollmentManagerJob
	if err := m.do(ctx, func() error {
		return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".ListJobs", 0).Store(&jobs)
	}); err != nil {
		return err
	}
	for _, job := range jobs {
		for _, unit := range units {
			if job.Unit == unit {
				return errors.New("known worker still has a pending job")
			}
		}
	}
	return m.checkGeneration(ctx)
}
func (m *enrollmentManager) workerPeer(ctx context.Context, peer *unix.Ucred, state *enrollmentWorkerUnit, profile enrollmentWorkerProfile) (string, error) {
	if peer == nil || peer.Pid <= 0 || peer.Uid != 0 || peer.Gid != 0 || state == nil {
		return "", errors.New("actual root worker peer required")
	}
	pid := uint32(peer.Pid)
	start, err := enrollmentProcessStart(pid)
	if err != nil {
		return "", err
	}
	var path dbus.ObjectPath
	if err = m.do(ctx, func() error {
		return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".GetUnitByPID", 0, pid).Store(&path)
	}); err != nil {
		return "", err
	}
	if path != state.Path {
		return "", errors.New("actual socket peer is outside the known worker unit")
	}
	if err = enrollmentProcessImage(pid, profile.image, profile.workerArgs); err != nil {
		return "", err
	}
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	if !enrollmentProcessGroup(body, state.Group) {
		return "", errors.New("actual socket peer cgroup differs from known invocation")
	}
	after, err := enrollmentProcessStart(pid)
	if err != nil || after != start {
		return "", errors.Join(errors.New("worker peer changed incarnation"), err)
	}
	return start, m.checkGeneration(ctx)
}
func enrollmentProcessImage(pid uint32, path string, args []string) error {
	executable, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	canonical, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := canonical.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !canonical.Mode().IsRegular() || canonical.Mode().Perm()&0022 != 0 || !os.SameFile(executable, canonical) {
		return errors.New("known process image inode/owner changed")
	}
	if args != nil {
		body, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return err
		}
		if len(body) > 16*1024 || len(body) == 0 || body[len(body)-1] != 0 {
			return errors.New("invalid known process arguments")
		}
		got := strings.Split(string(body[:len(body)-1]), "\x00")
		if !equalEnrollmentArguments(got, args) {
			return errors.New("known process arguments changed")
		}
	}
	return nil
}
func enrollmentProcessGroup(body []byte, group string) bool {
	if group == "" {
		return false
	}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) != 3 {
			continue
		}
		if f[0] == "0" && f[1] == "" || strings.Contains(","+f[1]+",", ",name=systemd,") {
			if f[2] == group {
				return true
			}
		}
	}
	return false
}

type enrollmentWorkerProof struct {
	Association                                        enrollmentHandoff
	Job                                                dbus.ObjectPath
	PossibleStart                                      bool
	Bound                                              *enrollmentWorkerUnit
	PeerPID                                            int32
	PeerStart                                          string
	StreamComplete, Drained                            bool
	GatePending, GateAcknowledged                      bool
	LocalCopiesClosed                                  bool
	BusID, ManagerOwner, ManagerPIDStart, BootID       string
	Stage                                              string
	StageDevice, StageInode, SocketDevice, SocketInode uint64
}

// Caller retains its original claim/EX on every unknown result. The generation
// owns close-only copies; PID1 owns independent duplicates after actual FDSTORE.
func (m *enrollmentManager) runWorker(ctx context.Context, profile enrollmentWorkerProfile, attempt string, kind enrollmentWorkerKind, capabilities []*os.File, validate func() error) (proof *enrollmentWorkerProof, result error) {
	unit := profile.unitPrefix + attempt + "-" + string(kind) + ".service"
	association, err := enrollmentWorkerAssociation(unit, profile.unitPrefix)
	if err != nil {
		return nil, err
	}
	if validate == nil || profile.record == nil || len(capabilities) != len(association.FDNames) {
		return nil, errors.New("full parent claim/settle validator and exact capabilities required")
	}
	if err = validate(); err != nil {
		return nil, err
	}
	bounds, err := captureEnrollmentWorkerBounds(ctx)
	if err != nil {
		return nil, err
	}
	handoff, stopHandoff, err := bounds.context(ctx, true)
	if err != nil {
		return nil, err
	}
	defer stopHandoff()
	stage, err := openEnrollmentWorkerStage(profile.stage, 0)
	if err != nil {
		return nil, err
	}
	defer stage.close()
	listener, err := stage.listen()
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	// Files are duplicated atomically CLOEXEC, never LOCK_UN'd or independently
	// reopened. Registration and retirement share the existing submit mutex.
	var owned []*os.File
	for _, file := range capabilities {
		if file == nil {
			enrollmentCloseFiles(owned)
			return nil, errors.New("missing held capability")
		}
		fd, e := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if e != nil {
			enrollmentCloseFiles(owned)
			return nil, e
		}
		owned = append(owned, os.NewFile(uintptr(fd), "enrollment-local-worker-copy"))
	}
	for i, file := range owned {
		canonical := profile.claimPath
		if i == 1 {
			canonical = filepath.Join(profile.pkiDir, ".active-domain.lock")
		}
		if err = validateEnrollmentCapability(file, canonical, 0); err != nil {
			enrollmentCloseFiles(owned)
			stage.removeSocket()
			return nil, err
		}
	}
	proof = &enrollmentWorkerProof{Association: association, BusID: m.busID, ManagerOwner: m.owner, ManagerPIDStart: m.pidStart, BootID: m.bootID}
	stageStat := stage.identity.Sys().(*syscall.Stat_t)
	socketStat := stage.socket.Sys().(*syscall.Stat_t)
	proof.Stage = stage.path
	proof.StageDevice = uint64(stageStat.Dev)
	proof.StageInode = stageStat.Ino
	proof.SocketDevice = uint64(socketStat.Dev)
	proof.SocketInode = socketStat.Ino
	ownedByManager := false
	result = m.control(ctx, func() error {
		if e := m.ownWorkerFiles(owned); e != nil {
			return e
		}
		ownedByManager = true
		if e := profile.record(*proof); e != nil {
			return e
		}
		if m.observer || !m.subscribed {
			return errors.New("worker requires owning subscribed manager")
		}
		otherKind := enrollmentWorkerKind("prepare")
		if kind == otherKind {
			otherKind = "apparmor"
		}
		other := profile.unitPrefix + attempt + "-" + string(otherKind) + ".service"
		for _, name := range []string{unit, other} {
			existing, e := m.readWorker(handoff, name, profile)
			if e != nil {
				return e
			}
			if existing != nil {
				return errors.New("existing current/foreign worker requires reconciliation; no adoption or stop")
			}
		}
		if err = m.noWorkerJobs(handoff, unit, other); err != nil {
			return err
		}
		supported, e := m.workerOOMSupport(handoff)
		if e != nil {
			return e
		}
		if e = stage.validate(); e != nil {
			return e
		}
		if e = validate(); e != nil {
			return e
		}
		proof.PossibleStart = true // before the potentially partially submitted call
		if e = profile.record(*proof); e != nil {
			return e
		}
		var auxiliary []struct {
			Name       string
			Properties []enrollmentUnitProperty
		}
		if e = m.do(handoff, func() error {
			return m.bus.Object(m.owner, enrollmentSystemdPath).CallWithContext(handoff, enrollmentSystemdInterface+".StartTransientUnit", 0, unit, "fail", enrollmentWorkerProperties(profile, bounds, supported), auxiliary).Store(&proof.Job)
		}); e != nil {
			return e
		}
		if e = profile.record(*proof); e != nil {
			return e
		}
		if e = m.waitWorkerJob(handoff, proof.Job, unit); e != nil {
			return e
		}
		state, e := m.readWorker(handoff, unit, profile)
		if e != nil {
			return e
		}
		if e = state.launchGate(0); e != nil {
			return e
		}
		if supported && (state.OOMPolicy == nil || *state.OOMPolicy != "continue") {
			return errors.New("owned worker OOM continue readback missing")
		}
		empty, e := enrollmentWorkerCgroupEmpty(unit, state.Group)
		if e != nil || empty {
			return errors.Join(errors.New("actual waiting worker cgroup is not populated"), e)
		}
		proof.Bound = state
		if e = profile.record(*proof); e != nil {
			return e
		}
		deadline, _ := handoff.Deadline()
		if e = listener.SetDeadline(deadline); e != nil {
			return e
		}
		// Context cancellation closes the actual listener before joining Accept.
		acceptStop, acceptJoined := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(acceptJoined)
			select {
			case <-handoff.Done():
				listener.Close()
			case <-acceptStop:
			}
		}()
		connection, e := listener.AcceptUnix()
		close(acceptStop)
		<-acceptJoined
		if e != nil {
			return e
		}
		defer connection.Close()
		peer, e := enrollmentSocketPeer(connection)
		if e != nil {
			return e
		}
		proof.PeerPID = peer.Pid
		proof.PeerStart, e = m.workerPeer(handoff, peer, state, profile)
		if e != nil {
			return e
		}
		if e = profile.record(*proof); e != nil {
			return e
		}
		if e = stage.validate(); e != nil {
			return e
		}
		if e = validate(); e != nil {
			return e
		}
		if e = writeEnrollmentPacket(handoff, connection, association, owned); e != nil {
			return e
		}
		var stream enrollmentReportState
		body, closed, e := readEnrollmentReportPacket(handoff, connection, peer)
		if e != nil {
			return e
		}
		if e = stream.receive(body, closed, association); e != nil {
			return e
		}
		stored, e := m.readWorker(handoff, unit, profile)
		if e != nil {
			return e
		}
		if e = stored.launchGate(len(owned)); e != nil {
			return e
		}
		if stored.Group != state.Group || !bytes.Equal(stored.Invocation, state.Invocation) || stored.Path != state.Path {
			return errors.New("worker changed before parent gate")
		}
		if supported && (stored.OOMPolicy == nil || *stored.OOMPolicy != "continue") {
			return errors.New("owned worker lost OOM continue before gate")
		}
		if _, e = m.workerPeer(handoff, peer, stored, profile); e != nil {
			return e
		}
		empty, e = enrollmentWorkerCgroupEmpty(unit, stored.Group)
		if e != nil || empty {
			return errors.Join(errors.New("worker no longer physically populated before gate"), e)
		}
		if e = validate(); e != nil {
			return e
		}
		if e = stage.validate(); e != nil {
			return e
		}
		proof.GatePending = true
		if e = profile.record(*proof); e != nil {
			return e
		}
		ready := association
		ready.Ready = true
		if e = writeEnrollmentPacket(handoff, connection, ready, nil); e != nil {
			return e
		}
		if e = stream.acknowledgeGate(); e != nil {
			return e
		}
		proof.GateAcknowledged = true
		if e = profile.record(*proof); e != nil {
			return e
		}
		// Parent claim authority stays local. Drift closes the SAME worker channel,
		// preventing subsequent utility launches while actual PID1 custody persists.
		receiveCtx, cancelReceive := context.WithCancel(ctx)
		defer cancelReceive()
		monitorStop, monitorDone := make(chan struct{}), make(chan error, 1)
		go func() {
			ticker := time.NewTicker(25 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-monitorStop:
					monitorDone <- nil
					return
				case <-receiveCtx.Done():
					monitorDone <- receiveCtx.Err()
					return
				case <-ticker.C:
					if e := validate(); e != nil {
						cancelReceive()
						monitorDone <- e
						return
					}
				}
			}
		}()
		streamErr := func() error {
			for stream != 4 {
				b, c, e := readEnrollmentReportPacket(receiveCtx, connection, peer)
				if e != nil {
					return e
				}
				if e = stream.receive(b, c, association); e != nil {
					return e
				}
			}
			return nil
		}()
		close(monitorStop)
		monitorErr := <-monitorDone
		if streamErr != nil || monitorErr != nil {
			return errors.Join(streamErr, monitorErr)
		}
		proof.StreamComplete = true
		if e = profile.record(*proof); e != nil {
			return e
		}
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			if e = validate(); e != nil {
				return e
			}
			current, e := m.readWorker(ctx, unit, profile)
			if e != nil {
				return e
			}
			empty, e := enrollmentWorkerCgroupEmpty(unit, state.Group)
			if e != nil {
				return e
			}
			terminal, e := enrollmentWorkerTerminal(*state, current, empty)
			if e != nil {
				return e
			}
			if terminal {
				if e = m.noWorkerJobs(ctx, unit, other); e != nil {
					return e
				}
				if e = stage.validate(); e != nil {
					return e
				}
				if e = validate(); e != nil {
					return e
				}
				if e = stage.removeSocket(); e != nil {
					return e
				}
				if e = m.releaseWorkerFiles(); e != nil {
					return e
				}
				proof.Drained = true
				proof.LocalCopiesClosed = true
				return profile.record(*proof)
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return ctx.Err()
			case <-m.retiredCh:
				return errEnrollmentManagerRetired
			}
		}
	})
	if !ownedByManager {
		result = errors.Join(result, enrollmentCloseFiles(owned))
	}
	if result != nil {
		// There is no Stop/Clean/Reset/unload cleanup here. Keep the actual known
		// unit/root/binding for reconciliation; first join this original sender.
		m.interrupt()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		retireErr := m.retire(cleanup)
		if retireErr == nil {
			proof.LocalCopiesClosed = true
		}
		result = errors.Join(errors.New("worker result unknown; preserve actual custody and binding"), result, retireErr, profile.record(*proof))
	}
	return proof, result
}
