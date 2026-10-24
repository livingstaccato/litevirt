package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/litevirt/litevirt/internal/pki"
)

const enrollmentC1FixtureAttempt = "012345abcdef"
const enrollmentC1MainRole = "--enrollment-c1-main-fixture"
const enrollmentC1MainUnit = "litevirt-enrollment-c1-" + enrollmentC1FixtureAttempt + "-main.service"
const enrollmentC1MainDescription = "LiteVirt isolated C1 main " + enrollmentC1FixtureAttempt

func enrollmentC1Root() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	want := filepath.Join(filepath.Dir(executable), "root-unit-fixture")
	if os.Geteuid() != 0 || os.Getenv("LITEVIRT_ENROLLMENT_C1_ROOT") != "1" || os.Getenv("LITEVIRT_ENROLLMENT_C1_UNIT_ROOT") != want {
		return "", errors.New("actual root private unit fixture envelope required")
	}
	real, err := filepath.EvalSymlinks(want)
	if err != nil || real != want {
		return "", errors.New("noncanonical unit fixture root")
	}
	info, err := os.Lstat(want)
	if err != nil {
		return "", err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || owner.Uid != 0 || owner.Gid != 0 {
		return "", errors.New("unit fixture root must be root:root0700")
	}
	return want, nil
}

func enrollmentC1Main() error {
	root, err := enrollmentC1Root()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// This is a genuine C0 strong lifetime registration, not a successful
	// manager snapshot substituted for an actual kernel SH consumer.
	if err := pki.RegisterDaemonHostDomain(ctx, filepath.Join(root, "pki")); err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stop)
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return errors.New("fixture has no actual manager notify socket")
	}
	notify, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return err
	}
	if err := notify.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = notify.Close()
		return err
	}
	_, err = notify.Write([]byte("READY=1"))
	_ = notify.Close()
	if err != nil {
		return err
	}
	fmt.Printf("ACTUAL_FIXTURE_MAIN_ADMITTED pid=%d\n", os.Getpid())
	<-stop
	return nil // registry retains SH until TestMain's actual process exit.
}

// dispatchEnrollmentC1Role handles only the fixed subprocess roles before the
// package TestMain initializes ordinary endpoint tests. Each recognized role exits.
func dispatchEnrollmentC1Role() {
	if len(os.Args) >= 2 && strings.HasPrefix(os.Args[1], "--enrollment-c1-worker-") {
		if err := enrollmentC1WorkerRole(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if len(os.Args) == 2 && os.Args[1] == enrollmentC1MainRole {
		if err := enrollmentC1Main(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

type enrollmentC1Property struct {
	Name  string
	Value dbus.Variant
}
type enrollmentC1Exec struct {
	Path          string
	Args          []string
	IgnoreFailure bool
}
type enrollmentC1ExecObserved struct {
	Path                                                       string
	Args                                                       []string
	IgnoreFailure                                              bool
	StartRealtime, StartMonotonic, ExitRealtime, ExitMonotonic uint64
	PID                                                        uint32
	Code, Status                                               int32
}
type enrollmentC1Unit struct {
	Path                         dbus.ObjectPath
	Description, Active, Group   string
	MainPID, ControlPID, FDStore uint32
	Invocation                   []byte
	ExecPath                     string
	ExecArgs                     []string
}
type enrollmentC1Binding struct {
	Unit, Description, Executable, Root, BusID, ManagerOwner, BootID string
	Phase                                                            string
	StartJob                                                         dbus.ObjectPath
	Invocation                                                       []byte
	Group                                                            string
	MainPID                                                          uint32
}

// This is the exact fixture action boundary; ordinary interruption controls
// exercise it without granting a fabricated manager observation authority.
func enrollmentC1CleanupAssociation(binding enrollmentC1Binding, info *enrollmentC1Unit, action func() error) error {
	id, jobErr := strconv.ParseUint(filepath.Base(string(binding.StartJob)), 10, 32)
	if binding.Phase != "bound" || jobErr != nil || id == 0 || !strings.HasPrefix(string(binding.StartJob), "/org/freedesktop/systemd1/job/") || len(binding.Invocation) != 16 || bytes.Equal(binding.Invocation, make([]byte, 16)) || binding.MainPID == 0 || binding.Group == "" || filepath.Clean(binding.Group) != binding.Group || !strings.HasPrefix(binding.Group, "/") || !strings.HasSuffix(binding.Group, "/"+enrollmentC1MainUnit) {
		return errors.New("fixture start is not bound to an actual accepted job/invocation/cgroup; retain root for reconciliation")
	}
	if info != nil {
		if info.Description != binding.Description || info.ExecPath != binding.Executable || len(info.ExecArgs) != 2 || info.ExecArgs[1] != enrollmentC1MainRole {
			return errors.New("foreign fixture unit preserved")
		}
		if !bytes.Equal(info.Invocation, binding.Invocation) || info.Group != "" && info.Group != binding.Group || info.MainPID != 0 && info.MainPID != binding.MainPID {
			return errors.New("fixture invocation changed; reconciliation required")
		}
	}
	return action()
}

func TestEnrollmentFixtureUnknownStartCannotAuthorizeCleanup(t *testing.T) {
	for _, phase := range []string{"prepared", "possible-start", "accepted-without-binding"} {
		for _, present := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/present=%t", phase, present), func(t *testing.T) {
				root := t.TempDir()
				file, err := os.OpenFile(filepath.Join(root, ".active-domain.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				binding := enrollmentC1Binding{Unit: enrollmentC1MainUnit, Description: enrollmentC1MainDescription, Executable: "/known/private/cli.test", Root: root, Phase: phase}
				if phase == "accepted-without-binding" {
					binding.Phase = "possible-start"
					binding.StartJob = "/org/freedesktop/systemd1/job/42"
				}
				var info *enrollmentC1Unit
				if present {
					info = &enrollmentC1Unit{Description: binding.Description, ExecPath: binding.Executable, ExecArgs: []string{binding.Executable, enrollmentC1MainRole}, Invocation: bytes.Repeat([]byte{1}, 16), Group: "/system.slice/" + enrollmentC1MainUnit, MainPID: 1234, Active: "active"}
				}
				stopCalls, completed := 0, false
				err = enrollmentC1CleanupAssociation(binding, info, func() error {
					stopCalls++
					completed = true
					return os.RemoveAll(root)
				})
				_, statErr := os.Stat(root)
				if err == nil || stopCalls != 0 || completed || statErr != nil {
					t.Fatalf("RED_C1_UNKNOWN_START_CLEANUP: incomplete %s/present=%t authorized action=%d complete=%t rootstat=%v err=%v", phase, present, stopCalls, completed, statErr, err)
				}
			})
		}
	}
}

func TestEnrollmentFixtureInterruptedBindingStaysUncertain(t *testing.T) {
	root := t.TempDir()
	binding := enrollmentC1Binding{Unit: enrollmentC1MainUnit, Description: enrollmentC1MainDescription, Executable: "/known/private/cli.test", Root: root, Phase: "prepared"}
	for _, stage := range []string{"prepared", "possible-start", "accepted-before-bound-save"} {
		binding.Phase = stage
		if stage == "accepted-before-bound-save" {
			binding.Phase = "possible-start"
			binding.StartJob = "/org/freedesktop/systemd1/job/42"
		}
		if err := enrollmentC1Save(root, binding); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(root, "main-binding.json"))
		if err != nil {
			t.Fatal(err)
		}
		var recovered enrollmentC1Binding
		if json.Unmarshal(body, &recovered) != nil {
			t.Fatal("actual binding bytes did not decode")
		}
		for _, present := range []bool{false, true} {
			var info *enrollmentC1Unit
			if present {
				info = &enrollmentC1Unit{Description: binding.Description, ExecPath: binding.Executable, ExecArgs: []string{binding.Executable, enrollmentC1MainRole}, Invocation: bytes.Repeat([]byte{1}, 16), Group: "/system.slice/" + enrollmentC1MainUnit, MainPID: 1234}
			}
			called := false
			if err := enrollmentC1CleanupAssociation(recovered, info, func() error { called = true; return os.RemoveAll(root) }); err == nil || called {
				t.Fatal("interrupted on-disk binding authorized absent/present cleanup", stage, present)
			}
			if after, err := os.ReadFile(filepath.Join(root, "main-binding.json")); err != nil || !bytes.Equal(body, after) {
				t.Fatal("unknown binding or namespace was removed")
			}
		}
	}
	// Actual failure before final bound publication must leave the durable
	// possible-start record, never promote it through later manager snapshots.
	if err := os.WriteFile(filepath.Join(root, ".main-binding.tmp"), []byte("foreign temporary preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	bound := binding
	bound.Phase, bound.Invocation, bound.Group, bound.MainPID = "bound", bytes.Repeat([]byte{1}, 16), "/system.slice/"+enrollmentC1MainUnit, 1234
	if err := enrollmentC1Save(root, bound); err == nil {
		t.Fatal("injected bound publication collision did not fail")
	}
	body, err := os.ReadFile(filepath.Join(root, "main-binding.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recovered enrollmentC1Binding
	if json.Unmarshal(body, &recovered) != nil || recovered.Phase != "possible-start" || len(recovered.Invocation) != 0 || recovered.Group != "" {
		t.Fatal("failed bound save manufactured actual association evidence")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("uncertain namespace was removed", err)
	}
}

func TestEnrollmentFixtureBoundCleanupNeedsCompleteEvidence(t *testing.T) {
	valid := enrollmentC1Binding{Unit: enrollmentC1MainUnit, Description: enrollmentC1MainDescription, Executable: "/known/private/cli.test", Phase: "bound", StartJob: "/org/freedesktop/systemd1/job/42", Invocation: bytes.Repeat([]byte{1}, 16), Group: "/system.slice/" + enrollmentC1MainUnit, MainPID: 1234}
	for _, cut := range []string{"job", "invocation", "zero-invocation", "group", "pid"} {
		for _, present := range []bool{false, true} {
			binding := valid
			switch cut {
			case "job":
				binding.StartJob = ""
			case "invocation":
				binding.Invocation = nil
			case "zero-invocation":
				binding.Invocation = make([]byte, 16)
			case "group":
				binding.Group = ""
			case "pid":
				binding.MainPID = 0
			}
			var info *enrollmentC1Unit
			if present {
				info = &enrollmentC1Unit{Description: valid.Description, ExecPath: valid.Executable, ExecArgs: []string{valid.Executable, enrollmentC1MainRole}, Invocation: valid.Invocation, Group: valid.Group, MainPID: valid.MainPID, Active: "active"}
			}
			called := false
			if err := enrollmentC1CleanupAssociation(binding, info, func() error { called = true; return nil }); err == nil || called {
				t.Fatalf("incomplete bound %s/present=%t authorized cleanup", cut, present)
			}
		}
	}
	for _, present := range []bool{false, true} {
		var info *enrollmentC1Unit
		if present {
			info = &enrollmentC1Unit{Description: valid.Description, ExecPath: valid.Executable, ExecArgs: []string{valid.Executable, enrollmentC1MainRole}, Invocation: valid.Invocation, Group: valid.Group, MainPID: valid.MainPID}
		}
		called := 0
		if err := enrollmentC1CleanupAssociation(valid, info, func() error { called++; return nil }); err != nil || called != 1 {
			t.Fatal("fully bound path cannot reach actual terminal/EX verification", present, err)
		}
	}
	if empty, err := enrollmentC1GroupEmpty(""); err == nil || empty {
		t.Fatal("empty group fabricated a known empty cgroup")
	}
}

func enrollmentC1Save(root string, binding enrollmentC1Binding) error {
	body, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	temporary := filepath.Join(root, ".main-binding.tmp")
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(root, "main-binding.json")); err != nil {
		return err
	}
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func enrollmentC1Read(ctx context.Context, manager *enrollmentManager) (*enrollmentC1Unit, error) {
	var path dbus.ObjectPath
	if err := manager.do(ctx, func() error {
		return manager.bus.Object(manager.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".GetUnit", 0, enrollmentC1MainUnit).Store(&path)
	}); err != nil {
		var remote dbus.Error
		if errors.As(err, &remote) && remote.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return nil, nil
		}
		return nil, err
	}
	var unit, service map[string]dbus.Variant
	for _, query := range []struct {
		name   string
		result *map[string]dbus.Variant
	}{{"org.freedesktop.systemd1.Unit", &unit}, {"org.freedesktop.systemd1.Service", &service}} {
		if err := manager.do(ctx, func() error {
			return manager.bus.Object(manager.owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.GetAll", 0, query.name).Store(query.result)
		}); err != nil {
			return nil, err
		}
	}
	info := &enrollmentC1Unit{Path: path}
	var ok bool
	if info.Description, ok = unit["Description"].Value().(string); !ok {
		return nil, errors.New("fixture description has wrong type")
	}
	if info.Active, ok = unit["ActiveState"].Value().(string); !ok {
		return nil, errors.New("fixture active state has wrong type")
	}
	if info.Invocation, ok = unit["InvocationID"].Value().([]byte); !ok {
		return nil, errors.New("fixture invocation has wrong type")
	}
	if info.Group, ok = service["ControlGroup"].Value().(string); !ok {
		return nil, errors.New("fixture cgroup has wrong type")
	}
	if info.MainPID, ok = service["MainPID"].Value().(uint32); !ok {
		return nil, errors.New("fixture mainPID has wrong type")
	}
	if info.ControlPID, ok = service["ControlPID"].Value().(uint32); !ok {
		return nil, errors.New("fixture controlPID has wrong type")
	}
	if info.FDStore, ok = service["NFileDescriptorStore"].Value().(uint32); !ok {
		return nil, errors.New("fixture FD-store count has wrong type")
	}
	var commands []enrollmentC1ExecObserved
	if err := dbus.Store([]any{service["ExecStart"].Value()}, &commands); err != nil || len(commands) != 1 {
		return nil, errors.New("fixture ExecStart is not the expected single command")
	}
	info.ExecPath, info.ExecArgs = commands[0].Path, commands[0].Args
	return info, nil
}

func enrollmentC1WaitJob(ctx context.Context, manager *enrollmentManager, path dbus.ObjectPath) error {
	id, err := strconv.ParseUint(filepath.Base(string(path)), 10, 32)
	if err != nil || id == 0 || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/job/") {
		return errors.New("invalid actual fixture job")
	}
	for {
		select {
		case event, ok := <-manager.signals:
			if !ok {
				return errors.New("actual fixture observation connection closed")
			}
			if event.Name != enrollmentSystemdInterface+".Reloading" && event.Name != enrollmentSystemdInterface+".JobRemoved" {
				continue // includes the bus's automatically delivered NameAcquired.
			}
			if event.Sender != manager.owner || event.Path != enrollmentSystemdPath {
				return errors.New("fixture event has wrong actual sender/path")
			}
			if event.Name == enrollmentSystemdInterface+".Reloading" {
				return errors.New("fixture manager reload invalidates attempt")
			}
			if event.Name != enrollmentSystemdInterface+".JobRemoved" {
				continue
			}
			if len(event.Body) != 4 {
				return errors.New("invalid actual JobRemoved body")
			}
			gotID, a := event.Body[0].(uint32)
			gotPath, b := event.Body[1].(dbus.ObjectPath)
			unit, c := event.Body[2].(string)
			result, d := event.Body[3].(string)
			if !a || !b || !c || !d {
				return errors.New("invalid actual JobRemoved types")
			}
			if gotPath != path {
				continue
			}
			if gotID != uint32(id) || unit != enrollmentC1MainUnit || result != "done" {
				return fmt.Errorf("actual fixture job %s/%s ended %s", path, unit, result)
			}
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func enrollmentC1GroupEmpty(group string) (bool, error) {
	if group == "" {
		return false, errors.New("empty fixture cgroup is unknown, not proven empty")
	}
	if filepath.Clean(group) != group || !strings.HasSuffix(group, "/"+enrollmentC1MainUnit) || !strings.HasPrefix(group, "/") {
		return false, errors.New("unexpected actual fixture cgroup")
	}
	path := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(group, "/"), "cgroup.events")
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if line == "populated 0" {
			return true, nil
		}
		if line == "populated 1" {
			return false, nil
		}
	}
	return false, errors.New("actual fixture cgroup population unproved")
}

func enrollmentC1Cleanup(root string) (result map[string]any, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	manager, err := openEnrollmentManager(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		err = errors.Join(err, manager.retire(end))
		if err != nil {
			result = nil
		}
	}()
	body, err := os.ReadFile(filepath.Join(root, "main-binding.json"))
	if err != nil {
		return nil, err
	}
	var binding enrollmentC1Binding
	if json.Unmarshal(body, &binding) != nil || binding.Unit != enrollmentC1MainUnit || binding.Description != enrollmentC1MainDescription || binding.Root != root || binding.BusID != manager.busID || binding.ManagerOwner != manager.owner || binding.BootID != manager.bootID {
		return nil, errors.New("fixture prepared association/generation changed")
	}
	info, err := enrollmentC1Read(ctx, manager)
	if err != nil {
		return nil, err
	}
	err = enrollmentC1CleanupAssociation(binding, info, func() error {
		var stopJob dbus.ObjectPath
		if info != nil {
			if err := manager.do(ctx, func() error {
				return manager.bus.Object(manager.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".StopUnit", 0, enrollmentC1MainUnit, "replace").Store(&stopJob)
			}); err != nil {
				return err
			}
			if err := enrollmentC1WaitJob(ctx, manager, stopJob); err != nil {
				return err
			}
			if info.Group != "" {
				binding.Group = info.Group
			}
		}
		for {
			info, err := enrollmentC1Read(ctx, manager)
			if err != nil {
				return err
			}
			empty, err := enrollmentC1GroupEmpty(binding.Group)
			if err != nil {
				return err
			}
			if empty && (info == nil || info.MainPID == 0 && info.ControlPID == 0 && info.FDStore == 0 && (info.Active == "inactive" || info.Active == "failed")) {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
		ex, err := pki.AcquireHostReinitialization(ctx, filepath.Join(root, "pki"))
		if err != nil {
			return err
		}
		ex.Release()
		result = map[string]any{"unit": binding.Unit, "binding_phase": binding.Phase, "start_job": binding.StartJob, "bound_cgroup": binding.Group, "bound_main_pid": binding.MainPID, "invocation": hex.EncodeToString(binding.Invocation), "stop_job": stopJob, "actual_cgroup_empty": true, "actual_lifetime_EX_acquired": true, "main_control_FDstore_zero": true}
		return nil
	})
	return result, err
}

func TestEnrollmentUnitCleanupProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_UNIT_ROOT") == "" {
		t.Skip("separate actual unit cleanup fixture only")
	}
	root, err := enrollmentC1Root()
	if err != nil {
		t.Fatal(err)
	}
	result, err := enrollmentC1Cleanup(root)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(result)
	fmt.Printf("ENROLLMENT_UNIT_CLEANUP_RESULT %s\n", body)
}

func TestEnrollmentUnitPrestateProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_UNIT_ROOT") == "" {
		t.Skip("separate actual unit prestate fixture only")
	}
	if _, err := enrollmentC1Root(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	observer, err := openEnrollmentObserver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := observer.retire(end); err != nil {
			t.Errorf("actual prestate observer retirement: %v", err)
		}
	}()
	info, err := enrollmentC1Read(ctx, observer)
	if err != nil || info != nil {
		t.Fatalf("preexisting private unit preserved: %+v %v", info, err)
	}
	body, _ := json.Marshal(map[string]any{"unit": enrollmentC1MainUnit, "absent": true, "bus_id": observer.busID, "manager_owner": observer.owner, "manager_pid_start": observer.pidStart, "boot_id": observer.bootID})
	fmt.Printf("ENROLLMENT_UNIT_PRESTATE_RESULT %s\n", body)
}

func TestEnrollmentManagerStopsActualLifetimeConsumer(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_UNIT_ROOT") == "" {
		t.Skip("new root unit/job family requires its own first preflight")
	}
	root, err := enrollmentC1Root()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	manager, err := openEnrollmentManager(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manager.mainUnit = enrollmentC1MainUnit // private mapped owner, no runtime path option.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manager.mainExecutable = executable
	manager.mainArguments = []string{executable, enrollmentC1MainRole}
	if info, err := enrollmentC1Read(ctx, manager); err != nil || info != nil {
		t.Fatalf("preexisting fixture unit preserved: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pki"), 0700); err != nil {
		t.Fatal(err)
	}
	binding := enrollmentC1Binding{Unit: enrollmentC1MainUnit, Description: enrollmentC1MainDescription, Executable: executable, Root: root, BusID: manager.busID, ManagerOwner: manager.owner, BootID: manager.bootID, Phase: "prepared"}
	if err := enrollmentC1Save(root, binding); err != nil {
		t.Fatal(err)
	}
	defer func() {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := manager.retire(end); err != nil {
			t.Errorf("original fixture sender retirement: %v", err)
			return
		}
		if _, err := enrollmentC1Cleanup(root); err != nil {
			t.Errorf("actual fixture cleanup: %v", err)
		}
	}()
	properties := []enrollmentC1Property{
		{"Description", dbus.MakeVariant(enrollmentC1MainDescription)}, {"Type", dbus.MakeVariant("notify")}, {"NotifyAccess", dbus.MakeVariant("main")},
		{"ExecStart", dbus.MakeVariant([]enrollmentC1Exec{{executable, []string{executable, enrollmentC1MainRole}, false}})},
		{"Environment", dbus.MakeVariant([]string{"LITEVIRT_ENROLLMENT_C1_ROOT=1", "LITEVIRT_ENROLLMENT_C1_UNIT_ROOT=" + root, "PATH=/usr/bin:/bin"})},
		{"Restart", dbus.MakeVariant("no")}, {"KillMode", dbus.MakeVariant("process")}, {"Delegate", dbus.MakeVariant(false)},
		{"TimeoutStartUSec", dbus.MakeVariant(uint64(20 * time.Second / time.Microsecond))}, {"TimeoutStopUSec", dbus.MakeVariant(uint64(5 * time.Second / time.Microsecond))},
	}
	var job dbus.ObjectPath
	binding.Phase = "possible-start"
	if err := enrollmentC1Save(root, binding); err != nil {
		t.Fatal(err)
	}
	if err := manager.do(ctx, func() error {
		return manager.bus.Object(manager.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".StartTransientUnit", 0, enrollmentC1MainUnit, "fail", properties, []struct {
			Name       string
			Properties []enrollmentC1Property
		}{}).Store(&job)
	}); err != nil {
		t.Fatal(err)
	}
	binding.StartJob = job
	if err := enrollmentC1Save(root, binding); err != nil {
		t.Fatal(err)
	}
	if err := enrollmentC1WaitJob(ctx, manager, job); err != nil {
		t.Fatal(err)
	}
	info, err := enrollmentC1Read(ctx, manager)
	if err != nil || info == nil || info.Active != "active" || info.MainPID == 0 || info.ControlPID != 0 || len(info.Invocation) != 16 {
		t.Fatalf("actual lifetime consumer did not become active: %+v %v", info, err)
	}
	binding.Invocation, binding.Group, binding.MainPID = info.Invocation, info.Group, info.MainPID
	binding.Phase = "bound"
	if err := enrollmentC1Save(root, binding); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual_main_pid=%d invocation=%x cgroup=%s accepted_start_job=%s", info.MainPID, info.Invocation, info.Group, job)
	// Keep this disposable transient definition loaded across the real stop.
	// The reference belongs to this bus connection and is dropped on retirement.
	if err := manager.do(ctx, func() error {
		return manager.bus.Object(manager.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".RefUnit", 0, enrollmentC1MainUnit).Err
	}); err != nil {
		t.Fatal("retain exact private unit definition", err)
	}
	blocked, finish := context.WithTimeout(ctx, 150*time.Millisecond)
	lease, err := pki.AcquireHostReinitialization(blocked, filepath.Join(root, "pki"))
	finish()
	if err == nil {
		lease.Release()
		t.Fatal("actual MainPID failed to hold genuine lifetime SH")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lifetime contention was not actual deadline exclusion", err)
	}
	if err := manager.quiesceMain(ctx); err != nil {
		t.Fatalf("RED_ENROLLMENT_CONTROLLED_MAIN: actual controlled stop refused: %v", err)
	}
	if manager.mainStopped == nil || manager.mainStopped.Before.MainPID != binding.MainPID || !bytes.Equal(manager.mainStopped.Before.Invocation, binding.Invocation) || manager.mainStopped.Before.Group != binding.Group || manager.mainStopped.Job == "" {
		t.Fatal("controlled stop omitted the actual bound job/incarnation proof")
	}
	t.Logf("actual_controlled_stop_job=%s original_pid=%d invocation=%x cgroup=%s", manager.mainStopped.Job, binding.MainPID, binding.Invocation, binding.Group)
	firstStop := manager.mainStopped.Job
	inactive, err := enrollmentC1Read(ctx, manager)
	if err != nil || inactive == nil || inactive.MainPID != 0 || inactive.ControlPID != 0 || inactive.FDStore != 0 || inactive.Active != "inactive" {
		t.Fatalf("known inactive fixture did not retain its definition: %+v %v", inactive, err)
	}
	if err := manager.quiesceMain(ctx); err != nil {
		t.Fatal("ordered stop of known inactive main", err)
	}
	if manager.mainStopped == nil || manager.mainStopped.Job == "" || manager.mainStopped.Job == firstStop || manager.mainStopped.Before.MainPID != binding.MainPID || manager.mainStopped.Before.Group != binding.Group {
		t.Fatal("known inactive stop lost actual prior incarnation or omitted new ordered job")
	}
	t.Logf("actual_known_inactive_stop_job=%s prior_stop_job=%s retained_pid=%d retained_cgroup=%s", manager.mainStopped.Job, firstStop, binding.MainPID, binding.Group)
	info, err = enrollmentC1Read(ctx, manager)
	if err != nil || info != nil && (info.MainPID != 0 || info.ControlPID != 0 || info.Active != "inactive" || info.FDStore != 0) {
		t.Fatalf("controlled stop did not establish actual terminal state: %+v %v", info, err)
	}
	if empty, err := enrollmentC1GroupEmpty(binding.Group); err != nil || !empty {
		t.Fatal("controlled stop left actual cgroup population", err)
	}
	lease, err = pki.AcquireHostReinitialization(ctx, filepath.Join(root, "pki"))
	if err != nil {
		t.Fatal("actual lifetime consumer outlived controlled stop", err)
	}
	defer lease.Release()
	f, err := os.OpenFile(filepath.Join(root, "protected-after-stop"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("actual stop/job/control/cgroup/EX preceded effect\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("actual_lifetime_EX_and_durable_protected_effect_after_controlled_stop")
	// The daemon needs its real SH: release EX before submitting controlled start.
	lease.Release()
	binding.Phase, binding.StartJob = "possible-start", ""
	if err := enrollmentC1Save(root, binding); err != nil {
		t.Fatal(err)
	}
	if err := manager.startMain(ctx); err != nil {
		t.Fatal("controlled restart", err)
	}
	proof := manager.mainStarted
	if proof == nil || proof.After == nil || proof.Job == "" {
		t.Fatal("controlled restart omitted actual job/incarnation proof")
	}
	info, err = enrollmentC1Read(ctx, manager)
	if err != nil || info == nil || info.MainPID == 0 || info.MainPID != proof.After.MainPID || !bytes.Equal(info.Invocation, proof.After.Invocation) || bytes.Equal(info.Invocation, binding.Invocation) || info.Group != proof.After.Group {
		t.Fatalf("controlled restart did not bind fresh lifetime consumer: %+v %v", info, err)
	}
	binding.Phase, binding.StartJob, binding.Invocation, binding.Group, binding.MainPID = "bound", proof.Job, info.Invocation, info.Group, info.MainPID
	if err := enrollmentC1Save(root, binding); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual_controlled_restart_job=%s restarted_pid=%d invocation=%x cgroup=%s", proof.Job, binding.MainPID, binding.Invocation, binding.Group)
	blocked, finish = context.WithTimeout(ctx, 150*time.Millisecond)
	second, err := pki.AcquireHostReinitialization(blocked, filepath.Join(root, "pki"))
	finish()
	if err == nil {
		second.Release()
		t.Fatal("restarted consumer did not retain actual lifetime SH")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("restart contention not actual deadline exclusion", err)
	}
	if err := manager.quiesceMain(ctx); err != nil {
		t.Fatal("controlled final stop", err)
	}
	if manager.mainStopped == nil || manager.mainStopped.Before.MainPID != binding.MainPID {
		t.Fatal("final stop omitted rebound main proof")
	}
	t.Logf("actual_controlled_final_stop_job=%s restarted_pid=%d", manager.mainStopped.Job, binding.MainPID)
	second, err = pki.AcquireHostReinitialization(ctx, filepath.Join(root, "pki"))
	if err != nil {
		t.Fatal("controlled final stop retained lifetime SH", err)
	}
	second.Release()
}

// This separate fixed fixture path NEVER submits Start/StartTransientUnit. It
// must not be used to clean a prepared/possible-start main-binding record.
type enrollmentC1AbsenceProof struct {
	Unit, Root, Executable, BusID, ManagerOwner, BootID string
	ChildPID                                            int
	ChildStart                                          string
	ChildWait                                           int
	ResponseSequence                                    dbus.Sequence
}

func enrollmentC1SaveAbsence(root string, proof enrollmentC1AbsenceProof) error {
	body, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	temp := filepath.Join(root, ".absence-proof.tmp")
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(temp, filepath.Join(root, "absence-proof.json")); err != nil {
		return err
	}
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func TestEnrollmentManagerOrdersActualAbsentMain(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_UNIT_ROOT") == "" {
		t.Skip("absence root family needs its own first preflight")
	}
	root, err := enrollmentC1Root()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	manager, err := openEnrollmentManager(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := manager.retire(end); err != nil {
			t.Errorf("actual absent-main sender retirement: %v", err)
		}
	}()
	manager.mainUnit = enrollmentC1MainUnit
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manager.mainExecutable, manager.mainArguments = executable, []string{executable, enrollmentC1MainRole}
	if info, err := enrollmentC1Read(ctx, manager); err != nil || info != nil {
		t.Fatalf("preexisting main preserved: %+v %v", info, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "main-binding.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unknown prepared/bound fixture record must be retained", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pki"), 0700); err != nil {
		t.Fatal(err)
	}
	// The actual socket stays inside this owned root. A retained directory FD
	// supplies short Linux pathname aliases, avoiding sockaddr_un's108-byte cap.
	notifyRoot, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer notifyRoot.Close()
	notifyBind := fmt.Sprintf("/proc/self/fd/%d/independent-sh.sock", notifyRoot.Fd())
	notifyPath := fmt.Sprintf("/proc/%d/fd/%d/independent-sh.sock", os.Getpid(), notifyRoot.Fd())
	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyBind, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer notify.Close()
	child := exec.Command(executable, enrollmentC1MainRole)
	child.Env = []string{"PATH=/usr/bin:/bin", "LITEVIRT_ENROLLMENT_C1_ROOT=1", "LITEVIRT_ENROLLMENT_C1_UNIT_ROOT=" + root, "NOTIFY_SOCKET=" + notifyPath}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- child.Wait() }()
	joined := false
	defer func() {
		if joined {
			return
		}
		_ = child.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-waited:
			joined = true
			t.Logf("actual_independent_SH_cleanup_pid=%d Wait=%v", child.Process.Pid, err)
		case <-time.After(5 * time.Second):
			_ = child.Process.Kill()
			err := <-waited
			joined = true
			t.Errorf("forced independent SH cleanup pid=%d Wait=%v", child.Process.Pid, err)
		}
	}()
	start, err := enrollmentProcessStart(uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := notify.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 128)
	n, _, err := notify.ReadFromUnix(data)
	if err != nil || string(data[:n]) != "READY=1" {
		t.Fatal("actual independent SH consumer never ready", err)
	}
	t.Logf("actual_independent_SH_pid=%d process_start=%s no_main_unit_started", child.Process.Pid, start)
	if err := manager.quiesceMain(ctx); err != nil {
		t.Fatal("actual ordered absent-main stop", err)
	}
	proof := manager.mainStopped
	if proof == nil || proof.Absence == nil || proof.Job != "" || proof.Before.Group != "" || proof.Before.MainPID != 0 {
		t.Fatal("manager absence invented a job/incarnation/group")
	}
	if err := manager.orderedMainAbsence(proof.Absence); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual_ordered_StopUnit_NoSuchUnit unit=%s response_sequence=%d no_pending_main_job=true", manager.mainUnit, proof.Absence.ResponseSequence)
	blocked, finish := context.WithTimeout(ctx, 150*time.Millisecond)
	lease, err := pki.AcquireHostReinitialization(blocked, filepath.Join(root, "pki"))
	finish()
	if err == nil {
		lease.Release()
		t.Fatal("NoSuchUnit incorrectly bypassed independent genuine SH")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("independent SH did not provide actual EX exclusion", err)
	}
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waited:
		joined = true
		if err != nil {
			t.Fatal("original independent SH child Wait", err)
		}
	case <-ctx.Done():
		t.Fatal("original independent SH child did not terminate", ctx.Err())
	}
	t.Logf("actual_independent_SH_Wait0 pid=%d", child.Process.Pid)
	lease, err = pki.AcquireHostReinitialization(ctx, filepath.Join(root, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	f, err := os.OpenFile(filepath.Join(root, "protected-after-absence"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write([]byte("actual ordered NoSuchUnit and independent SH Wait/EX preceded this effect\n"))
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		t.Fatal(err)
	}
	receipt := enrollmentC1AbsenceProof{Unit: manager.mainUnit, Root: root, Executable: executable, BusID: manager.busID, ManagerOwner: manager.owner, BootID: manager.bootID, ChildPID: child.Process.Pid, ChildStart: start, ChildWait: 0, ResponseSequence: proof.Absence.ResponseSequence}
	if err := enrollmentC1SaveAbsence(root, receipt); err != nil {
		t.Fatal(err)
	}
	t.Log("actual_absence_EX_durable_effect_receipt_after_original_SH_Wait")
}

func TestEnrollmentUnitAbsenceCleanupProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_UNIT_ROOT") == "" {
		t.Skip("absence cleanup needs exact root preflight")
	}
	root, err := enrollmentC1Root()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "main-binding.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("prepared/unknown main record cannot use absence-only cleanup", err)
	}
	body, err := os.ReadFile(filepath.Join(root, "absence-proof.json"))
	if err != nil {
		t.Fatal("no completed absence-only source/Wait receipt; preserve root", err)
	}
	var proof enrollmentC1AbsenceProof
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &proof); err != nil || proof.Unit != enrollmentC1MainUnit || proof.Root != root || proof.Executable != executable || proof.ChildPID <= 0 || proof.ChildStart == "" || proof.ChildWait != 0 || proof.ResponseSequence == dbus.NoSequence {
		t.Fatal("incomplete absence-only source/Wait receipt", err)
	}
	if current, err := enrollmentProcessStart(uint32(proof.ChildPID)); err == nil && current == proof.ChildStart {
		t.Fatal("original SH child still present; preserve root")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original SH process identity unknown", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	manager, err := openEnrollmentManager(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := manager.retire(end); err != nil {
			t.Errorf("fresh actual absence cleanup retirement: %v", err)
		}
	}()
	manager.mainUnit = enrollmentC1MainUnit
	if proof.BusID != manager.busID || proof.ManagerOwner != manager.owner || proof.BootID != manager.bootID {
		t.Fatal("absence-only bus/manager generation changed; preserve root")
	}
	if err := manager.quiesceMain(ctx); err != nil {
		t.Fatal("fresh ordered absent-main cleanup barrier", err)
	}
	if manager.mainStopped == nil || manager.mainStopped.Absence == nil {
		t.Fatal("fresh cleanup did not obtain actual ordered NoSuchUnit")
	}
	lease, err := pki.AcquireHostReinitialization(ctx, filepath.Join(root, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	result := map[string]any{"unit": enrollmentC1MainUnit, "source": "absence-only-no-start", "no_main_binding_record": true, "original_SH_pid": proof.ChildPID, "original_SH_start": proof.ChildStart, "original_SH_Wait": proof.ChildWait, "ordered_StopUnit_NoSuchUnit": true, "response_sequence": manager.mainStopped.Absence.ResponseSequence, "no_pending_main_job": true, "actual_lifetime_EX_acquired": true, "same_bus_manager_generation": true}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ENROLLMENT_UNIT_ABSENCE_CLEANUP_RESULT " + string(data))
}

const enrollmentC1WorkerPrefix = "litevirt-enrollment-c1-"
const enrollmentC1LauncherRole = "--enrollment-c1-worker-launcher"
const enrollmentC1WaitingRole = "--enrollment-c1-worker-waiting"
const enrollmentC1UtilityRole = "--enrollment-c1-worker-utility"
const enrollmentC1LeafRole = "--enrollment-c1-worker-leaf"

// These fixed TestMain roles exist only in the immutable test binary. They
// cannot select an executable, path, script or production command.
func enrollmentC1WorkerRole() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	root := filepath.Join(filepath.Dir(executable), "root-unit-fixture")
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || stat.Uid != 0 || stat.Gid != 0 {
		return errors.New("fixed root worker fixture envelope missing")
	}
	os.Setenv("LITEVIRT_ENROLLMENT_C1_ROOT", "1")
	os.Setenv("LITEVIRT_ENROLLMENT_C1_UNIT_ROOT", root)
	profile, err := enrollmentC1WorkerProfile()
	if err != nil {
		return err
	}
	switch os.Args[1] {
	case enrollmentC1LauncherRole:
		if len(os.Args) != 2 {
			return errors.New("extra launcher argument")
		}
		return runEnrollmentControl(context.Background(), "launcher", profile)
	case enrollmentC1WaitingRole:
		if len(os.Args) != 2 {
			return errors.New("extra worker argument")
		}
		return runEnrollmentControl(context.Background(), "worker", profile)
	case enrollmentC1UtilityRole:
		if len(os.Args) < 3 {
			return errors.New("fixed utility name missing")
		}
		name := os.Args[2]
		if name != "apt-get" && name != "modprobe" && name != "apparmor_parser" {
			return errors.New("unsupported inert fixture utility")
		}
		if err = enrollmentC1WriteUtilityEvidence(root, name, os.Args[3:]); err != nil {
			return err
		}
		if os.Getenv("LITEVIRT_C1_WORKER_CUT") == "descendant" && name == "apparmor_parser" {
			child := exec.Command(executable, enrollmentC1LeafRole)
			child.Dir = root
			child.Env = os.Environ()
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
			if err = child.Start(); err != nil {
				return err
			}
			// The positive path owns this exact utility child Wait. The death cut
			// deliberately kills only coordinator/utility parent; PID1 reaps them.
			err = child.Wait()
			fmt.Fprintf(os.Stderr, "C1 fixture leaf pid=%d originalWait=%v\n", child.Process.Pid, err)
			return err
		}
		return nil
	case enrollmentC1LeafRole:
		if len(os.Args) != 2 || os.Getenv("LITEVIRT_C1_WORKER_CUT") != "descendant" {
			return errors.New("fixed descendant cut required")
		}
		// Explicitly close any lock-inode aliases, then prove the capable leaf has
		// none. The selected production runner already strips/uses CLOEXEC.
		for _, path := range []string{profile.claimPath, filepath.Join(profile.pkiDir, ".active-domain.lock")} {
			canonical, err := os.Stat(path)
			if err != nil {
				return err
			}
			entries, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				return err
			}
			for _, entry := range entries {
				fd, e := strconv.Atoi(entry.Name())
				if e != nil || fd < 3 {
					continue
				}
				current, e := os.Stat("/proc/self/fd/" + entry.Name())
				if e == nil && os.SameFile(canonical, current) {
					if e = unix.Close(fd); e != nil {
						return e
					}
				}
			}
		}
		pid := uint32(os.Getpid())
		start, err := enrollmentProcessStart(pid)
		if err != nil {
			return err
		}
		body, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			return err
		}
		if err = enrollmentC1WorkerSave(root, "leaf-ready.json", map[string]any{"pid": pid, "start": start, "parent": os.Getppid(), "cgroup": string(body), "capability_descriptors_closed": true}); err != nil {
			return err
		}
		deadline := time.Now().Add(40 * time.Second)
		for {
			if _, e := os.Lstat(filepath.Join(root, "leaf-release")); e == nil {
				break
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
			if time.Now().After(deadline) {
				return errors.New("leaf release absent; preserve failed custody evidence")
			}
			time.Sleep(10 * time.Millisecond)
		}
		return enrollmentC1WorkerSave(root, "leaf-effect.json", map[string]any{"pid": pid, "start": start, "synced": true})
	}
	return errors.New("unsupported fixed root worker role")
}
func enrollmentC1WorkerProfile() (enrollmentWorkerProfile, error) {
	root, err := enrollmentC1Root()
	if err != nil {
		return enrollmentWorkerProfile{}, err
	}
	image, err := os.Executable()
	if err != nil {
		return enrollmentWorkerProfile{}, err
	}
	profile := defaultEnrollmentWorkerProfile(root)
	profile.image = image
	profile.parentImage = image
	profile.unitPrefix = enrollmentC1WorkerPrefix
	profile.claimPath = filepath.Join(root, "claim")
	profile.markerPath = filepath.Join(root, "marker")
	profile.pkiDir = filepath.Join(root, "pki")
	profile.launcherArgs = []string{image, enrollmentC1LauncherRole}
	profile.workerArgs = []string{image, enrollmentC1WaitingRole}
	profile.utilities.resolve = func(name string) (string, []string, error) {
		if name == "apt-get" || name == "modprobe" || name == "apparmor_parser" {
			return image, []string{enrollmentC1UtilityRole, name}, nil
		}
		return "", nil, os.ErrNotExist
	}
	return profile, nil
}
func enrollmentC1WorkerSave(root, name string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := filepath.Join(root, "."+name+".tmp")
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(append(body, '\n'))
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(temporary, filepath.Join(root, name)); err != nil {
		return err
	}
	return syncEnrollmentDirectory(root)
}
func enrollmentC1WorkerBinding(root string) (enrollmentWorkerProof, error) {
	var proof enrollmentWorkerProof
	body, err := os.ReadFile(filepath.Join(root, "worker-binding.json"))
	if err != nil {
		return proof, err
	}
	if err = json.Unmarshal(body, &proof); err != nil {
		return proof, err
	}
	return proof, nil
}
func enrollmentC1WorkerProofBound(proof enrollmentWorkerProof, manager *enrollmentManager, profile enrollmentWorkerProfile) error {
	if !proof.PossibleStart || proof.Bound == nil || proof.Stage != profile.stage || proof.BusID != manager.busID || proof.ManagerOwner != manager.owner || proof.ManagerPIDStart != manager.pidStart || proof.BootID != manager.bootID {
		return errors.New("worker binding incomplete or generation changed; preserve root/custody")
	}
	if _, err := enrollmentJobID(proof.Job); err != nil {
		return err
	}
	association, err := enrollmentWorkerAssociation(proof.Association.Unit, profile.unitPrefix)
	if err != nil || association.Attempt != enrollmentC1FixtureAttempt || proof.Bound.Unit != association.Unit {
		return errors.New("foreign worker association")
	}
	if proof.Bound.Executable != profile.image || !equalEnrollmentArguments(proof.Bound.Arguments, profile.launcherArgs) || !proof.Bound.Path.IsValid() || !strings.HasPrefix(string(proof.Bound.Path), "/org/freedesktop/systemd1/unit/") {
		return errors.New("worker bound source/object invalid")
	}
	if len(proof.Bound.Invocation) != 16 || bytes.Equal(proof.Bound.Invocation, make([]byte, 16)) {
		return errors.New("unknown worker invocation")
	}
	if err = enrollmentMainGroup(proof.Bound.Unit, proof.Bound.Group); err != nil {
		return err
	}
	info, err := os.Lstat(profile.stage)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != proof.StageDevice || stat.Ino != proof.StageInode {
		return errors.New("worker staging generation changed")
	}
	return nil
}
func enrollmentC1WorkerPhysicalRelease(ctx context.Context, manager *enrollmentManager, profile enrollmentWorkerProfile, proof enrollmentWorkerProof) error {
	if err := enrollmentC1WorkerProofBound(proof, manager, profile); err != nil {
		return err
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, err := manager.readWorker(ctx, proof.Association.Unit, profile)
		if err != nil {
			return err
		}
		empty, err := enrollmentWorkerCgroupEmpty(proof.Association.Unit, proof.Bound.Group)
		if err != nil {
			return err
		}
		done, err := enrollmentWorkerTerminal(*proof.Bound, current, empty)
		if err != nil {
			return err
		}
		if done {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := manager.noWorkerJobs(ctx, proof.Association.Unit); err != nil {
		return err
	}
	claim, err := os.OpenFile(profile.claimPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = unix.Flock(int(claim.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	err = errors.Join(err, claim.Close())
	if err != nil {
		return errors.Join(errors.New("actual claim still held"), err)
	}
	lease, err := pki.AcquireHostDomain(ctx, profile.pkiDir)
	if err != nil {
		return err
	}
	lease.Release()
	stage, err := openEnrollmentWorkerStage(profile.stage, 0)
	if err != nil {
		return err
	}
	defer stage.close()
	socket, err := os.Lstat(stage.address())
	if err == nil {
		stat, ok := socket.Sys().(*syscall.Stat_t)
		if !ok || socket.Mode()&os.ModeSocket == 0 || uint64(stat.Dev) != proof.SocketDevice || stat.Ino != proof.SocketInode {
			return errors.New("foreign socket replacement preserved")
		}
		stage.socket = socket
		return stage.removeSocket()
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func TestEnrollmentWorkerUnitPrestateProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_ROOT") != "1" {
		t.Skip("root worker prestate only")
	}
	profile, err := enrollmentC1WorkerProfile()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	manager, err := openEnrollmentObserver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.retire(ctx)
	var names []string
	for _, kind := range []string{"prepare", "apparmor"} {
		name := profile.unitPrefix + enrollmentC1FixtureAttempt + "-" + kind + ".service"
		state, e := manager.readWorker(ctx, name, profile)
		if e != nil || state != nil {
			t.Fatal("fixture worker must be absent", name, state, e)
		}
		names = append(names, name)
	}
	if err = manager.noWorkerJobs(ctx, names...); err != nil {
		t.Fatal(err)
	}
	supported, err := manager.workerOOMSupport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"absent": true, "units": names, "oom_property_present": supported, "bus_id": manager.busID, "manager_owner": manager.owner, "manager_pid_start": manager.pidStart, "boot_id": manager.bootID})
	fmt.Println("ENROLLMENT_WORKER_PRESTATE_RESULT " + string(body))
}
func TestEnrollmentManagerRunsActualWorker(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_ROOT") != "1" {
		t.Skip("separate actual worker/FD-store fixture only")
	}
	profile, err := enrollmentC1WorkerProfile()
	if err != nil {
		t.Fatal(err)
	}
	root := profile.stage
	cut := os.Getenv("LITEVIRT_C1_WORKER_CUT")
	kind := enrollmentWorkerKind("prepare")
	if cut == "descendant" {
		kind = "apparmor"
	} else if cut != "positive" {
		t.Fatal("exact first worker cut required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	claim, err := os.OpenFile(profile.claimPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(int(claim.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(profile.pkiDir, 0700); err != nil {
		t.Fatal(err)
	}
	capabilities := []*os.File{claim}
	var lease *pki.HostDomainLease
	var borrowed *os.File
	if kind == "apparmor" {
		lease, err = pki.AcquireHostReinitialization(ctx, profile.pkiDir)
		if err != nil {
			t.Fatal(err)
		}
		borrowed, err = lease.BorrowForEnrollmentWorker()
		if err != nil {
			t.Fatal(err)
		}
		capabilities = append(capabilities, borrowed)
	}
	// Callback is fixture evidence for the existing parent claim receipt owner;
	// it cannot grant adoption/cleanup authority to a prepared/possible-send state.
	var saved os.FileInfo
	profile.record = func(proof enrollmentWorkerProof) error {
		path := filepath.Join(root, "worker-binding.json")
		info, e := os.Lstat(path)
		if saved == nil {
			if !errors.Is(e, os.ErrNotExist) {
				return errors.New("foreign worker evidence preserved")
			}
		} else if e != nil || !os.SameFile(saved, info) {
			return errors.New("worker evidence inode replaced")
		}

		if proof.GatePending && !proof.GateAcknowledged {
			time.Sleep(100 * time.Millisecond) // fixture-only withheld-ACK observation
			for _, name := range []string{"utility-apt-get.json", "utility-modprobe.json", "utility-apparmor_parser.json", "leaf-ready.json"} {
				if _, e := os.Lstat(filepath.Join(root, name)); !errors.Is(e, os.ErrNotExist) {
					return errors.Join(errors.New("inert utility effect appeared BEFORE parent ACK"), e)
				}
			}
		}
		if e = enrollmentC1WorkerSave(root, "worker-binding.json", proof); e != nil {
			return e
		}
		saved, e = os.Lstat(path)
		return e
	}
	validate := func() error {
		if e := validateEnrollmentCapability(claim, profile.claimPath, 0); e != nil {
			return e
		}
		for _, path := range []string{profile.markerPath, filepath.Join(root, "settle")} {
			if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				return errors.Join(errors.New("exact marker absence/settle changed"), e)
			}
		}
		return nil
	}
	manager, err := openEnrollmentManager(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := openEnrollmentObserver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.retire(ctx)
	type outcome struct {
		proof *enrollmentWorkerProof
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		proof, e := manager.runWorker(ctx, profile, enrollmentC1FixtureAttempt, kind, capabilities, validate)
		done <- outcome{proof, e}
	}()
	var result outcome
	var positiveUtilities []enrollmentC1UtilityEvidence
	if cut == "positive" {
		result = <-done
		if result.err != nil {
			t.Fatal("actual worker failed", result.err)
		}
		if result.proof == nil || !result.proof.StreamComplete || !result.proof.Drained || !result.proof.LocalCopiesClosed {
			t.Fatal("stable worker gates incomplete")
		}
		if !result.proof.GatePending || !result.proof.GateAcknowledged {
			t.Fatal("actual parent ACK evidence missing")
		}
		positiveUtilities, err = enrollmentC1RequirePositiveUtilities(root, uint32(result.proof.PeerPID), result.proof.Bound.Group, profile.image)
		if err != nil || len(positiveUtilities) != 2 {
			t.Fatal("required post-ACK inert utility sequence/effects missing", err)
		}
	} else {
		var leaf struct {
			PID    uint32 `json:"pid"`
			Start  string `json:"start"`
			Parent uint32 `json:"parent"`
			Cgroup string `json:"cgroup"`
			Closed bool   `json:"capability_descriptors_closed"`
		}
		for {
			body, e := os.ReadFile(filepath.Join(root, "leaf-ready.json"))
			if e == nil {
				if json.Unmarshal(body, &leaf) != nil {
					t.Fatal("malformed leaf evidence")
				}
				break
			}
			select {
			case result = <-done:
				t.Fatal("worker ended before capable leaf", result.err)
			case <-time.After(10 * time.Millisecond):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		proof, e := enrollmentC1WorkerBinding(root)
		if e != nil {
			t.Fatal(e)
		}
		if e = enrollmentC1WorkerProofBound(proof, observer, profile); e != nil {
			t.Fatal(e)
		}
		state, e := observer.readWorker(ctx, proof.Association.Unit, profile)
		if e != nil {
			t.Fatal(e)
		}
		if e = state.launchGate(2); e != nil {
			t.Fatal(e)
		}
		if !leaf.Closed || !enrollmentProcessGroup([]byte(leaf.Cgroup), state.Group) {
			t.Fatal("leaf did not close descriptors or wrong cgroup")
		}
		var utility struct {
			PID    uint32 `json:"pid"`
			Start  string `json:"start"`
			Parent uint32 `json:"parent"`
		}
		body, e := os.ReadFile(filepath.Join(root, "utility-apparmor_parser.json"))
		if e != nil || json.Unmarshal(body, &utility) != nil {
			t.Fatal(e)
		}
		if leaf.Parent != utility.PID || utility.Parent != uint32(proof.PeerPID) {
			t.Fatal("unknown descendant chain")
		}
		for _, identity := range []struct {
			pid   uint32
			start string
		}{{leaf.PID, leaf.Start}, {utility.PID, utility.Start}, {uint32(proof.PeerPID), proof.PeerStart}} {
			current, e := enrollmentProcessStart(identity.pid)
			if e != nil || current != identity.start {
				t.Fatal("actual fixture process incarnation changed", e)
			}
			if e = enrollmentProcessImage(identity.pid, profile.image, nil); e != nil {
				t.Fatal(e)
			}
			var path dbus.ObjectPath
			e = observer.do(ctx, func() error {
				return observer.bus.Object(observer.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".GetUnitByPID", 0, identity.pid).Store(&path)
			})
			if e != nil || path != state.Path {
				t.Fatal("fixture descendant outside actual unit", e)
			}
		}
		if e = unix.Kill(int(proof.PeerPID), unix.SIGKILL); e != nil {
			t.Fatal(e)
		}
		if e = unix.Kill(int(utility.PID), unix.SIGKILL); e != nil {
			t.Fatal(e)
		}
		result = <-done
		if result.err == nil || result.proof == nil || result.proof.StreamComplete || result.proof.Drained {
			t.Fatal("death/missing completion fabricated success")
		}
		select {
		case <-manager.closed:
		default:
			t.Fatal("local sender retirement incomplete; preserve all original refs")
		}
		// Close only caller-owned original copies after actual sender join. From
		// here, this capable leaf has NO lock FD; PID1 must independently retain both.
		if e = borrowed.Close(); e != nil {
			t.Fatal(e)
		}
		borrowed = nil
		lease.Release()
		lease = nil
		if e = claim.Close(); e != nil {
			t.Fatal(e)
		}
		claim = nil
		for _, lock := range []struct {
			path string
			mode int
		}{{profile.claimPath, unix.LOCK_EX}, {filepath.Join(profile.pkiDir, ".active-domain.lock"), unix.LOCK_SH}} {
			f, e := os.OpenFile(lock.path, os.O_RDWR, 0)
			if e != nil {
				t.Fatal(e)
			}
			e = unix.Flock(int(f.Fd()), lock.mode|unix.LOCK_NB)
			f.Close()
			if !enrollmentC1FlockContention(e) {
				t.Fatal("PID1 custody probe lacks actual nonblocking contention", lock.path, e)
			}
		}
		empty, e := enrollmentWorkerCgroupEmpty(state.Unit, state.Group)
		if e != nil || empty {
			t.Fatal("capable descendant unexpectedly absent", e)
		}
		if _, e = os.Lstat(filepath.Join(root, "leaf-effect.json")); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("leaf effect occurred before release")
		}
		if e = enrollmentC1WorkerSave(root, "leaf-release", map[string]bool{"release": true}); e != nil {
			t.Fatal(e)
		}
		t.Logf("actual worker death pid=%d utility=%d descriptor-free leaf=%d retained_store=2 cgroup=%s", proof.PeerPID, utility.PID, leaf.PID, state.Group)
	}
	if claim != nil {
		if err = claim.Close(); err != nil {
			t.Fatal(err)
		}
		claim = nil
	}
	if borrowed != nil {
		borrowed.Close()
		borrowed = nil
	}
	if lease != nil {
		lease.Release()
		lease = nil
	}
	if err = manager.retire(ctx); err != nil {
		t.Fatal(err)
	}
	if result.proof == nil {
		t.Fatal("missing known original worker proof")
	}
	if err = enrollmentC1WorkerPhysicalRelease(ctx, observer, profile, *result.proof); err != nil {
		t.Fatal(err)
	}
	if cut == "descendant" {
		if _, err = os.Stat(filepath.Join(root, "leaf-effect.json")); err != nil {
			t.Fatal("real capable leaf effect missing", err)
		}
	}
	if err = enrollmentC1WorkerSave(root, "worker-result.json", map[string]any{"cut": cut, "unit": result.proof.Association.Unit, "job": result.proof.Job, "invocation": hex.EncodeToString(result.proof.Bound.Invocation), "cgroup": result.proof.Bound.Group, "stable_success": result.err == nil, "positive_utilities": positiveUtilities, "positive_effects_verified": cut == "positive", "expected_unknown": cut == "descendant" && result.err != nil, "actual_group_empty": true, "actual_store_released": true, "actual_claim_EX_and_pki_SH": true}); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ENROLLMENT_WORKER_RESULT cut=%s unit=%s job=%s actual_cleanup=true\n", cut, result.proof.Association.Unit, result.proof.Job)
}
func TestEnrollmentWorkerCleanupProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_ROOT") != "1" {
		t.Skip("separate actual worker cleanup only")
	}
	profile, err := enrollmentC1WorkerProfile()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := enrollmentC1WorkerBinding(profile.stage)
	if err != nil {
		t.Fatal("unknown binding; preserve root", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager, err := openEnrollmentObserver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.retire(ctx)
	if err = enrollmentC1WorkerProofBound(proof, manager, profile); err != nil {
		t.Fatal(err)
	}
	// No Stop/Clean/Reset/unload: only release the fixed known private leaf, if
	// that actual bound fixture has one, then require physical terminal/custody.

	empty, err := enrollmentWorkerCgroupEmpty(proof.Association.Unit, proof.Bound.Group)
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		var leaf struct {
			PID    uint32 `json:"pid"`
			Start  string `json:"start"`
			Closed bool   `json:"capability_descriptors_closed"`
		}
		body, e := os.ReadFile(filepath.Join(profile.stage, "leaf-ready.json"))
		if e != nil || json.Unmarshal(body, &leaf) != nil || !leaf.Closed {
			t.Fatal("unknown capable descendant; preserve exact custody/root", e)
		}
		start, e := enrollmentProcessStart(leaf.PID)
		if e != nil || start != leaf.Start {
			t.Fatal("unknown live leaf incarnation", e)
		}
		if e = enrollmentProcessImage(leaf.PID, profile.image, []string{profile.image, enrollmentC1LeafRole}); e != nil {
			t.Fatal(e)
		}
		var path dbus.ObjectPath
		e = manager.do(ctx, func() error {
			return manager.bus.Object(manager.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".GetUnitByPID", 0, leaf.PID).Store(&path)
		})
		if e != nil || path != proof.Bound.Path {
			t.Fatal("leaf outside actual bound unit", e)
		}
		if _, e = os.Lstat(filepath.Join(profile.stage, "leaf-release")); errors.Is(e, os.ErrNotExist) {
			if e = enrollmentC1WorkerSave(profile.stage, "leaf-release", map[string]bool{"release": true}); e != nil {
				t.Fatal(e)
			}
		} else if e != nil {
			t.Fatal(e)
		}
	}
	if err = enrollmentC1WorkerPhysicalRelease(ctx, manager, profile, proof); err != nil {
		t.Fatal(err)
	}

	current, err := manager.readWorker(ctx, proof.Association.Unit, profile)
	if err != nil {
		t.Fatal(err)
	}
	if current != nil {
		// Empty/terminal/store0 and independent claim/SH were just proven above.
		if err = manager.do(ctx, func() error {
			return manager.bus.Object(manager.owner, enrollmentSystemdPath).CallWithContext(ctx, enrollmentSystemdInterface+".ResetFailedUnit", 0, proof.Association.Unit).Err
		}); err != nil {
			t.Fatal(err)
		}
		for {
			current, err = manager.readWorker(ctx, proof.Association.Unit, profile)
			if err != nil {
				t.Fatal(err)
			}
			if current == nil {
				break
			}
			select {
			case <-time.After(25 * time.Millisecond):
			case <-ctx.Done():
				t.Fatal("known empty transient did not GC", ctx.Err())
			}
		}
	}
	body, _ := json.Marshal(map[string]any{"unit": proof.Association.Unit, "job": proof.Job, "invocation": hex.EncodeToString(proof.Bound.Invocation), "cgroup": proof.Bound.Group, "actual_group_empty": true, "actual_store_released": true, "actual_claim_EX_and_pki_SH": true})
	fmt.Println("ENROLLMENT_WORKER_CLEANUP_RESULT " + string(body))
}

func TestEnrollmentWorkerFixtureUnknownStartRetainsRoot(t *testing.T) {
	root := t.TempDir()
	statInfo, _ := os.Stat(root)
	stat := statInfo.Sys().(*syscall.Stat_t)
	profile := enrollmentWorkerProfile{stage: root, image: "/fixed/image", unitPrefix: enrollmentC1WorkerPrefix, launcherArgs: []string{"/fixed/image", enrollmentC1LauncherRole}}
	manager := &enrollmentManager{busID: "bus", owner: ":1.7", pidStart: "12", bootID: "boot"}
	unit := enrollmentC1WorkerPrefix + enrollmentC1FixtureAttempt + "-prepare.service"
	good := enrollmentWorkerProof{PossibleStart: true, Association: enrollmentHandoff{Version: 1, Unit: unit, Attempt: enrollmentC1FixtureAttempt, Kind: "prepare", FDNames: []string{"claim"}}, Job: "/org/freedesktop/systemd1/job/1", Bound: &enrollmentWorkerUnit{enrollmentMainState: enrollmentMainState{Unit: unit, Path: "/org/freedesktop/systemd1/unit/owned", Executable: profile.image, Arguments: profile.launcherArgs, Invocation: []byte("0123456789abcdef"), Group: "/system.slice/" + unit}}, Stage: root, StageDevice: uint64(stat.Dev), StageInode: stat.Ino, BusID: manager.busID, ManagerOwner: manager.owner, ManagerPIDStart: manager.pidStart, BootID: manager.bootID}
	if err := enrollmentC1WorkerProofBound(good, manager, profile); err != nil {
		t.Fatal(err)
	}
	for _, cut := range []string{"prepared", "possible-send", "job-missing", "group-missing", "invocation-missing", "source-changed", "generation-changed", "staging-changed"} {
		t.Run(cut, func(t *testing.T) {
			proof := good
			state := *good.Bound
			proof.Bound = &state
			switch cut {
			case "prepared":
				proof.PossibleStart = false
				proof.Bound = nil
			case "possible-send":
				proof.Bound = nil
			case "job-missing":
				proof.Job = ""
			case "group-missing":
				state.Group = ""
			case "invocation-missing":
				state.Invocation = nil
			case "source-changed":
				state.Executable = "/foreign"
			case "generation-changed":
				proof.ManagerOwner = ":1.8"
			case "staging-changed":
				proof.StageInode++
			}
			if err := enrollmentC1WorkerProofBound(proof, manager, profile); err == nil {
				t.Fatal("unknown worker binding could authorize cleanup")
			}
			if _, err := os.Stat(root); err != nil {
				t.Fatal("unknown worker namespace removed", err)
			}
		})
	}
}
func TestEnrollmentWorkerMissingReceiptOwnerRefusesBeforeEffects(t *testing.T) {
	profile := defaultEnrollmentWorkerProfile("/not-opened")
	called := false
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var manager *enrollmentManager
	if _, err := manager.runWorker(ctx, profile, enrollmentC1FixtureAttempt, "prepare", []*os.File{nil}, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("missing durable claim receipt owner reached effect route", err, called)
	}
}

// These are fixture evidence oracles, not production authority or a journal.
type enrollmentC1UtilityEvidence struct {
	Name   string   `json:"name"`
	Args   []string `json:"args"`
	PID    uint32   `json:"pid"`
	Start  string   `json:"start"`
	Parent uint32   `json:"parent"`
	Image  string   `json:"image"`
	Cgroup string   `json:"cgroup"`
}
type enrollmentC1UtilityEffect struct {
	Name   string `json:"name"`
	PID    uint32 `json:"pid"`
	Start  string `json:"start"`
	Synced bool   `json:"synced"`
}

func enrollmentC1WriteUtilityEvidence(root, name string, args []string) error {
	pid := uint32(os.Getpid())
	start, err := enrollmentProcessStart(pid)
	if err != nil {
		return err
	}
	image, err := os.Executable()
	if err != nil {
		return err
	}
	group, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	record := enrollmentC1UtilityEvidence{name, args, pid, start, uint32(os.Getppid()), image, string(group)}
	if err = enrollmentC1WorkerSave(root, "utility-"+name+".json", record); err != nil {
		return err
	}
	return enrollmentC1WorkerSave(root, "utility-"+name+"-effect.json", enrollmentC1UtilityEffect{name, pid, start, true})
}
func enrollmentC1FlockContention(err error) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}
func enrollmentC1RequirePositiveUtilities(root string, parent uint32, group, image string) ([]enrollmentC1UtilityEvidence, error) {
	if parent == 0 || group == "" || !filepath.IsAbs(image) {
		return nil, errors.New("positive utility owner/group/image missing")
	}
	names := []string{"apt-get", "modprobe"}
	expected := [][]string{{"install", "-y", "-qq", "qemu-system-x86", "qemu-utils", "libvirt-daemon-system", "genisoimage", "bridge-utils", "haproxy", "keepalived"}, {"vfio-pci"}}
	read := func(name string, value any) error {
		fd, err := unix.Open(filepath.Join(root, name), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0600 || info.Size() > 16*1024 {
			return errors.New("positive utility artifact type/owner/mode/size changed")
		}
		decoder := json.NewDecoder(io.LimitReader(file, 16*1024+1))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(value); err != nil {
			return err
		}
		var extra any
		if err = decoder.Decode(&extra); err != io.EOF {
			return errors.New("positive utility artifact has trailing data")
		}
		return nil
	}
	records := make([]enrollmentC1UtilityEvidence, 0, 2)
	seen := map[uint32]bool{}
	for i, name := range names {
		var record enrollmentC1UtilityEvidence
		if err := read("utility-"+name+".json", &record); err != nil {
			return nil, err
		}
		start, err := strconv.ParseUint(record.Start, 10, 64)
		if err != nil || start == 0 || strconv.FormatUint(start, 10) != record.Start || record.PID < 2 || record.PID > math.MaxInt32 || record.PID == parent || seen[record.PID] || record.Parent != parent || record.Image != image || !enrollmentProcessGroup([]byte(record.Cgroup), group) || record.Name != name || !equalEnrollmentArguments(record.Args, expected[i]) {
			return nil, errors.New("positive actual utility name/argv/PID/start/parent/image/group changed")
		}
		seen[record.PID] = true
		var effect enrollmentC1UtilityEffect
		if err = read("utility-"+name+"-effect.json", &effect); err != nil {
			return nil, err
		}
		if !effect.Synced || effect.Name != name || effect.PID != record.PID || effect.Start != record.Start {
			return nil, errors.New("positive utility effect not bound to actual child")
		}
		records = append(records, record)
	}
	return records, nil
}
func TestEnrollmentWorkerFlockOracleRequiresActualContention(t *testing.T) {
	for _, err := range []error{nil, syscall.EINTR, syscall.EIO, syscall.EBADF, syscall.EPERM, errors.Join(syscall.EAGAIN, syscall.EIO)} {
		if enrollmentC1FlockContention(err) {
			t.Errorf("unrelated probe result became retained custody: %v", err)
		}
	}
	if err := unix.Flock(-1, unix.LOCK_EX|unix.LOCK_NB); err != syscall.EBADF || enrollmentC1FlockContention(err) {
		t.Errorf("actual invalid-fd error became custody: %v", err)
	}
	for _, err := range []error{syscall.EAGAIN, syscall.EWOULDBLOCK} {
		if !enrollmentC1FlockContention(err) {
			t.Errorf("actual contention rejected: %v", err)
		}
	}
}
