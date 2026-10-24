package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func TestEnrollmentWorkerTransientPropertiesPreserveSelectedProvider(t *testing.T) {
	profile := defaultEnrollmentWorkerProfile("/owned/stage")
	bounds := enrollmentWorkerBounds{operation: 999999999999, handoff: 888888888888}
	for _, oom := range []bool{false, true} {
		properties := enrollmentWorkerProperties(profile, bounds, oom)
		if len(properties) == 0 {
			t.Fatal("RED_WORKER_MANAGER: no actual selected transient properties")
		}
		byName := map[string]dbus.Variant{}
		for _, property := range properties {
			if _, duplicate := byName[property.Name]; duplicate {
				t.Fatal("duplicate transient property", property.Name)
			}
			byName[property.Name] = property.Value
		}
		for name, want := range map[string]any{"Type": "forking", "GuessMainPID": false, "PIDFile": "", "RemainAfterExit": false, "Restart": "no", "NotifyAccess": "all", "FileDescriptorStoreMax": uint32(2), "RuntimeMaxUSec": uint64(math.MaxUint64), "StopWhenUnneeded": false, "Delegate": false, "WorkingDirectory": profile.stage} {
			if !reflect.DeepEqual(byName[name].Value(), want) {
				t.Fatalf("provider property %s=%v want%v", name, byName[name].Value(), want)
			}
		}
		if value, present := byName["OOMPolicy"]; present != oom || present && value.Value() != "continue" {
			t.Fatal("optional OOM property is not initial known-supported continue", byName)
		}
		for _, name := range []string{"ExitType", "ExtraFileDescriptors", "FileDescriptorStorePreserve"} {
			if _, present := byName[name]; present {
				t.Fatal("introduced newer required mechanism", name)
			}
		}
		if !reflect.DeepEqual(byName["Environment"].Value(), append(enrollmentUtilityEnvironment(profile.environment, ""), bounds.environment()...)) {
			t.Fatal("original exact bootstrap bounds changed in unit environment")
		}
		commands, ok := byName["ExecStart"].Value().([]enrollmentExecCommand)
		if !ok || len(commands) != 1 || commands[0].Path != profile.image || !reflect.DeepEqual(commands[0].Args, profile.launcherArgs) || commands[0].Ignore {
			t.Fatal("ExecStart escaped fixed launcher source", commands)
		}
		if dbus.SignatureOf(commands).String() != "a(sasb)" {
			t.Fatal("wrong StartTransientUnit ExecStart ABI")
		}
	}
}

func TestEnrollmentWorkerManagerGateNeedsExactSourceAndPhysicalAssociation(t *testing.T) {
	profile := defaultEnrollmentWorkerProfile("/owned/stage")
	want := enrollmentHandoffFixture("prepare")
	for _, cut := range []string{"valid-no-OOM-property", "valid-continue-OOM", "wrong-executable", "wrong-argv", "guessed-main", "known-main", "control-live", "store-empty", "store-extra", "pending-job", "wrong-kind-type", "no-group", "no-invocation", "oom-stop", "runtime-timeout", "foreign-working-dir", "unexpected-precommand"} {
		t.Run(cut, func(t *testing.T) {
			unit := map[string]dbus.Variant{"Id": dbus.MakeVariant(want.Unit), "ActiveState": dbus.MakeVariant("active"), "InvocationID": dbus.MakeVariant([]byte("0123456789abcdef")), "Job": dbus.MakeVariant([]any{uint32(0), dbus.ObjectPath("/")}), "StopWhenUnneeded": dbus.MakeVariant(false)}
			commands := []enrollmentExecStartWire{{Path: profile.image, Args: append([]string{}, profile.launcherArgs...)}}
			service := map[string]dbus.Variant{"ExecStart": enrollmentExecStartPropertyFromWire(t, commands), "Type": dbus.MakeVariant("forking"), "GuessMainPID": dbus.MakeVariant(false), "PIDFile": dbus.MakeVariant(""), "RemainAfterExit": dbus.MakeVariant(false), "Restart": dbus.MakeVariant("no"), "NotifyAccess": dbus.MakeVariant("all"), "FileDescriptorStoreMax": dbus.MakeVariant(uint32(2)), "NFileDescriptorStore": dbus.MakeVariant(uint32(1)), "MainPID": dbus.MakeVariant(uint32(0)), "ControlPID": dbus.MakeVariant(uint32(0)), "ControlGroup": dbus.MakeVariant("/system.slice/" + want.Unit), "RuntimeMaxUSec": dbus.MakeVariant(uint64(math.MaxUint64)), "Delegate": dbus.MakeVariant(false), "WorkingDirectory": dbus.MakeVariant(profile.stage)}
			service["WatchdogUSec"] = dbus.MakeVariant(uint64(0))
			service["KillMode"] = dbus.MakeVariant("process")
			for _, name := range []string{"ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"} {
				service[name] = enrollmentExecStartPropertyFromWire(t, []enrollmentExecStartWire{})
			}
			switch cut {
			case "valid-continue-OOM":
				service["OOMPolicy"] = dbus.MakeVariant("continue")
			case "wrong-executable":
				commands[0].Path = "/foreign"
				service["ExecStart"] = enrollmentExecStartPropertyFromWire(t, commands)
			case "wrong-argv":
				commands[0].Args = []string{profile.image, "arbitrary"}
				service["ExecStart"] = enrollmentExecStartPropertyFromWire(t, commands)
			case "guessed-main":
				service["GuessMainPID"] = dbus.MakeVariant(true)
			case "known-main":
				service["MainPID"] = dbus.MakeVariant(uint32(123))
			case "control-live":
				service["ControlPID"] = dbus.MakeVariant(uint32(123))
			case "store-empty":
				service["NFileDescriptorStore"] = dbus.MakeVariant(uint32(0))
			case "store-extra":
				service["NFileDescriptorStore"] = dbus.MakeVariant(uint32(2))
			case "pending-job":
				unit["Job"] = dbus.MakeVariant([]any{uint32(42), dbus.ObjectPath("/org/freedesktop/systemd1/job/42")})
			case "wrong-kind-type":
				service["Type"] = dbus.MakeVariant("oneshot")
			case "no-group":
				service["ControlGroup"] = dbus.MakeVariant("")
			case "no-invocation":
				unit["InvocationID"] = dbus.MakeVariant([]byte{})
			case "oom-stop":
				service["OOMPolicy"] = dbus.MakeVariant("stop")
			case "runtime-timeout":
				service["RuntimeMaxUSec"] = dbus.MakeVariant(uint64(1000))
			case "foreign-working-dir":
				service["WorkingDirectory"] = dbus.MakeVariant("/foreign")
			case "unexpected-precommand":
				service["ExecStartPre"] = enrollmentExecStartPropertyFromWire(t, []enrollmentExecStartWire{{Path: "/foreign", Args: []string{"/foreign"}}})
			}
			state, err := decodeEnrollmentWorkerUnit(want.Unit, "/org/freedesktop/systemd1/unit/worker", unit, service, profile)
			if err == nil {
				err = state.launchGate(1)
			}
			valid := strings.HasPrefix(cut, "valid-")
			if (err == nil) != valid {
				t.Fatalf("RED_WORKER_MANAGER: actual gate classification mismatch: %+v %v", state, err)
			}
		})
	}
}

func TestEnrollmentWorkerOOMCapabilityUsesPresenceNotConfiguredValue(t *testing.T) {
	for _, configured := range []string{"continue", "stop", "kill", ""} {
		present, err := enrollmentWorkerOOMPresence(map[string]dbus.Variant{"OOMPolicy": dbus.MakeVariant(configured)})
		if err != nil || !present {
			t.Fatal("actual typed property support was confused with configured policy", configured, err)
		}
	}
	if present, err := enrollmentWorkerOOMPresence(map[string]dbus.Variant{}); err != nil || present {
		t.Fatal("successful Service map without optional property was not accepted as old path", present, err)
	}
	for _, properties := range []map[string]dbus.Variant{nil, {"OOMPolicy": dbus.MakeVariant(uint32(1))}} {
		if _, err := enrollmentWorkerOOMPresence(properties); err == nil {
			t.Fatal("unknown/malformed Service reply inferred support", properties)
		}
	}
}

func TestEnrollmentMainAbsenceRequiresExactOrderedRemoteReply(t *testing.T) {
	m := &enrollmentManager{owner: ":1.4", mainUnit: "litevirt.service"}
	for _, cut := range []string{"ordered-NoSuchUnit", "GetUnit", "different-unit", "different-mode", "wrong-owner", "wrong-path", "missing-response", "transport", "timeout", "wrapped-remote", "different-remote", "successful-reply", "extra-argument", "nil-call"} {
		t.Run(cut, func(t *testing.T) {
			call := &dbus.Call{Destination: m.owner, Path: enrollmentSystemdPath, Method: enrollmentSystemdInterface + ".StopUnit", Args: []any{m.mainUnit, "replace"}, ResponseSequence: 1, Err: dbus.Error{Name: "org.freedesktop.systemd1.NoSuchUnit", Body: []any{"Unit not loaded."}}}
			switch cut {
			case "GetUnit":
				call.Method = enrollmentSystemdInterface + ".GetUnit"
			case "different-unit":
				call.Args[0] = "foreign.service"
			case "different-mode":
				call.Args[1] = "fail"
			case "wrong-owner":
				call.Destination = ":1.5"
			case "wrong-path":
				call.Path = "/foreign"
			case "missing-response":
				call.ResponseSequence = dbus.NoSequence
			case "transport":
				call.Err = errors.New("connection lost")
			case "timeout":
				call.Err = context.DeadlineExceeded
			case "wrapped-remote":
				call.Err = fmt.Errorf("unknown transport outcome: %w", call.Err)
			case "different-remote":
				call.Err = dbus.Error{Name: "org.freedesktop.systemd1.NoSuchJob"}
			case "successful-reply":
				call.Err = nil
			case "extra-argument":
				call.Args = append(call.Args, "foreign")
			case "nil-call":
				call = nil
			}
			err := m.orderedMainAbsence(call)
			if (err == nil) != (cut == "ordered-NoSuchUnit") {
				t.Fatalf("ordered main absence classification: %v", err)
			}
		})
	}
}

func TestEnrollmentMainInactiveRequiresRetainedActualBinding(t *testing.T) {
	m := &enrollmentManager{mainUnit: "litevirt.service", mainExecutable: "/usr/local/bin/litevirt", mainArguments: []string{"/usr/local/bin/litevirt", "daemon"}}
	active := enrollmentMainState{Unit: m.mainUnit, Path: "/org/freedesktop/systemd1/unit/litevirt_2eservice", Active: "active", Executable: m.mainExecutable, Arguments: m.mainArguments, MainPID: 1234, Invocation: []byte("0123456789abcdef"), Group: "/system.slice/litevirt.service"}
	for _, cut := range []string{"live", "fresh-observation-only", "known-inactive", "known-failed", "known-removed", "inactive-without-binding", "failed-without-binding", "missing-group", "missing-invocation", "missing-pid", "missing-job", "foreign-invocation", "foreign-group", "foreign-source", "foreign-unit"} {
		t.Run(cut, func(t *testing.T) {
			current := active
			before := &current
			proof := &enrollmentMainProof{Before: active, Job: "/org/freedesktop/systemd1/job/42"}
			wantErr, wantNil := false, false
			switch cut {
			case "live":
				proof = nil
			case "fresh-observation-only":
				before = nil
				proof = nil
				wantNil = true // permits only subsequent ordered Stop; not quiescence
			case "known-inactive":
				current.MainPID = 0
				current.Active = "inactive"
				current.Group = ""
			case "known-failed":
				current.MainPID = 0
				current.Active = "failed"
				current.Group = ""
			case "known-removed":
				before = nil
			case "inactive-without-binding":
				current.MainPID = 0
				current.Active = "inactive"
				current.Group = ""
				proof = nil
				wantErr = true
			case "failed-without-binding":
				current.MainPID = 0
				current.Active = "failed"
				current.Group = ""
				proof = nil
				wantErr = true
			case "missing-group":
				before = nil
				proof.Before.Group = ""
				wantErr = true
			case "missing-invocation":
				before = nil
				proof.Before.Invocation = nil
				wantErr = true
			case "missing-pid":
				before = nil
				proof.Before.MainPID = 0
				wantErr = true
			case "missing-job":
				before = nil
				proof.Job = ""
				wantErr = true
			case "foreign-invocation":
				current.MainPID = 0
				current.Invocation = []byte("fedcba9876543210")
				wantErr = true
			case "foreign-group":
				current.MainPID = 0
				current.Group = "/different.slice/litevirt.service"
				wantErr = true
			case "foreign-source":
				current.MainPID = 0
				current.Executable = "/foreign"
				wantErr = true
			case "foreign-unit":
				current.MainPID = 0
				current.Unit = "foreign.service"
				wantErr = true
			}
			known, err := m.knownMainIncarnation(before, proof)
			if (err != nil) != wantErr {
				t.Fatalf("binding classification: known=%+v err=%v", known, err)
			}
			if err == nil && ((known == nil) != wantNil) {
				t.Fatalf("missing/current observation became a synthetic incarnation: %+v", known)
			}
			if err == nil && known != nil && (known.MainPID != active.MainPID || known.Group != active.Group || !bytes.Equal(known.Invocation, active.Invocation)) {
				t.Fatal("physical binding was not retained", known)
			}
		})
	}
}

func TestEnrollmentMainJobListDecodesRealABIAndRefusesPendingMain(t *testing.T) {
	type wireJob struct {
		ID                uint32
		Unit, Type, State string
		Path, UnitPath    dbus.ObjectPath
	}
	wire := []wireJob{{42, "litevirt.service", "start", "waiting", "/org/freedesktop/systemd1/job/42", "/org/freedesktop/systemd1/unit/litevirt_2eservice"}}
	if signature := dbus.SignatureOf(wire).String(); signature != "a(usssoo)" {
		t.Fatal("wrong actual ListJobs ABI", signature)
	}
	// Reuse the real message codec round trip; the property wrapper is local
	// test transport, while the ListJobs struct values and Store are identical.
	value := enrollmentExecStartPropertyFromWire(t, wire)
	var jobs []enrollmentManagerJob
	if err := dbus.Store([]any{value.Value()}, &jobs); err != nil {
		t.Fatal("actual pinned ListJobs Store", err)
	}
	if len(jobs) != 1 || jobs[0].ID != 42 || jobs[0].Unit != "litevirt.service" || jobs[0].Path != wire[0].Path || jobs[0].UnitPath != wire[0].UnitPath {
		t.Fatal("ListJobs decode lost exact job association", jobs)
	}
	m := &enrollmentManager{mainUnit: "litevirt.service"}
	if err := m.mainJobsTerminal(jobs); err == nil {
		t.Fatal("pending main job admitted absence/stop completion")
	}
	jobs[0].Unit = "unrelated.service"
	if err := m.mainJobsTerminal(jobs); err != nil {
		t.Fatal("unrelated job is not main", err)
	}
	if err := m.mainJobsTerminal(nil); err != nil {
		t.Fatal("empty actual list refused", err)
	}
}

// Independent systemd Service.ExecStart ABI, from the installed manager
// documentation: a(sasbttttuii). Do not alias the production decode type.
type enrollmentExecStartWire struct {
	Path                                                       string
	Args                                                       []string
	Ignore                                                     bool
	StartRealtime, StartMonotonic, ExitRealtime, ExitMonotonic uint64
	PID                                                        uint32
	Code, Status                                               int32
}

func enrollmentExecStartPropertyFromWire(t *testing.T, value any) dbus.Variant {
	t.Helper()
	properties := map[string]dbus.Variant{"ExecStart": dbus.MakeVariant(value)}
	message := &dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{dbus.FieldReplySerial: dbus.MakeVariant(uint32(1)), dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf(properties))}, Body: []any{properties}}
	var buffer bytes.Buffer
	if err := message.EncodeTo(&buffer, binary.LittleEndian); err != nil {
		t.Fatal("actual pinned godbus encode", err)
	}
	decoded, err := dbus.DecodeMessage(&buffer)
	if err != nil {
		t.Fatal("actual pinned godbus decode", err)
	}
	var result map[string]dbus.Variant
	if err := dbus.Store(decoded.Body, &result); err != nil {
		t.Fatal("actual property Store", err)
	}
	return result["ExecStart"]
}

func TestEnrollmentMainExecDecodesActualSystemdSignature(t *testing.T) {
	wire := enrollmentExecStartWire{Path: "/usr/local/bin/litevirt", Args: []string{"/usr/local/bin/litevirt", "daemon"}, StartRealtime: 1700000000000001, StartMonotonic: 2000002, ExitRealtime: 1700000000000003, ExitMonotonic: 4000004, PID: 12345, Code: 1, Status: 7}
	if signature := dbus.SignatureOf([]enrollmentExecStartWire{wire}).String(); signature != "a(sasbttttuii)" {
		t.Fatal("test did not encode real systemd ABI", signature)
	}
	value := enrollmentExecStartPropertyFromWire(t, []enrollmentExecStartWire{wire})
	// Call.Store's map conversion re-infers this variant as aav after copying
	// its decoded interface slices. Production must decode the ten actual values
	// rather than treating that local re-inference as the original wire ABI.
	t.Logf("genuine_wire_signature=a(sasbttttuii) post_CallStore_signature=%s", value.Signature())
	m := &enrollmentManager{mainExecutable: wire.Path, mainArguments: wire.Args}
	command, err := m.decodeMainExec(value)
	if err != nil {
		t.Fatal("production decoder refused genuine ten-field systemd ExecStart", err)
	}
	if signature := dbus.SignatureOf(command).String(); signature != "(sasbttttuii)" {
		t.Fatal("production decode type differs from genuine systemd ABI", signature)
	}
	if command.Path != wire.Path || !equalEnrollmentArguments(command.Args, wire.Args) || command.Ignore || command.PID != wire.PID || command.Code != wire.Code || command.Status != wire.Status {
		t.Fatal("actual production Store changed execution identity or result", command)
	}
	fields := reflect.ValueOf(command)
	for i, want := range []uint64{wire.StartRealtime, wire.StartMonotonic, wire.ExitRealtime, wire.ExitMonotonic} {
		if got := fields.Field(i + 3).Uint(); got != want {
			t.Fatalf("wire timestamp %d decoded as %d, want %d", i, got, want)
		}
	}
}

func TestEnrollmentMainExecRejectsMalformedShapeAndForeignSource(t *testing.T) {
	valid := enrollmentExecStartWire{Path: "/usr/local/bin/litevirt", Args: []string{"/usr/local/bin/litevirt", "daemon"}}
	m := &enrollmentManager{mainExecutable: valid.Path, mainArguments: valid.Args}
	for _, cut := range []string{"missing-property", "empty", "two-commands", "foreign-path", "foreign-argv0", "foreign-purpose", "extra-argument", "ignore-failure", "wrong-property-signature", "eight-fields", "nine-fields", "eleven-fields"} {
		t.Run(cut, func(t *testing.T) {
			command := valid
			commands := []enrollmentExecStartWire{command}
			switch cut {
			case "empty":
				commands = nil
			case "two-commands":
				commands = append(commands, valid)
			case "foreign-path":
				commands[0].Path = "/foreign/litevirt"
			case "foreign-argv0":
				commands[0].Args = []string{"/foreign/litevirt", "daemon"}
			case "foreign-purpose":
				commands[0].Args = []string{valid.Path, "host-enroll-control"}
			case "extra-argument":
				commands[0].Args = append(append([]string{}, valid.Args...), "foreign")
			case "ignore-failure":
				commands[0].Ignore = true
			}
			value := enrollmentExecStartPropertyFromWire(t, commands)
			switch cut {
			case "missing-property":
				value = dbus.Variant{}
			case "wrong-property-signature":
				value = enrollmentExecStartPropertyFromWire(t, []string{valid.Path})
			case "eight-fields", "nine-fields", "eleven-fields":
				// Force a signature-preserving malformed decoded value through the
				// real Store path as well as testing actual wire signatures above.
				row := []any{valid.Path, valid.Args, false, uint64(1), uint64(2), uint64(3), uint64(4), uint32(123), int32(1), int32(0)}
				if cut == "eight-fields" {
					row = []any{valid.Path, valid.Args, false, uint64(1), uint64(2), uint32(123), int32(1), int32(0)}
				}
				if cut == "nine-fields" {
					row = row[:9]
				}
				if cut == "eleven-fields" {
					row = append(row, uint32(99))
				}
				value = dbus.MakeVariantWithSignature([][]any{row}, dbus.ParseSignatureMust("a(sasbttttuii)"))
			}
			if command, err := m.decodeMainExec(value); err == nil {
				t.Fatalf("malformed/foreign source authorized: %+v", command)
			}
		})
	}
}

func TestEnrollmentMainJobRequiresExactTerminalObservation(t *testing.T) {
	job := dbus.ObjectPath("/org/freedesktop/systemd1/job/42")
	valid := func() *dbus.Signal {
		return &dbus.Signal{Sender: ":1.4", Path: enrollmentSystemdPath, Name: enrollmentSystemdInterface + ".JobRemoved", Body: []any{uint32(42), job, "litevirt.service", "done"}}
	}
	for _, cut := range []string{"valid", "sender", "path", "id", "unit", "result", "types", "arity", "reload", "closed", "unrelated-job", "unrelated-name"} {
		t.Run(cut, func(t *testing.T) {
			e := valid()
			wantDone, wantErr := false, true
			switch cut {
			case "valid":
				wantDone, wantErr = true, false
			case "sender":
				e.Sender = ":1.5"
			case "path":
				e.Path = "/foreign"
			case "id":
				e.Body[0] = uint32(43)
			case "unit":
				e.Body[2] = "foreign.service"
			case "result":
				e.Body[3] = "canceled"
			case "types":
				e.Body[0] = int32(42)
			case "arity":
				e.Body = e.Body[:3]
			case "reload":
				e.Name = enrollmentSystemdInterface + ".Reloading"
				e.Body = []any{true}
			case "closed":
				e = nil
			case "unrelated-job":
				e.Body[1] = dbus.ObjectPath("/org/freedesktop/systemd1/job/41")
				wantErr = false
			case "unrelated-name":
				e.Name = "org.freedesktop.DBus.NameAcquired"
				wantErr = false
			}
			done, err := enrollmentJobEvent(e, ":1.4", job, "litevirt.service")
			if done != wantDone || (err != nil) != wantErr {
				t.Fatalf("done=%v err=%v", done, err)
			}
		})
	}
	for _, path := range []dbus.ObjectPath{"", "/org/freedesktop/systemd1/job/0", "/org/freedesktop/systemd1/job/042", "/org/freedesktop/systemd1/job/+42", "/org/freedesktop/systemd1/job/42/foreign", "/foreign/42"} {
		if _, err := enrollmentJobID(path); err == nil {
			t.Fatalf("invalid accepted job admitted: %q", path)
		}
	}
}

func TestEnrollmentMainStopNeedsBoundIncarnationAndPhysicalPopulation(t *testing.T) {
	before := enrollmentMainState{Path: "/org/freedesktop/systemd1/unit/litevirt_2eservice", Unit: "litevirt.service", Active: "active", Group: "/system.slice/litevirt.service", Executable: "/usr/local/bin/litevirt", Arguments: []string{"/usr/local/bin/litevirt", "daemon"}, Invocation: []byte("0123456789abcdef"), MainPID: 1234}
	for _, cut := range []string{"terminal", "known-removed", "running", "control", "fdstore", "pending-job", "different-invocation", "different-pid", "different-group", "different-source", "different-args", "unknown-group", "unknown-invocation", "unknown-pid"} {
		t.Run(cut, func(t *testing.T) {
			b := before
			a := before
			a.Active = "inactive"
			a.MainPID = 0
			after := &a
			wantDone, wantErr := false, false
			switch cut {
			case "terminal":
				wantDone = true
			case "known-removed":
				after = nil
				wantDone = true
			case "running":
				a.MainPID = 1234
				a.Active = "active"
			case "control":
				a.ControlPID = 55
			case "fdstore":
				a.FDStore = 1
			case "pending-job":
				a.Job.ID = 99
			case "different-invocation":
				a.Invocation = []byte("fedcba9876543210")
				wantErr = true
			case "different-pid":
				a.MainPID = 5678
				wantErr = true
			case "different-group":
				a.Group = "/system.slice/foreign.service"
				wantErr = true
			case "different-source":
				a.Executable = "/foreign"
				wantErr = true
			case "different-args":
				a.Arguments = []string{"/usr/local/bin/litevirt", "foreign"}
				wantErr = true
			case "unknown-group":
				b.Group = ""
				after = nil
				wantErr = true
			case "unknown-invocation":
				b.Invocation = nil
				after = nil
				wantErr = true
			case "unknown-pid":
				b.MainPID = 0
				after = nil
				wantErr = true
			}
			done, err := enrollmentStoppedMain(b, after)
			if done != wantDone || (err != nil) != wantErr {
				t.Fatalf("terminal=%v err=%v", done, err)
			}
		})
	}
	for _, body := range []string{"", "frozen 0\n", "populated 2\n", "populated 0\npopulated 1\n"} {
		if empty, err := enrollmentCgroupPopulation([]byte(body)); err == nil || empty {
			t.Fatalf("unknown population admitted: %q", body)
		}
	}
	if empty, err := enrollmentCgroupPopulation([]byte("populated 1\nfrozen 0\n")); err != nil || empty {
		t.Fatalf("populated group admitted: %v %v", empty, err)
	}
	if empty, err := enrollmentCgroupPopulation([]byte("populated 0\nfrozen 0\n")); err != nil || !empty {
		t.Fatalf("empty actual population refused: %v %v", empty, err)
	}
}

func TestEnrollmentRetirementJoinsWholeControlObservation(t *testing.T) {
	raw, peer := enrollmentSocketPair(t)
	defer peer.Close()
	bus, err := dbus.DialUnix(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := newEnrollmentTransport(raw, bus)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- m.control(ctx, func() error { close(entered); <-m.retiredCh; <-finish; return errEnrollmentManagerRetired })
	}()
	<-entered
	short, stop := context.WithTimeout(ctx, 25*time.Millisecond)
	err = m.retire(short)
	stop()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		close(finish)
		<-done
		t.Fatalf("retirement escaped original observation: %v", err)
	}
	select {
	case <-m.closed:
		close(finish)
		<-done
		t.Fatal("library closure was reported before observation joined")
	default:
	}
	called := false
	if err := m.control(ctx, func() error { called = true; return nil }); !errors.Is(err, errEnrollmentManagerRetired) || called {
		close(finish)
		<-done
		t.Fatal("retired observation accepted new work", err)
	}
	close(finish)
	if err := <-done; !errors.Is(err, errEnrollmentManagerRetired) {
		t.Fatal(err)
	}
	if err := m.retire(ctx); err != nil {
		t.Fatal("original observation failed to join", err)
	}
}

func enrollmentSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	convert := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "enrollment-private-transport")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := convert(fds[0]), convert(fds[1])
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestEnrollmentConnectionUniqueAcceptsAcquiredDuplicate(t *testing.T) {
	for _, names := range [][]string{{":1.42"}, {":1.42", ":1.42"}} {
		name, err := enrollmentConnectionUnique(names)
		if err != nil || name != ":1.42" {
			t.Fatalf("valid Hello/NameAcquired identity rejected: %v %v", names, err)
		}
	}
	for _, names := range [][]string{nil, {""}, {"org.litevirt.EnrollmentControl1"}, {":1.42", ":1.43"}, {":1.42", "org.litevirt.EnrollmentControl1"}} {
		if _, err := enrollmentConnectionUnique(names); err == nil {
			t.Fatalf("unexpected pre-RequestName identity accepted: %v", names)
		}
	}
}

// Fill the actual kernel send buffer while the peer deliberately reads nothing.
// EAGAIN and the pinned writer's actual stack establish the cut, not a sleep.
func enrollmentStallSocket(t *testing.T, c *net.UnixConn) {
	t.Helper()
	if err := c.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var terminal error
	total := 0
	err = raw.Control(func(fd uintptr) {
		for total < 1<<20 {
			n, e := unix.SendmsgN(int(fd), make([]byte, 4096), nil, nil, unix.MSG_DONTWAIT)
			total += n
			if e != nil {
				terminal = e
				return
			}
		}
	})
	if err != nil || terminal != syscall.EAGAIN || total == 0 {
		t.Fatalf("kernel buffer was not filled: bytes=%d terminal=%v control=%v", total, terminal, err)
	}
	t.Logf("ACTUAL_SEND_BUFFER_FULL bytes=%d", total)
}

func enrollmentWaitForLibraryWrite(t *testing.T) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		stacks := string(buf[:n])
		if strings.Contains(stacks, "dbus/v5.(*unixTransport).SendMessage") &&
			strings.Contains(stacks, "dbus/v5.(*outputHandler).sendAndIfClosed") {
			fmt.Println("ACTUAL_LIBRARY_WRITE_STALLED")
			return
		}
		runtime.Gosched()
	}
	t.Fatal("actual pinned library writer never reached the stalled transport")
}

func enrollmentWaitClosed(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("original %s did not terminate after raw interruption", label)
	}
}

func TestEnrollmentSenderStalledUnixWriteRetirement(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestEnrollmentTransportProcess$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "LITEVIRT_ENROLLMENT_TRANSPORT_CHILD=stalled-write")
	out, err := cmd.CombinedOutput()
	t.Logf("original_pid=%d original_wait=%v\n%s", cmd.Process.Pid, err, out)
	if !bytes.Contains(out, []byte("ACTUAL_LIBRARY_WRITE_STALLED")) {
		t.Fatal("child did not establish the actual library transport cut")
	}
	if err != nil {
		t.Fatalf("stalled writer was not retired by the bounded original operation: %v", err)
	}
	if !bytes.Contains(out, []byte("ORIGINAL_SENDER_JOINED")) {
		t.Fatal("child did not join its actual sender")
	}
}

func TestEnrollmentTransportProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_TRANSPORT_CHILD") != "stalled-write" {
		t.Skip("subprocess only; actual parent owns PID and Wait")
	}
	client, peer := enrollmentSocketPair(t)
	enrollmentStallSocket(t, client)
	// No fake manager result: this fixture exercises only the actual local
	// transport writer. Authenticated real-system-bus ordering is separate.
	conn, err := dbus.DialUnix(client)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	manager := newEnrollmentTransport(client, conn)
	sender := make(chan struct{})
	go func() {
		defer close(sender)
		_ = manager.do(ctx, func() error {
			return conn.Object("org.litevirt.TransportFixture", "/org/litevirt/TransportFixture").CallWithContext(
				ctx, "org.litevirt.TransportFixture.Stall", 0, make([]byte, 65536)).Err
		})
	}()
	enrollmentWaitForLibraryWrite(t)
	cancel()
	closed := make(chan struct{})
	var closeErr error
	go func() {
		defer close(closed)
		end, finish := context.WithTimeout(context.Background(), time.Second)
		defer finish()
		closeErr = manager.retire(end)
	}()
	retired := false
	select {
	case <-closed:
		retired = true
	case <-time.After(time.Second):
	}
	// Always clean up the true failed baseline after observing the oracle.
	// This cleanup cannot turn its failed bounded retirement into success.
	_ = client.Close()
	_ = peer.Close()
	enrollmentWaitClosed(t, sender, "sender")
	enrollmentWaitClosed(t, closed, "library Close")
	fmt.Println("ORIGINAL_SENDER_JOINED")
	if !retired || closeErr != nil {
		t.Fatal("RED_ENROLLMENT_STALLED_WRITE_RETIREMENT: cancellation and normal Close did not interrupt the writer")
	}
	if err := manager.do(ctx, func() error { t.Fatal("retired sender executed"); return nil }); err != errEnrollmentManagerRetired {
		t.Fatalf("retired generation accepted a submission: %v", err)
	}
}

func TestEnrollmentCanceledCallerCannotSubmit(t *testing.T) {
	lateCalls, lateBytes := 0, 0
	// Independent ready-token/canceled-context cuts. Every one must refuse the
	// new submission, regardless of which ready select branch the runtime picks.
	for cut := 0; cut < 32; cut++ {
		client, peer := enrollmentSocketPair(t)
		bus, err := dbus.DialUnix(client)
		if err != nil {
			t.Fatal(err)
		}
		manager := newEnrollmentTransport(client, bus)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cancel()
		err = manager.do(ctx, func() error {
			lateCalls++
			_, err := client.Write([]byte{'x'})
			return err
		})
		if err == nil {
			t.Fatal("canceled caller reported successful submission")
		}
		end, finish := context.WithTimeout(context.Background(), time.Second)
		if err := manager.retire(end); err != nil {
			t.Fatal(err)
		}
		finish()
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var body [1]byte
		n, _ := peer.Read(body[:])
		lateBytes += n
		_ = peer.Close()
	}
	if lateCalls != 0 {
		t.Fatalf("RED_ENROLLMENT_CANCELED_SUBMIT: already canceled caller invoked %d submissions and wrote %d actual peer bytes", lateCalls, lateBytes)
	}
}

func TestEnrollmentManagerOwnsRootSystemBusGeneration(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_ROOT") != "1" {
		t.Skip("separate root system-bus fixture envelope required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root fixture envelope did not supply actual root")
	}
	t.Logf("actual_root_uid=%d actual_original_pid=%d", os.Geteuid(), os.Getpid())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	manager, err := openEnrollmentManager(ctx)
	if err != nil {
		t.Fatalf("RED_ENROLLMENT_ROOT_MANAGER: actual root system-bus generation refused: %v", err)
	}
	defer func() {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := manager.retire(end); err != nil {
			t.Errorf("actual original generation did not retire: %v", err)
		}
	}()
	if manager.busID == "" || manager.owner == "" || !manager.bus.SupportsUnixFDs() || !manager.subscribed || manager.signals == nil {
		t.Fatal("root generation lacks actual bus/manager identity or negotiated UnixFDs")
	}
	var peer *syscall.Ucred
	var peerErr error
	rawControl, err := manager.raw.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := rawControl.Control(func(fd uintptr) {
		peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || peerErr != nil || peer == nil || peer.Uid != 0 {
		t.Fatalf("actual root socket peer not independently established: %v %v", err, peerErr)
	}
	t.Logf("actual_bus_peer_uid=%d actual_bus_peer_pid=%d bus_id=%s manager_owner=%s manager_pid=%d manager_start=%s boot_id=%s writer_unique=%s acknowledged_subscription=%t", peer.Uid, peer.Pid, manager.busID, manager.owner, manager.managerPID, manager.pidStart, manager.bootID, manager.unique, manager.subscribed)
	other, err := openEnrollmentManager(ctx)
	if err == nil {
		_ = other.retire(ctx)
		t.Fatal("another generation acquired the nonreplaceable name")
	}
	observer, err := openEnrollmentObserver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.retire(ctx)
	var owner string
	if err := observer.do(ctx, func() error {
		return observer.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, "org.litevirt.EnrollmentControl1").Store(&owner)
	}); err != nil || owner != manager.unique {
		t.Fatalf("actual independent observer did not see the owned generation: %v", err)
	}
	if os.Getenv("LITEVIRT_ENROLLMENT_POLICY_STALL") == "1" {
		fmt.Printf("POLICY_STALL_WRITER_OWNED unique=%s observed_owner=%s bus=%s manager=%s\n", manager.unique, owner, manager.busID, manager.owner)
		<-ctx.Done()
		t.Fatal("post-ownership timeout fixture did not terminate its actual child within its shorter bound")
	}
	if err := manager.retire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.do(ctx, func() error { t.Fatal("retired root generation submitted"); return nil }); err != errEnrollmentManagerRetired {
		t.Fatalf("retired actual root generation accepted work: %v", err)
	}
}

func TestEnrollmentPolicyBusProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_C1_ROOT") != "1" {
		t.Skip("separate fixed-policy root fixture only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("policy fixture requires actual root")
	}
	action := os.Getenv("LITEVIRT_ENROLLMENT_POLICY_ACTION")
	if action != "inspect" && action != "reload" {
		t.Fatal("unsupported test-only fixed policy action")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if action == "reload" {
		if err := reloadEnrollmentControlPolicy(ctx); err != nil {
			t.Fatal(err)
		}
	}
	observer, err := openEnrollmentObserver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		end, finish := context.WithTimeout(context.Background(), 5*time.Second)
		defer finish()
		if err := observer.retire(end); err != nil {
			t.Errorf("policy observer retirement incomplete: %v", err)
		}
	}()
	if err := observer.checkGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	var owned bool
	if err := observer.do(ctx, func() error {
		return observer.bus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, enrollmentWriterName).Store(&owned)
	}); err != nil {
		t.Fatal(err)
	}
	if owned {
		t.Fatal("selected writer name remains owned")
	}
	result, err := json.Marshal(map[string]any{
		"bus_id": observer.busID, "manager_owner": observer.owner,
		"manager_pid_start": observer.pidStart, "boot_id": observer.bootID,
		"name_owned": owned, "reloaded": action == "reload", "actual_root_uid": os.Geteuid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ENROLLMENT_POLICY_RESULT %s\n", result)
}

func TestEnrollmentWorkerRefsRemainOwnedUntilOriginalRetirement(t *testing.T) {
	raw, peer := enrollmentSocketPair(t)
	defer peer.Close()
	bus, err := dbus.DialUnix(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := newEnrollmentTransport(raw, bus)
	path := t.TempDir() + "/claim"
	held, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(int(held.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err = m.ownWorkerFiles([]*os.File{held}); err != nil {
		held.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- m.control(ctx, func() error { close(entered); <-m.retiredCh; <-finish; return errEnrollmentManagerRetired })
	}()
	<-entered
	probe := func(blocked bool) {
		t.Helper()
		f, e := os.OpenFile(path, os.O_RDWR, 0)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if blocked && !enrollmentC1FlockContention(e) {
			t.Fatal("local capability probe lacks actual nonblocking contention before sender/observation join", e)
		}
		if !blocked && e != nil {
			t.Fatal("original retirement did not close owned local refs", e)
		}
	}
	short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	err = m.retire(short)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		close(finish)
		<-done
		t.Fatal(err)
	}
	probe(true)
	rejected, _ := os.OpenFile(path, os.O_RDWR, 0)
	defer rejected.Close()
	if err = m.ownWorkerFiles([]*os.File{rejected}); !errors.Is(err, errEnrollmentManagerRetired) {
		close(finish)
		<-done
		t.Fatal("retired generation accepted capability", err)
	}
	close(finish)
	<-done
	if err = m.retire(ctx); err != nil {
		t.Fatal(err)
	}
	probe(false)
}

func TestEnrollmentWorkerTerminalRetainsActualIncarnationAndGroup(t *testing.T) {
	before := enrollmentWorkerUnit{enrollmentMainState: enrollmentMainState{Unit: "litevirt-enrollment-012345abcdef-prepare.service", Path: "/org/freedesktop/systemd1/unit/known", Invocation: []byte("0123456789abcdef"), Group: "/system.slice/litevirt-enrollment-012345abcdef-prepare.service", Executable: "/fixed/image", Arguments: []string{"/fixed/image", "host-enroll-control", "launcher"}, Active: "active", FDStore: 1}}
	before.Job.Path = "/"
	for _, cut := range []string{"gone-empty", "gone-populated", "inactive-empty", "inactive-populated", "active-empty", "stored", "new-invocation", "new-source", "new-group", "unbound", "pending"} {
		t.Run(cut, func(t *testing.T) {
			b := before
			after := before
			after.Active = "inactive"
			after.FDStore = 0
			after.Group = ""
			current := &after
			empty := true
			want := false
			wantErr := false
			switch cut {
			case "gone-empty":
				current = nil
				want = true
			case "gone-populated":
				current = nil
				empty = false
			case "inactive-empty":
				want = true
			case "inactive-populated":
				empty = false
			case "active-empty":
				after.Active = "active"
			case "stored":
				after.FDStore = 1
			case "new-invocation":
				after.Invocation = []byte("fedcba9876543210")
				wantErr = true
			case "new-source":
				after.Executable = "/foreign"
				wantErr = true
			case "new-group":
				after.Group = "/foreign.service"
				wantErr = true
			case "unbound":
				b.Group = ""
				current = nil
				wantErr = true
			case "pending":
				after.Job.ID = 11
				after.Job.Path = "/org/freedesktop/systemd1/job/11"
			}
			done, err := enrollmentWorkerTerminal(b, current, empty)
			if done != want || (err != nil) != wantErr {
				t.Fatalf("done=%v err=%v", done, err)
			}
		})
	}
}
func TestEnrollmentWorkerAssociationUsesOnlySelectedUnitShape(t *testing.T) {
	prefix := "litevirt-enrollment-"
	for _, kind := range []enrollmentWorkerKind{"prepare", "apparmor"} {
		unit := prefix + "012345abcdef-" + string(kind) + ".service"
		got, err := enrollmentWorkerAssociation(unit, prefix)
		if err != nil || got.Unit != unit || got.Kind != kind || got.Attempt != "012345abcdef" || !reflect.DeepEqual(got.FDNames, enrollmentFDNames(kind)) {
			t.Fatal(got, err)
		}
	}
	for _, unit := range []string{"litevirt.service", "litevirt-enrollment-012345abcdef-rollback.service", "litevirt-enrollment-012345abcdeF-prepare.service", "litevirt-enrollment-012345abcdef-prepare.service.extra", "foreign-012345abcdef-prepare.service"} {
		if _, err := enrollmentWorkerAssociation(unit, prefix); err == nil {
			t.Fatal("foreign unit accepted", unit)
		}
	}
}
