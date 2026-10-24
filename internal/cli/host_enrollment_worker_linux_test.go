package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestEnrollmentSeqpacketEmptyDoesNotProvePeerClosed(t *testing.T) {
	peer, receiver := enrollmentPacketPair(t)
	if _, _, err := peer.WriteMsgUnix(nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	body, control := make([]byte, 1), make([]byte, 128)
	n, oob, flags, _, emptyErr := receiver.ReadMsgUnix(body, control)
	if n != 0 || oob != 0 || !errors.Is(emptyErr, io.EOF) {
		t.Fatalf("unexpected actual zero-packet observation: %d %d %d %v", n, oob, flags, emptyErr)
	}
	// This real peer is still capable of writing after the apparent EOF.
	if _, _, err := peer.WriteMsgUnix([]byte{'x'}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if count, _, _, _, err := receiver.ReadMsgUnix(body, control); err != nil || count != 1 || body[0] != 'x' {
		t.Fatal("peer was not actually open after apparent EOF", count, err)
	}
	_ = peer.Close()
	closedN, closedOOB, closedFlags, _, closedErr := receiver.ReadMsgUnix(body, control)
	if closedN != n || closedOOB != oob || closedFlags != flags || !errors.Is(closedErr, io.EOF) {
		t.Fatalf("zero-packet/true-close observations differ: %d %d %d %v", closedN, closedOOB, closedFlags, closedErr)
	}
	t.Logf("SEQPACKET_EMPTY_AND_CLOSE_IDENTICAL n=%d oob=%d flags=%d err=%v; actual peer wrote another byte after apparent EOF", n, oob, flags, emptyErr)
}

func TestEnrollmentPassCredListenerCoversQueuedBeforeAccept(t *testing.T) {
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "pc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	address := &net.UnixAddr{Name: filepath.Join(dir, "c.sock"), Net: "unixpacket"}
	listener, err := net.ListenUnix("unixpacket", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	rawListener, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := rawListener.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	// The listener option is set before the client exists; both messages are
	// queued before Accept, reproducing the earliest possible worker response.
	client, err := net.DialUnix("unixpacket", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, _, err := client.WriteMsgUnix(nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.WriteMsgUnix([]byte("later-extra"), nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	control, err := accepted.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var inherited int
	var peer *unix.Ucred
	if err := control.Control(func(fd uintptr) {
		inherited, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED)
		if optionErr == nil {
			peer, optionErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}
	}); err != nil || optionErr != nil || inherited != 1 || peer == nil {
		t.Fatalf("accepted credential option not inherited: %d %v %v", inherited, err, optionErr)
	}
	if err := accepted.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body, oob := make([]byte, 4097), make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(2*4))
	if len(oob) != 56 {
		t.Fatal("unexpected pinned ABI OOB size", len(oob))
	}
	for index := 0; index < 2; index++ {
		n, count, flags, _, err := accepted.ReadMsgUnix(body, oob)
		if index == 0 && (n != 0 || !errors.Is(err, io.EOF)) {
			t.Fatal("zero DATA shape changed", n, err)
		}
		if index == 1 && (n != len("later-extra") || err != nil) {
			t.Fatal("queued extra missing", n, err)
		}
		messages, parseErr := unix.ParseSocketControlMessage(oob[:count])
		if parseErr != nil || len(messages) != 1 || messages[0].Header.Level != unix.SOL_SOCKET || messages[0].Header.Type != unix.SCM_CREDENTIALS {
			t.Fatalf("queued DATA lacks exactly one kernel credential: %d %d %v", n, count, parseErr)
		}
		credential, err := unix.ParseUnixCredentials(&messages[0])
		if err != nil || *credential != *peer {
			t.Fatal("kernel credentials did not match prechecked actual peer", credential, peer, err)
		}
		t.Logf("QUEUED_DATA_HAS_CREDENTIAL index=%d n=%d oob=%d flags=%d pid=%d uid=%d gid=%d", index, n, count, flags, credential.Pid, credential.Uid, credential.Gid)
	}
	n, count, _, _, err := accepted.ReadMsgUnix(body, oob)
	if n != 0 || count != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("true close carried DATA credentials", n, count, err)
	}
	t.Log("PASSCRED_INHERITED_BEFORE_LAUNCH_AND_TRUE_EOF_HAS_NO_CMSG")
}

func TestEnrollmentPassCredZeroDataRightsRequireCleanup(t *testing.T) {
	for _, number := range []int{1, 3} {
		t.Run(fmt.Sprint(number), func(t *testing.T) {
			peer, receiver := enrollmentPacketPair(t)
			raw, err := receiver.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var optionErr error
			if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || optionErr != nil {
				t.Fatal(err, optionErr)
			}
			file := enrollmentLockedFile(t)
			path := file.Name()
			rights := make([]int, number)
			for i := range rights {
				rights[i] = int(file.Fd())
			}
			sender, err := peer.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			if err := peer.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var sendErr error
			if err := sender.Write(func(fd uintptr) bool {
				// x/sys SendmsgN pads empty ancillary messages for non-DGRAM.
				// This adversarial test alone bypasses that padding; production
				// sends only nonempty fixed JSON and uses the ordinary API.
				rightsControl := unix.UnixRights(rights...)
				message := unix.Msghdr{Control: &rightsControl[0]}
				message.SetControllen(len(rightsControl))
				_, _, errno := unix.Syscall(unix.SYS_SENDMSG, fd, uintptr(unsafe.Pointer(&message)), uintptr(unix.MSG_DONTWAIT))
				runtime.KeepAlive(rightsControl)
				if errno != 0 {
					sendErr = errno
				} else {
					sendErr = nil
				}
				return sendErr != unix.EAGAIN && sendErr != unix.EWOULDBLOCK
			}); err != nil || sendErr != nil {
				t.Fatal(err, sendErr)
			}
			_ = file.Close()
			if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			body, control := make([]byte, 1), make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(2*4))
			n, count, flags, _, readErr := receiver.ReadMsgUnix(body, control)
			messages, parseErr := unix.ParseSocketControlMessage(control[:count])
			var delivered []*os.File
			credentials := 0
			for _, message := range messages {
				if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
					fds, err := unix.ParseUnixRights(&message)
					if err != nil {
						t.Fatal(err)
					}
					for _, fd := range fds {
						f := os.NewFile(uintptr(fd), "refused-right")
						delivered = append(delivered, f)
						t.Cleanup(func() { _ = f.Close() })
					}
				} else if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_CREDENTIALS {
					credentials++
				}
			}
			if n != 0 || !errors.Is(readErr, io.EOF) || parseErr != nil || credentials != 1 || len(delivered) == 0 {
				t.Fatalf("zero DATA/EOF still delivered controls: n%d/oob%d flags%d creds%d rights%d %v %v", n, count, flags, credentials, len(delivered), readErr, parseErr)
			}
			if number == 3 && flags&unix.MSG_CTRUNC == 0 {
				t.Fatal("refused excess descriptors were not marked truncated")
			}
			for _, file := range delivered {
				_ = file.Close()
			}
			probe, err := os.OpenFile(path, os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal("zero DATA/refused or truncated rights retained actual OFD after received-close", err)
			}
			t.Logf("ZERO_DATA_RIGHTS_PARSED_DESPITE_EOF sent=%d delivered=%d flags=%d oob=%d actual_flock_acquired", number, len(delivered), flags, count)
		})
	}
}

func TestEnrollmentWorkerCompletionIsDistinctAndStrict(t *testing.T) {
	want := enrollmentHandoffFixture("apparmor")
	complete := want
	complete.Completed = true
	raw, err := json.Marshal(complete)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeEnrollmentCompletion(raw, want); err != nil || !got.Completed || got.Ready {
		t.Fatalf("RED_ENROLLMENT_COMPLETION: exact distinct completion refused: %v", err)
	}
	for _, ack := range []bool{false, true} {
		if _, err := decodeEnrollmentHandoff(raw, want, ack); err == nil {
			t.Fatal("completion accepted as request/readiness")
		}
	}
	ready := want
	ready.Ready = true
	readyRaw, _ := json.Marshal(ready)
	if bytes.Contains(readyRaw, []byte("completed")) {
		t.Fatal("original ready byte schema changed")
	}
	for _, bad := range [][]byte{
		readyRaw,
		bytes.Replace(raw, []byte(`"completed":true`), []byte(`"completed":false`), 1),
		bytes.Replace(raw, []byte(`"completed":true`), []byte(`"completed":true,"ready":true`), 1),
		bytes.Replace(raw, []byte(`"completed":true`), []byte(`"completed":true,"completed":true`), 1),
		bytes.Replace(raw, []byte(`"completed":true`), []byte(`"completed":true,"extra":0`), 1),
		bytes.Replace(raw, []byte(`"completed":true`), []byte(`"completed":"true"`), 1),
		append(append([]byte{}, raw...), []byte(" {}")...),
		bytes.Replace(raw, []byte(want.Attempt), []byte("ffffffffffff"), 1),
		bytes.Repeat([]byte("x"), 4097),
		append(append([]byte{}, raw...), 0xff),
	} {
		if _, err := decodeEnrollmentCompletion(bad, want); err == nil {
			t.Fatalf("invalid completion accepted: %q", bad)
		}
	}
}

func TestEnrollmentWorkerMonotonicBootstrapNeverRenewsBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var clock unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock); err != nil {
		t.Fatal(err)
	}
	before := clock.Nano()
	bounds, err := captureEnrollmentWorkerBounds(ctx)
	if err != nil {
		t.Fatal("RED_WORKER_BOOTSTRAP: bounded original context refused", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock); err != nil {
		t.Fatal(err)
	}
	if bounds.handoff <= before || bounds.handoff > clock.Nano()+int64(10*time.Second) || bounds.operation < bounds.handoff || bounds.operation > before+int64(20*time.Second) {
		t.Fatal("bootstrap extended original operation/handoff budget", bounds)
	}
	parsed, err := parseEnrollmentWorkerBounds(bounds.environment())
	if err != nil || parsed != bounds {
		t.Fatalf("exact monotonic bounds changed across bootstrap: %+v %v", parsed, err)
	}
	if _, err := captureEnrollmentWorkerBounds(context.Background()); err == nil {
		t.Fatal("unbounded operation received a renewed default")
	}
	for _, values := range [][]string{nil, {"LITEVIRT_ENROLLMENT_OPERATION_DEADLINE_NS=01", "LITEVIRT_ENROLLMENT_HANDOFF_DEADLINE_NS=1"}, {"LITEVIRT_ENROLLMENT_OPERATION_DEADLINE_NS=9223372036854775808", "LITEVIRT_ENROLLMENT_HANDOFF_DEADLINE_NS=1"}, {"LITEVIRT_ENROLLMENT_OPERATION_DEADLINE_NS=1", "LITEVIRT_ENROLLMENT_HANDOFF_DEADLINE_NS=1"}, append(bounds.environment(), bounds.environment()[0])} {
		if _, err := parseEnrollmentWorkerBounds(values); err == nil {
			t.Fatal("missing/malformed/overflow/expired/duplicate bounds admitted", values)
		}
	}
}

func TestEnrollmentWorkerCompletionRequiresParentGateAndTrueClose(t *testing.T) {
	want := enrollmentHandoffFixture("prepare")
	ready := want
	ready.Ready = true
	complete := want
	complete.Completed = true
	rawReady, _ := json.Marshal(ready)
	rawComplete, _ := json.Marshal(complete)
	for _, cut := range []string{"ordered", "no-parent-ACK", "completion-before-ready", "duplicate-ready", "extra-after-completed", "premature-close", "empty-DATA-after-completed"} {
		t.Run(cut, func(t *testing.T) {
			var state enrollmentReportState
			if cut == "completion-before-ready" {
				if err := state.receive(rawComplete, false, want); err == nil {
					t.Fatal("out-of-order completion admitted")
				}
				return
			}
			if err := state.receive(rawReady, false, want); err != nil {
				t.Fatal("RED_WORKER_PARENT_GATE: genuine first readiness refused", err)
			}
			if cut == "duplicate-ready" {
				if err := state.receive(rawReady, false, want); err == nil {
					t.Fatal("duplicate readiness admitted")
				}
				return
			}
			if cut == "no-parent-ACK" {
				if err := state.receive(rawComplete, false, want); err == nil {
					t.Fatal("completion bypassed actual parent launch gate")
				}
				return
			}
			if err := state.acknowledgeGate(); err != nil {
				t.Fatal(err)
			}
			if cut == "premature-close" {
				if err := state.receive(nil, true, want); err == nil {
					t.Fatal("premature EOF proved utility success")
				}
				return
			}
			if err := state.receive(rawComplete, false, want); err != nil {
				t.Fatal(err)
			}
			if cut == "extra-after-completed" {
				if err := state.receive(rawComplete, false, want); err == nil {
					t.Fatal("duplicate completion admitted")
				}
				return
			}
			if cut == "empty-DATA-after-completed" {
				if err := state.receive(nil, false, want); err == nil {
					t.Fatal("empty DATA became true close")
				}
				return
			}
			if err := state.receive(nil, true, want); err != nil {
				t.Fatal("true close after provisional completion refused", err)
			}
			if err := state.receive(rawReady, false, want); err == nil {
				t.Fatal("stream accepted extra packet after close")
			}
		})
	}
}

func enrollmentReportPeer(t *testing.T, receiver *net.UnixConn, enable bool) *unix.Ucred {
	t.Helper()
	raw, err := receiver.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var peer *unix.Ucred
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		if enable {
			optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
		}
		if optionErr == nil {
			peer, optionErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}
	}); err != nil || optionErr != nil || peer == nil {
		t.Fatal(err, optionErr)
	}
	return peer
}

func TestEnrollmentWorkerReportReaderDistinguishesEmptyDATAFromClose(t *testing.T) {
	for _, cut := range []string{"normal", "queued-empty-extra", "wrong-peer", "missing-credentials"} {
		t.Run(cut, func(t *testing.T) {
			sender, receiver := enrollmentPacketPair(t)
			peer := enrollmentReportPeer(t, receiver, cut != "missing-credentials")
			want := enrollmentHandoffFixture("prepare")
			ready := want
			ready.Ready = true
			raw, _ := json.Marshal(ready)
			if cut == "wrong-peer" {
				copy := *peer
				copy.Pid++
				peer = &copy
			}
			if _, _, err := sender.WriteMsgUnix(raw, nil, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			body, closed, err := readEnrollmentReportPacket(ctx, receiver, peer)
			if cut == "wrong-peer" || cut == "missing-credentials" {
				if err == nil {
					t.Fatal("unbound/missing credentials admitted DATA")
				}
				return
			}
			if err != nil || closed || !bytes.Equal(body, raw) {
				t.Fatal("RED_WORKER_REPORT_RECEIVE: genuine credential-bound DATA refused", closed, err)
			}
			if cut == "queued-empty-extra" {
				if _, _, err := sender.WriteMsgUnix(nil, nil, nil); err != nil {
					t.Fatal(err)
				}
				if _, _, err := sender.WriteMsgUnix(raw, nil, nil); err != nil {
					t.Fatal(err)
				}
				body, closed, err := readEnrollmentReportPacket(ctx, receiver, peer)
				if err != nil || closed || len(body) != 0 {
					t.Fatal("empty DATA became EOF or discarded its credentials", closed, err)
				}
				var state enrollmentReportState
				state = 3
				if err := state.receive(body, closed, want); err == nil {
					t.Fatal("post-completion empty DATA accepted as close")
				}
				body, closed, err = readEnrollmentReportPacket(ctx, receiver, peer)
				if err != nil || closed || !bytes.Equal(body, raw) {
					t.Fatal("queued extra packet vanished after empty DATA", err)
				}
			}
			_ = sender.Close()
			body, closed, err = readEnrollmentReportPacket(ctx, receiver, peer)
			if err != nil || !closed || len(body) != 0 {
				t.Fatal("genuine no-cmsg close refused", closed, err)
			}
		})
	}
}

func TestEnrollmentWorkerReportReaderClosesRightsEvenWrappedEOF(t *testing.T) {
	for _, count := range []int{1, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			sender, receiver := enrollmentPacketPair(t)
			peer := enrollmentReportPeer(t, receiver, true)
			file := enrollmentLockedFile(t)
			path := file.Name()
			fds := make([]int, count)
			for i := range fds {
				fds[i] = int(file.Fd())
			}
			raw, err := sender.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var sendErr error
			if err := sender.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := raw.Write(func(fd uintptr) bool {
				control := unix.UnixRights(fds...)
				msg := unix.Msghdr{Control: &control[0]}
				msg.SetControllen(len(control))
				_, _, errno := unix.Syscall(unix.SYS_SENDMSG, fd, uintptr(unsafe.Pointer(&msg)), uintptr(unix.MSG_DONTWAIT))
				runtime.KeepAlive(control)
				if errno != 0 {
					sendErr = errno
				} else {
					sendErr = nil
				}
				return sendErr != unix.EAGAIN && sendErr != unix.EWOULDBLOCK
			}); err != nil || sendErr != nil {
				t.Fatal(err, sendErr)
			}
			_ = file.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, closed, err := readEnrollmentReportPacket(ctx, receiver, peer); err == nil || closed {
				t.Fatal("zero DATA/rights wrongly accepted as termination")
			}
			probe, err := os.OpenFile(path, os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal("production report reader discarded wrappedEOF before closing delivered OFDs", err)
			}
		})
	}
}

func TestEnrollmentWorkerGateProcess(t *testing.T) {
	mode := os.Getenv("LITEVIRT_C1_GATE_TEST_CHILD")
	if mode == "" {
		t.Skip("owned actual process helper")
	}
	if mode != "positive" && mode != "withheld" && mode != "blocked" {
		t.Fatal("unknown fixed process test mode")
	}
	bounds, err := parseEnrollmentWorkerBounds(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	op, cancel, err := bounds.context(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	handoff, finish, err := bounds.context(op, true)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	c, err := (&net.Dialer{}).DialContext(handoff, "unixpacket", os.Getenv("LITEVIRT_C1_GATE_SOCKET"))
	if err != nil {
		t.Fatal(err)
	}
	connection := c.(*net.UnixConn)
	defer connection.Close()
	want := enrollmentHandoffFixture("prepare")
	files, err := readEnrollmentPacket(handoff, connection, want, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	ready := want
	ready.Ready = true
	if err := writeEnrollmentPacket(handoff, connection, ready, nil); err != nil {
		t.Fatal(err)
	}
	if err := awaitEnrollmentParentGate(handoff, connection, want); err != nil {
		if mode != "withheld" {
			t.Fatal("genuine parent gate refused", err)
		}
		if _, err := os.Stat(os.Getenv("LITEVIRT_C1_GATE_EFFECT")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("effect happened before parent ACK", err)
		}
		fmt.Println("ACTUAL_WORKER_NO_ACK_NO_EFFECT")
		return
	}
	if mode != "positive" && mode != "blocked" {
		t.Fatal("missing ACK did not stop fixed effect")
	}
	var stopMonitor func() error
	var utility context.Context
	if mode == "blocked" {
		var cancelUtility context.CancelFunc
		utility, cancelUtility = context.WithCancel(op)
		defer cancelUtility()
		stopMonitor = monitorEnrollmentParent(op, connection, cancelUtility)
		enrollmentAwaitIORead(t, op, "monitorEnrollmentParent")
	}
	f, err := os.OpenFile(os.Getenv("LITEVIRT_C1_GATE_EFFECT"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("parent ACK preceded actual effect\n"))
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		t.Fatal(err)
	}

	if stopMonitor != nil {
		if err := stopMonitor(); err != nil {
			t.Fatal("RED_BLOCKED_MONITOR_STOP_PREVENTED_COMPLETION", err)
		}
		if utility.Err() != nil {
			t.Fatal("local stop canceled valid utility outcome", utility.Err())
		}
	}
	complete := want
	complete.Completed = true
	if err := writeEnrollmentPacket(op, connection, complete, nil); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ACTUAL_WORKER_GATE_EFFECT_DURABLE bounds=%v\n", bounds.environment())
}

func TestEnrollmentWorkerActualProcessCannotActBeforeParentACK(t *testing.T) {
	for _, mode := range []string{"withheld", "positive"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "wg-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, "c.sock")
			effect := filepath.Join(dir, "effect")
			listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := listener.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var optionErr error
			if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || optionErr != nil {
				t.Fatal(err, optionErr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			bounds, err := captureEnrollmentWorkerBounds(ctx)
			if err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(executable, "-test.v", "-test.count=1", "-test.run=^TestEnrollmentWorkerGateProcess$", "-test.timeout=10s")
			child.Env = append(os.Environ(), bounds.environment()...)
			child.Env = append(child.Env, "LITEVIRT_C1_GATE_TEST_CHILD="+mode, "LITEVIRT_C1_GATE_SOCKET="+path, "LITEVIRT_C1_GATE_EFFECT="+effect)
			var output bytes.Buffer
			child.Stdout, child.Stderr = &output, &output
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			joined := false
			defer func() {
				if !joined {
					_ = child.Process.Kill()
					_ = child.Wait()
					t.Logf("failed owned gate child cleanup pid=%d output=%s", child.Process.Pid, output.String())
				}
			}()
			if deadline, ok := ctx.Deadline(); ok {
				_ = listener.SetDeadline(deadline)
			}
			connection, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			peer := enrollmentReportPeer(t, connection, false)
			if peer.Pid != int32(child.Process.Pid) {
				t.Fatal("actual peer differs from owned child", peer, child.Process.Pid)
			}
			want := enrollmentHandoffFixture("prepare")
			file := enrollmentLockedFile(t)
			claimPath := file.Name()
			if err := writeEnrollmentPacket(ctx, connection, want, []*os.File{file}); err != nil {
				t.Fatal("RED_WORKER_PROCESS_GATE: actual request send refused", err)
			}
			_ = file.Close()
			body, closed, err := readEnrollmentReportPacket(ctx, connection, peer)
			if err != nil {
				t.Fatal(err)
			}
			var state enrollmentReportState
			if err := state.receive(body, closed, want); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(effect); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("worker acted before actual parent ACK", err)
			}
			if mode == "withheld" {
				_ = connection.Close()
			} else {
				ready := want
				ready.Ready = true
				if err := writeEnrollmentPacket(ctx, connection, ready, nil); err != nil {
					t.Fatal(err)
				}
				if err := state.acknowledgeGate(); err != nil {
					t.Fatal(err)
				}
				body, closed, err = readEnrollmentReportPacket(ctx, connection, peer)
				if err != nil {
					t.Fatal(err)
				}
				if err := state.receive(body, closed, want); err != nil {
					t.Fatal(err)
				}
				body, closed, err = readEnrollmentReportPacket(ctx, connection, peer)
				if err != nil {
					t.Fatal(err)
				}
				if err := state.receive(body, closed, want); err != nil {
					t.Fatal(err)
				}
			}
			err = child.Wait()
			joined = true
			t.Logf("actual_gate_child_pid=%d Wait=%v output=%s", child.Process.Pid, err, output.String())
			if err != nil {
				t.Fatal(err)
			}
			if mode == "withheld" {
				if _, err := os.Stat(effect); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("withheld ACK permitted durable effect", err)
				}
			} else {
				if body, err := os.ReadFile(effect); err != nil || !bytes.Contains(body, []byte("parent ACK preceded")) {
					t.Fatal("actual ACK did not precede real effect", err)
				}
			}
			probe, err := os.OpenFile(claimPath, os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal("actual process/received references survived its Wait", err)
			}
		})
	}
}

type enrollmentUtilityTestRecord struct {
	Name              string
	Args, Environment []string
	PID               int
}

func TestEnrollmentWorkerUtilityProcess(t *testing.T) {
	mode := os.Getenv("LITEVIRT_C1_UTILITY_MODE")
	if mode == "" {
		t.Skip("owned fixed utility process helper")
	}
	index := -1
	for i, arg := range os.Args {
		if arg == "--" {
			index = i
			break
		}
	}
	if index < 0 || len(os.Args) <= index+1 {
		t.Fatal("missing exact fixed argv boundary")
	}
	name := os.Args[index+1]
	if name != "apt-get" && name != "dnf" && name != "modprobe" && name != "apparmor_parser" {
		t.Fatal("not a fixed utility")
	}
	recordPath := os.Getenv("LITEVIRT_C1_UTILITY_RECORD")
	previous, _ := os.ReadFile(recordPath)
	file, err := os.OpenFile(recordPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(enrollmentUtilityTestRecord{Name: name, Args: os.Args[index+2:], Environment: os.Environ(), PID: os.Getpid()})
	if _, err := file.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if mode == "cancel" && len(previous) == 0 {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(recordPath + ".release"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("owned cancel fixture release missing")
			}
			time.Sleep(time.Millisecond)
		}
	}
	if name == "modprobe" || name == "apparmor_parser" {
		os.Exit(23)
	} // selected ignored outcomes
	if name == "apt-get" && (mode == "fallback" || mode == "cancel") && len(previous) == 0 {
		os.Exit(17)
	}
	if name == "apt-get" && len(os.Args) > index+2 && os.Args[index+2] == "update" {
		os.Exit(19)
	} // retained ignored update error
}

func TestEnrollmentWorkerUtilitiesPreserveFiniteArgsEnvironmentAndCancellation(t *testing.T) {
	for _, mode := range []string{"success", "fallback", "dnf", "apparmor", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			recordPath := filepath.Join(dir, "utilities.jsonl")
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			watchDone := make(chan struct{})
			if mode == "cancel" {
				go func() {
					defer close(watchDone)
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}
						if body, err := os.ReadFile(recordPath); err == nil && bytes.Contains(body, []byte("\n")) {
							cancel()
							_ = os.WriteFile(recordPath+".release", []byte("release original utility"), 0600)
							return
						}
						time.Sleep(time.Millisecond)
					}
				}()
			} else {
				close(watchDone)
			}
			base := append(os.Environ(), "LITEVIRT_C1_UTILITY_MODE="+mode, "LITEVIRT_C1_UTILITY_RECORD="+recordPath, "NOTIFY_SOCKET=must-strip", "LISTEN_FDS=2", "WATCHDOG_USEC=5", "INVOCATION_ID=must-strip", enrollmentOperationDeadlineEnv+"=123", enrollmentHandoffDeadlineEnv+"=123")
			lookup := func(name string) (string, []string, error) {
				if name == "apt-get" && mode == "dnf" {
					return "", nil, exec.ErrNotFound
				}
				return executable, []string{"-test.v", "-test.count=1", "-test.run=^TestEnrollmentWorkerUtilityProcess$", "-test.timeout=8s", "--", name}, nil
			}
			kind := enrollmentWorkerKind("prepare")
			if mode == "apparmor" {
				kind = "apparmor"
			}
			err = runEnrollmentWorkerUtilities(ctx, kind, enrollmentUtilityExecution{directory: dir, environment: base, resolve: lookup})
			cancel()
			<-watchDone
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation was not retained after original utility Wait", err)
				}
			} else if err != nil {
				t.Fatal("RED_FIXED_WORKER_UTILITIES: real fixed utility sequence refused", err)
			}
			body, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal("no actual fixed utility ran", err)
			}
			var records []enrollmentUtilityTestRecord
			for _, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
				var record enrollmentUtilityTestRecord
				if err := json.Unmarshal(line, &record); err != nil {
					t.Fatal(err)
				}
				records = append(records, record)
			}
			want := 2
			if mode == "fallback" {
				want = 4
			}
			if mode == "apparmor" || mode == "cancel" {
				want = 1
			}
			if len(records) != want {
				t.Fatalf("fixed command/fallback/cancellation count %d want%d: %+v", len(records), want, records)
			}
			for _, record := range records {
				if record.PID <= 0 || record.PID == os.Getpid() {
					t.Fatal("fixed utility was not an actual child", record)
				}
				for _, entry := range record.Environment {
					if strings.HasPrefix(entry, "NOTIFY_SOCKET=") || strings.HasPrefix(entry, "LISTEN_") || strings.HasPrefix(entry, "WATCHDOG_") || strings.HasPrefix(entry, "INVOCATION_ID=") || strings.HasPrefix(entry, "LITEVIRT_ENROLLMENT_") {
						t.Fatal("manager/bootstrap control leaked into actual utility", entry)
					}
				}
				if kind == "prepare" {
					for _, required := range []string{"SYSTEMD_OFFLINE=1", "NEEDRESTART_SUSPEND=1", "NEEDRESTART_MODE=l"} {
						if !slices.Contains(record.Environment, required) {
							t.Fatal("preparation guard missing in actual child", required)
						}
					}
				}
			}
			if mode == "fallback" {
				if records[0].Name != "apt-get" || records[1].Name != "apt-get" || !reflect.DeepEqual(records[1].Args, []string{"update", "-qq", "-o", "Dir::Etc::sourcelist=/dev/null", "-o", "Dir::Etc::sourceparts=/dev/null"}) || !slices.Contains(records[0].Args, "qemu-utils") || slices.Contains(records[2].Args, "qemu-utils") {
					t.Fatal("exact apt fallback argv drifted", records)
				}
			}
			if mode == "dnf" && (!slices.Contains(records[0].Args, "qemu-kvm-core") || !slices.Contains(records[0].Args, "libvirt-daemon-kvm")) {
				t.Fatal("dnf branch was not retained", records)
			}
			if mode == "apparmor" && !reflect.DeepEqual(records[0].Args, []string{"-r", "/etc/apparmor.d/libvirt/TEMPLATE.qemu"}) {
				t.Fatal("fixed parser fallback drifted", records)
			}
			if mode != "apparmor" && mode != "cancel" && !reflect.DeepEqual(records[len(records)-1].Args, []string{"vfio-pci"}) {
				t.Fatal("fixed optional modprobe drifted", records)
			}
		})
	}
}

func TestEnrollmentWorkerCapabilityRejectsReopenAndWrongCanonicalInode(t *testing.T) {
	file := enrollmentLockedFile(t)
	path := file.Name()
	if err := validateEnrollmentCapability(file, path, uint32(os.Geteuid())); err != nil {
		t.Fatal("RED_ACTUAL_WORKER_OFD: genuine held claim refused", err)
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := os.NewFile(uintptr(fd), "borrowed")
	defer duplicate.Close()
	_ = file.Close()
	if err := validateEnrollmentCapability(duplicate, path, uint32(os.Geteuid())); err != nil {
		t.Fatal("actual same-OFD duplicate lost validation", err)
	}
	reopened, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := validateEnrollmentCapability(reopened, path, uint32(os.Geteuid())); err == nil {
		t.Fatal("same-inode independently reopened descriptor became actual claim")
	}
	if err := unix.Flock(int(reopened.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != syscall.EWOULDBLOCK {
		t.Fatal("validation acquired/unlocked the actual held claim", err)
	}
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateEnrollmentCapability(duplicate, other, uint32(os.Geteuid())); err == nil {
		t.Fatal("foreign canonical inode accepted")
	}
	if err := validateEnrollmentCapability(duplicate, path, uint32(os.Geteuid()+1)); err == nil {
		t.Fatal("foreign owner accepted")
	}
	shared, err := os.OpenFile(filepath.Join(t.TempDir(), "shared"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	if err := unix.Flock(int(shared.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := validateEnrollmentCapability(shared, shared.Name(), uint32(os.Geteuid())); err == nil {
		t.Fatal("SH admitted as actual exclusive worker capability")
	}
	_ = duplicate.Close()
	if err := unix.Flock(int(reopened.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("last actual reference did not release after validator", err)
	}
}

func TestEnrollmentWorkerBoundsProcess(t *testing.T) {
	mode := os.Getenv("LITEVIRT_C1_BOUNDS_TEST_CHILD")
	if mode == "" {
		t.Skip("owned actual bootstrap process helper")
	}
	bounds, err := parseEnrollmentWorkerBounds(os.Environ())
	if mode == "expired" {
		if err == nil {
			t.Fatal("delayed bootstrap renewed expired handoff")
		}
		fmt.Println("ACTUAL_DELAYED_BOOTSTRAP_REFUSED")
		return
	}
	if mode != "valid" || err != nil {
		t.Fatal("fixed bootstrap mode/deadline invalid", err)
	}
	ctx, cancel, err := bounds.context(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if _, bounded := ctx.Deadline(); !bounded {
		t.Fatal("bootstrap context not bounded")
	}
	fmt.Printf("ACTUAL_BOOTSTRAP_EXACT %s|%s\n", bounds.environment()[0], bounds.environment()[1])
}

func TestEnrollmentWorkerBootstrapActualProcessConsumesDelay(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			bounds, err := captureEnrollmentWorkerBounds(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "expired" {
				now, err := enrollmentMonotonicNow()
				if err != nil {
					t.Fatal(err)
				}
				bounds.handoff = now + int64(20*time.Millisecond)
				for {
					now, err = enrollmentMonotonicNow()
					if err != nil {
						t.Fatal(err)
					}
					if now >= bounds.handoff {
						break
					}
					time.Sleep(time.Millisecond)
				}
			}
			child := exec.Command(executable, "-test.v", "-test.count=1", "-test.run=^TestEnrollmentWorkerBoundsProcess$", "-test.timeout=8s")
			child.Env = append(os.Environ(), bounds.environment()...)
			child.Env = append(child.Env, "LITEVIRT_C1_BOUNDS_TEST_CHILD="+mode)
			out, err := child.CombinedOutput()
			t.Logf("actual_bootstrap_child_pid=%d Wait=%v output=%s", child.Process.Pid, err, out)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "valid" {
				if !bytes.Contains(out, []byte("ACTUAL_BOOTSTRAP_EXACT "+bounds.environment()[0]+"|"+bounds.environment()[1])) {
					t.Fatal("cross-process bootstrap changed original exact bounds")
				}
			} else if !bytes.Contains(out, []byte("ACTUAL_DELAYED_BOOTSTRAP_REFUSED")) {
				t.Fatal("no actual delayed-bootstrap refusal")
			}
		})
	}
}

func enrollmentHandoffFixture(kind enrollmentWorkerKind) enrollmentHandoff {
	w := enrollmentHandoff{Version: 1, Attempt: "012345abcdef", Kind: kind}
	w.Unit = "litevirt-enrollment-" + w.Attempt + "-" + string(kind) + ".service"
	w.FDNames = []string{"claim"}
	if kind == "apparmor" {
		w.FDNames = append(w.FDNames, "pki-ex")
	}
	return w
}

func TestEnrollmentWorkerHandoffStrictAssociation(t *testing.T) {
	for _, kind := range []enrollmentWorkerKind{"prepare", "apparmor"} {
		want := enrollmentHandoffFixture(kind)
		raw, _ := json.Marshal(want)
		got, err := decodeEnrollmentHandoff(raw, want, false)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("RED_ENROLLMENT_HANDOFF: genuine fixed association refused: %v", err)
		}
		ack := want
		ack.Ready = true
		raw, _ = json.Marshal(ack)
		got, err = decodeEnrollmentHandoff(raw, want, true)
		if err != nil || !reflect.DeepEqual(got, ack) {
			t.Fatalf("RED_ENROLLMENT_HANDOFF: genuine acknowledgement refused: %v", err)
		}
	}
	want := enrollmentHandoffFixture("apparmor")
	raw, _ := json.Marshal(want)
	bad := [][]byte{
		append(append([]byte(nil), raw...), []byte(" {}")...),
		bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1,"v":1`), 1),
		bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1,"other":0`), 1),
		bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1.0`), 1),
		bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":2`), 1),
		bytes.Replace(raw, []byte(`012345abcdef`), []byte(`012345abcdeF`), -1),
		bytes.Replace(raw, []byte(`"claim","pki-ex"`), []byte(`"pki-ex","claim"`), 1),
		bytes.Replace(raw, []byte(`"apparmor"`), []byte(`"shell"`), 1),
		bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1,"ready":true`), 1),
		append(bytes.Repeat([]byte(" "), 4096), raw...),
		[]byte("\xff"), []byte(`null`), raw[:len(raw)-1],
	}
	for i, body := range bad {
		if _, err := decodeEnrollmentHandoff(body, want, false); err == nil {
			t.Fatalf("malformed request %d accepted", i)
		}
	}
	if _, err := decodeEnrollmentHandoff(raw, want, true); err == nil {
		t.Fatal("request accepted as acknowledgement")
	}
	other := want
	other.Attempt = "abcdef012345"
	if _, err := decodeEnrollmentHandoff(raw, other, false); err == nil {
		t.Fatal("header replaced the actual known attempt")
	}
}

func enrollmentPacketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	convert := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "enrollment-private-packet")
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

func enrollmentLockedFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "claim"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestEnrollmentWorkerPacketKeepsActualOFDAndCloexec(t *testing.T) {
	want := enrollmentHandoffFixture("prepare")
	raw, _ := json.Marshal(want)
	a, b := enrollmentPacketPair(t)
	original := enrollmentLockedFile(t)
	path := original.Name()
	if _, _, err := a.WriteMsgUnix(raw, unix.UnixRights(int(original.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	_ = original.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	files, err := readEnrollmentPacket(ctx, b, want, false)
	if err != nil || len(files) != 1 {
		t.Fatalf("RED_ENROLLMENT_HANDOFF: actual descriptor handoff refused: %v", err)
	}
	defer files[0].Close()
	flags, err := unix.FcntlInt(files[0].Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("received descriptor was not atomically CLOEXEC")
	}
	contender, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer contender.Close()
	if err := unix.Flock(int(contender.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != syscall.EWOULDBLOCK {
		t.Fatalf("received description failed to preserve actual exclusion: %v", err)
	}
	_ = files[0].Close()
	if err := unix.Flock(int(contender.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("last received-reference close failed to release exclusion: %v", err)
	}
}

func TestEnrollmentWorkerPacketRefusalClosesEveryReceivedFD(t *testing.T) {
	want := enrollmentHandoffFixture("prepare")
	raw, _ := json.Marshal(want)
	for _, test := range []struct {
		name string
		body []byte
		fds  int
	}{
		{"unknown-key", bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1,"extra":0`), 1), 1},
		{"too-many-fds", raw, 3},
		{"oversized-packet", bytes.Repeat([]byte("x"), 4097), 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b := enrollmentPacketPair(t)
			f := enrollmentLockedFile(t)
			path := f.Name()
			fds := make([]int, test.fds)
			for i := range fds {
				fds[i] = int(f.Fd())
			}
			if _, _, err := a.WriteMsgUnix(test.body, unix.UnixRights(fds...), nil); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			files, err := readEnrollmentPacket(ctx, b, want, false)
			if err == nil || len(files) != 0 {
				t.Fatal("malformed descriptor packet accepted")
			}
			probe, err := os.OpenFile(path, os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatalf("RED_ENROLLMENT_HANDOFF: refusal leaked an actual received OFD: %v", err)
			}
		})
	}
}

func TestEnrollmentWorkerStoresEachNamedActualOFDSeparately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	receiver, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	files := make([]*os.File, 2)
	for i := range files {
		f, e := os.OpenFile(filepath.Join(t.TempDir(), "lock"), os.O_CREATE|os.O_RDWR, 0600)
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
			t.Fatal(e)
		}
		files[i] = f
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = storeEnrollmentCapabilities(ctx, path, []string{"claim", "pki-ex"}, files); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"claim", "pki-ex"} {
		receiver.SetReadDeadline(time.Now().Add(time.Second))
		b, oob := make([]byte, 256), make([]byte, unix.CmsgSpace(8))
		n, on, flags, _, e := receiver.ReadMsgUnix(b, oob)
		if e != nil {
			t.Fatal(e)
		}
		if string(b[:n]) != "FDSTORE=1\nFDNAME="+name || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			t.Fatal("wrong actual named notification", string(b[:n]), flags)
		}
		msgs, e := unix.ParseSocketControlMessage(oob[:on])
		if e != nil || len(msgs) != 1 {
			t.Fatal("wrong actual rights", e)
		}
		fds, e := unix.ParseUnixRights(&msgs[0])
		if e != nil || len(fds) != 1 {
			for _, fd := range fds {
				unix.Close(fd)
			}
			t.Fatal("multiple names collapsed onto one message", e)
		}
		unix.CloseOnExec(fds[0])
		received := os.NewFile(uintptr(fds[0]), name)
		if e = validateEnrollmentCapability(received, files[i].Name(), uint32(os.Geteuid())); e != nil {
			received.Close()
			t.Fatal(e)
		}
		received.Close()
	}
	if err = storeEnrollmentCapabilities(ctx, path, []string{"claim", "claim"}, files); err == nil {
		t.Fatal("duplicate FDNAME accepted")
	}
}
func TestEnrollmentWorkerStageRefusesForeignSocketAndTracksInode(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	stage, err := openEnrollmentWorkerStage(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.close()
	listener, err := stage.listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	alias := stage.address()
	peer, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: alias, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	raw, err := accepted.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var enabled int
	raw.Control(func(fd uintptr) { enabled, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED) })
	if err != nil || enabled != 1 {
		t.Fatal("listener-before-connect credentials missing", enabled, err)
	}
	if _, err = stage.listen(); err == nil {
		t.Fatal("existing socket overwritten")
	}
	listener.Close()
	if err = stage.removeSocket(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "control.sock"), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = stage.removeSocket(); err == nil {
		t.Fatal("foreign replacement deleted")
	}
	body, _ := os.ReadFile(filepath.Join(root, "control.sock"))
	if string(body) != "foreign" {
		t.Fatal("foreign artifact changed")
	}
	link := root + "-link"
	os.Symlink(root, link)
	if other, err := openEnrollmentWorkerStage(link, uint32(os.Geteuid())); err == nil {
		other.close()
		t.Fatal("symlink staging accepted")
	}
}

func TestEnrollmentWorkerParentRetirementPreventsLaterUtility(t *testing.T) {
	for _, cut := range []string{"normal", "peer-close", "extra-ready", "zero-rights"} {
		t.Run(cut, func(t *testing.T) {
			peer, receiver := enrollmentPacketPair(t)
			defer peer.Close()
			defer receiver.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			utility, stop := context.WithCancel(ctx)
			defer stop()
			finish := monitorEnrollmentParent(ctx, receiver, stop)
			if cut == "normal" {
				if err := finish(); err != nil {
					t.Fatal("normal no-extra stop", err)
				}
				if utility.Err() != nil {
					t.Fatal("normal monitor stopped utilities")
				}
				return
			}
			switch cut {
			case "peer-close":
				peer.Close()
			case "extra-ready":
				peer.WriteMsgUnix([]byte(`{"ready":true}`), nil, nil)
			case "zero-rights":
				f, err := os.OpenFile(filepath.Join(t.TempDir(), "held"), os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
				peer.WriteMsgUnix([]byte("extra"), unix.UnixRights(int(f.Fd())), nil)
				f.Close()
			}
			select {
			case <-utility.Done():
			case <-time.After(time.Second):
				t.Fatal("parent retirement/extra message did not prevent next utility")
			}
			if err := finish(); err == nil {
				t.Fatal("invalid parent termination reported clean")
			}
		})
	}
}
func TestEnrollmentWorkerCgroupLocationUsesActualSystemdHierarchy(t *testing.T) {
	for _, test := range []struct {
		mount   string
		unified bool
		want    string
	}{
		{"25 1 0:25 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n", true, "/sys/fs/cgroup/system.slice/known.service"},
		{"25 1 0:25 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd\n", false, "/sys/fs/cgroup/systemd/system.slice/known.service"},
		{"25 1 0:25 /system.slice /sys/fs/cgroup rw - cgroup2 cgroup rw\n", true, "/sys/fs/cgroup/known.service"},
	} {
		got, err := enrollmentCgroupDirectory([]byte(test.mount), "/system.slice/known.service", test.unified)
		if err != nil || got != test.want {
			t.Fatal(got, err)
		}
	}
	if _, err := enrollmentCgroupDirectory([]byte("25 1 0:25 / /foreign rw - tmpfs tmpfs rw\n"), "/system.slice/known.service", true); err == nil {
		t.Fatal("missing actual cgroup hierarchy inferred empty")
	}
}

func TestEnrollmentWorkerPositiveEffectProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_C1_POSITIVE_EFFECT_CHILD") != "1" {
		t.Skip("fixed actual inert effect process")
	}
	root := os.Getenv("LITEVIRT_C1_POSITIVE_EFFECT_ROOT")
	index := slices.Index(os.Args, "--")
	if index < 0 || len(os.Args) < index+2 {
		t.Fatal("fixed utility selector missing")
	}
	name := os.Args[index+1]
	if name != "apt-get" && name != "modprobe" {
		t.Fatal("unsupported fixed inert child")
	}
	if err := enrollmentC1WriteUtilityEvidence(root, name, os.Args[index+2:]); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ACTUAL_POSITIVE_EFFECT pid=%d parent=%d name=%s\n", os.Getpid(), os.Getppid(), name)
}
func enrollmentPositiveUtilityExecution(t *testing.T, root string) enrollmentUtilityExecution {
	t.Helper()
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return enrollmentUtilityExecution{directory: root, environment: append(os.Environ(), "LITEVIRT_C1_POSITIVE_EFFECT_CHILD=1", "LITEVIRT_C1_POSITIVE_EFFECT_ROOT="+root), resolve: func(name string) (string, []string, error) {
		return image, []string{"-test.v", "-test.count=1", "-test.timeout=8s", "-test.run=^TestEnrollmentWorkerPositiveEffectProcess$", "--", name}, nil
	}}
}
func TestEnrollmentWorkerDelayedLookupCannotStartAfterCancellation(t *testing.T) {
	for _, cut := range []string{"first-cancel", "first-expire", "later-cancel", "later-expire"} {
		t.Run(cut, func(t *testing.T) {
			root := t.TempDir()
			execution := enrollmentPositiveUtilityExecution(t, root)
			lookup := execution.resolve
			// The race-instrumented first child has real startup/exit-reporting
			// overhead before its original Wait. Choose this budget ONCE, before
			// that child, so later-expire can actually reach the later resolver.
			started := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			originalDeadline, _ := ctx.Deadline()
			calls := 0
			delayed := false
			execution.resolve = func(name string) (string, []string, error) {
				if name == "apt-get" {
					calls++
				}
				target := strings.HasPrefix(cut, "first") && name == "apt-get" && calls == 2 || strings.HasPrefix(cut, "later") && name == "modprobe"
				if target {
					deadline, _ := ctx.Deadline()
					if deadline != originalDeadline || ctx.Err() != nil || !time.Now().Before(originalDeadline) {
						t.Fatal("intended resolver not reached before SAME original deadline", cut, time.Since(started), ctx.Err())
					}
					if strings.HasPrefix(cut, "later") {
						body, e := os.ReadFile(filepath.Join(root, "utility-apt-get.json"))
						if e != nil {
							t.Fatal("later lookup lacks first actual child record", e)
						}
						var record enrollmentC1UtilityEvidence
						if json.Unmarshal(body, &record) != nil || record.PID == 0 || record.Start == "" || record.Parent != uint32(os.Getpid()) {
							t.Fatal("later lookup lacks original child identity")
						}
						body, e = os.ReadFile(filepath.Join(root, "utility-apt-get-effect.json"))
						if e != nil {
							t.Fatal("later lookup lacks first actual synced effect", e)
						}
						var effect enrollmentC1UtilityEffect
						if json.Unmarshal(body, &effect) != nil || !effect.Synced || effect.PID != record.PID || effect.Start != record.Start {
							t.Fatal("later lookup effect differs from first actual child")
						}
						// The fixed runner reaches this resolver only AFTER actual original
						// Wait. Verify that incarnation is gone, allowing proven PID reuse.
						current, e := enrollmentProcessStart(record.PID)
						if e == nil && current == record.Start || e != nil && !errors.Is(e, os.ErrNotExist) {
							t.Fatal("later lookup before original child Wait/join", record.PID, current, e)
						}
						t.Logf("ACTUAL_LATER_LOOKUP_AFTER_WAIT first_pid=%d elapsed=%s remaining_original=%s", record.PID, time.Since(started), time.Until(originalDeadline))
					}
					delayed = true
					if strings.HasSuffix(cut, "cancel") {
						cancel()
					} else {
						<-ctx.Done()
						deadline, _ := ctx.Deadline()
						if deadline != originalDeadline || !errors.Is(ctx.Err(), context.DeadlineExceeded) || time.Now().Before(originalDeadline) {
							t.Fatal("expiry cut did not use SAME actual original deadline", ctx.Err())
						}
					}
				}
				return lookup(name)
			}
			err := runEnrollmentWorkerUtilities(ctx, "prepare", execution)
			if !delayed || !errors.Is(err, ctx.Err()) || ctx.Err() == nil {
				t.Fatal("delayed lookup did not retain original cancellation/expiry", delayed, err, ctx.Err())
			}
			forbidden := "apt-get"
			if strings.HasPrefix(cut, "later") {
				forbidden = "modprobe"
				body, e := os.ReadFile(filepath.Join(root, "utility-apt-get.json"))
				if e != nil {
					t.Fatal("first actual utility did not complete before later lookup", e)
				}
				var record enrollmentC1UtilityEvidence
				if json.Unmarshal(body, &record) != nil || record.PID == 0 || record.Parent != uint32(os.Getpid()) {
					t.Fatal("first actual utility identity missing")
				}
			}
			for _, name := range []string{"utility-" + forbidden + ".json", "utility-" + forbidden + "-effect.json"} {
				if _, e := os.Lstat(filepath.Join(root, name)); !errors.Is(e, os.ErrNotExist) {
					t.Errorf("RED_DELAYED_LOOKUP_STARTED_CANCELLED_UTILITY: %s exists: %v", name, e)
				}
			}
		})
	}
}
func TestEnrollmentWorkerPositiveOracleRequiresPostACKEffects(t *testing.T) {
	root := t.TempDir()
	execution := enrollmentPositiveUtilityExecution(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runEnrollmentWorkerUtilities(ctx, "prepare", execution); err != nil {
		t.Fatal(err)
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	group := ""
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && (parts[0] == "0" && parts[1] == "" || strings.Contains(","+parts[1]+",", ",name=systemd,")) {
			group = parts[2]
		}
	}
	if _, err = enrollmentC1RequirePositiveUtilities(root, uint32(os.Getpid()), group, image); err != nil {
		t.Fatal("actual normal inert sequence rejected", err)
	}
	for _, name := range []string{"utility-apt-get.json", "utility-modprobe.json", "utility-apt-get-effect.json", "utility-modprobe-effect.json"} {
		path := filepath.Join(root, name)
		saved, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
		if _, e = enrollmentC1RequirePositiveUtilities(root, uint32(os.Getpid()), group, image); e == nil {
			t.Errorf("RED_OMITTED_UTILITY_EFFECT_ACCEPTED: %s", name)
		}
		if e = os.WriteFile(path, saved, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func enrollmentAwaitIORead(t *testing.T, ctx context.Context, needle string) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		stack := make([]byte, 256*1024)
		n := runtime.Stack(stack, true)
		if n == len(stack) {
			t.Fatal("actual goroutine read barrier exceeds bound")
		}
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, "[IO wait]") && strings.Contains(goroutine, "ReadMsgUnix") && strings.Contains(goroutine, needle) {
				t.Log("ACTUAL_RECVMSG_POLL_WAIT " + needle)
				return
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("actual recvmsg poll barrier not reached", ctx.Err())
		}
	}
}
func enrollmentBlockedReadProbe(channel *net.UnixConn, done chan<- struct {
	n, on, flags int
	err          error
}) {
	var body [64]byte
	var control [64]byte
	n, on, flags, _, err := channel.ReadMsgUnix(body[:], control[:])
	done <- struct {
		n, on, flags int
		err          error
	}{n, on, flags, err}
}
func TestEnrollmentBlockedRecvmsgTimeoutCharacterization(t *testing.T) {
	peer, receiver := enrollmentPacketPair(t)
	defer peer.Close()
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	receiver.SetReadDeadline(deadline)
	done := make(chan struct {
		n, on, flags int
		err          error
	}, 1)
	go enrollmentBlockedReadProbe(receiver, done)
	enrollmentAwaitIORead(t, ctx, "enrollmentBlockedReadProbe")
	if err := receiver.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	result := <-done
	var timeout net.Error
	t.Logf("ACTUAL_BLOCKED_RECVMSG n=%d oob=%d flags=%d err=%v", result.n, result.on, result.flags, result.err)
	if result.n != -1 || result.on != 0 || result.flags != 0 || !errors.As(result.err, &timeout) || !timeout.Timeout() || !errors.Is(result.err, os.ErrDeadlineExceeded) {
		t.Fatal("pinned blocked recvmsg timeout shape changed", result)
	}
}
func TestEnrollmentWorkerBlockedMonitorActualProcessCompletion(t *testing.T) {
	root, err := os.MkdirTemp(os.Getenv("TMPDIR"), "wm-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: filepath.Join(root, "control.sock"), Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var option error
	if err = raw.Control(func(fd uintptr) { option = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || option != nil {
		t.Fatal(err, option)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bounds, err := captureEnrollmentWorkerBounds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	effect := filepath.Join(root, "effect")
	child := exec.Command(image, "-test.v", "-test.count=1", "-test.timeout=8s", "-test.run=^TestEnrollmentWorkerGateProcess$")
	child.Env = append(os.Environ(), bounds.environment()...)
	child.Env = append(child.Env, "LITEVIRT_C1_GATE_TEST_CHILD=blocked", "LITEVIRT_C1_GATE_SOCKET="+filepath.Join(root, "control.sock"), "LITEVIRT_C1_GATE_EFFECT="+effect)
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- child.Wait() }()
	joined := false
	defer func() {
		if !joined {
			child.Process.Kill()
			waitErr := <-waited
			t.Logf("FAILED owned child cleanup pid=%d actualWait=%v output=%s", child.Process.Pid, waitErr, output.String())
		}
	}()
	deadline, _ := ctx.Deadline()
	listener.SetDeadline(deadline)
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer := enrollmentReportPeer(t, connection, false)
	if peer.Pid != int32(child.Process.Pid) {
		t.Fatal("actual child peer differs")
	}
	association := enrollmentHandoffFixture("prepare")
	claim := enrollmentLockedFile(t)
	claimPath := claim.Name()
	var state enrollmentReportState
	protocolErr := func() error {
		if e := writeEnrollmentPacket(ctx, connection, association, []*os.File{claim}); e != nil {
			return e
		}
		claim.Close()
		body, closed, e := readEnrollmentReportPacket(ctx, connection, peer)
		if e != nil {
			return e
		}
		if e = state.receive(body, closed, association); e != nil {
			return e
		}
		ready := association
		ready.Ready = true
		if e = writeEnrollmentPacket(ctx, connection, ready, nil); e != nil {
			return e
		}
		if e = state.acknowledgeGate(); e != nil {
			return e
		}
		for state != 4 {
			body, closed, e = readEnrollmentReportPacket(ctx, connection, peer)
			if e != nil {
				return e
			}
			if e = state.receive(body, closed, association); e != nil {
				return e
			}
		}
		return nil
	}()
	var waitErr error
	select {
	case waitErr = <-waited:
		joined = true
	case <-ctx.Done():
		connection.Close()
		child.Process.Kill()
		waitErr = <-waited
		joined = true
		t.Fatalf("actual original did not terminate naturally: %v", waitErr)
	}
	t.Logf("actual_blocked_monitor_child_pid=%d originalWait=%v protocol=%v output=%s", child.Process.Pid, waitErr, protocolErr, output.String())
	body, e := os.ReadFile(effect)
	if e != nil || !bytes.Contains(body, []byte("parent ACK preceded actual effect")) {
		t.Fatal("actual post-ACK effect missing", e)
	}
	probe, e := os.OpenFile(claimPath, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer probe.Close()
	if e = unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal("actual child refs survived originalWait", e)
	}
	if protocolErr != nil || waitErr != nil {
		t.Fatal("RED_BLOCKED_MONITOR_DROPPED_COMPLETION_AFTER_REAL_EFFECT", protocolErr, waitErr)
	}
}

func TestEnrollmentWorkerBlockedMonitorRetainsInvalidInputRefusal(t *testing.T) {
	for _, cut := range []string{"EOF", "empty-DATA", "extra-DATA", "rights-at-stop", "cancel", "expire"} {
		t.Run(cut, func(t *testing.T) {
			peer, receiver := enrollmentPacketPair(t)
			defer peer.Close()
			defer receiver.Close()
			duration := 3 * time.Second
			if cut == "expire" {
				duration = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			utility, cancelUtility := context.WithCancel(ctx)
			defer cancelUtility()
			finish := monitorEnrollmentParent(ctx, receiver, cancelUtility)
			enrollmentAwaitIORead(t, ctx, "monitorEnrollmentParent")
			var lockPath string
			switch cut {
			case "EOF":
				peer.Close()
			case "empty-DATA":
				if _, _, e := peer.WriteMsgUnix(nil, nil, nil); e != nil {
					t.Fatal(e)
				}
			case "extra-DATA":
				if _, _, e := peer.WriteMsgUnix([]byte("unexpected"), nil, nil); e != nil {
					t.Fatal(e)
				}
			case "rights-at-stop":
				file := enrollmentLockedFile(t)
				lockPath = file.Name()
				if _, _, e := peer.WriteMsgUnix([]byte("unexpected"), unix.UnixRights(int(file.Fd())), nil); e != nil {
					t.Fatal(e)
				}
				file.Close()
			case "cancel":
				cancel()
			case "expire":
				<-ctx.Done()
			}
			err := finish()
			if err == nil {
				t.Fatal("invalid parent input/termination classified as normal local stop", cut)
			}
			if utility.Err() == nil {
				t.Fatal("invalid parent input did not prevent next utility", cut)
			}
			if lockPath != "" {
				probe, e := os.OpenFile(lockPath, os.O_RDWR, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer probe.Close()
				if e = unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
					t.Fatal("unexpected delivered rights survived monitor refusal", e)
				}
			}
		})
	}
}
