package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type enrollmentWorkerKind string

func validateEnrollmentCapability(file *os.File, canonical string, owner uint32) error {
	if file == nil || !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical {
		return errors.New("canonical held worker capability required")
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	actual, err := os.Lstat(canonical)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || !actual.Mode().IsRegular() || !os.SameFile(info, actual) || stat.Uid != owner || info.Mode().Perm()&0022 != 0 {
		return errors.New("worker capability canonical inode/owner/type changed")
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return errors.Join(errors.New("worker capability is not CLOEXEC"), err)
	}
	fdinfo, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", file.Fd()))
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(fdinfo, 16*1024+1))
	closeErr := fdinfo.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(body) > 16*1024 {
		return errors.New("worker capability fdinfo exceeds bound")
	}
	found := 0
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 9 || fields[0] != "lock:" || fields[2] != "FLOCK" || fields[3] != "ADVISORY" || fields[4] != "WRITE" || fields[7] != "0" || fields[8] != "EOF" {
			continue
		}
		identity := strings.Split(fields[6], ":")
		if len(identity) != 3 {
			continue
		}
		major, a := strconv.ParseUint(identity[0], 16, 32)
		minor, b := strconv.ParseUint(identity[1], 16, 32)
		inode, c := strconv.ParseUint(identity[2], 10, 64)
		if a == nil && b == nil && c == nil && major == uint64(unix.Major(uint64(stat.Dev))) && minor == uint64(unix.Minor(uint64(stat.Dev))) && inode == stat.Ino {
			found++
		}
	}
	// Kernel show_fd_locks filters the actual struct file pointer, not just its
	// inode. Reopening a path held by some other OFD cannot supply this record.
	if found != 1 {
		return errors.New("descriptor does not carry the actual whole-file exclusive flock OFD")
	}
	current, err := os.Lstat(canonical)
	if err != nil || !os.SameFile(info, current) {
		return errors.Join(errors.New("canonical capability path changed after validation"), err)
	}
	return nil
}

type enrollmentWorkerBounds struct{ operation, handoff int64 }

func captureEnrollmentWorkerBounds(ctx context.Context) (enrollmentWorkerBounds, error) {
	if err := ctx.Err(); err != nil {
		return enrollmentWorkerBounds{}, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return enrollmentWorkerBounds{}, errors.New("worker requires original absolute operation deadline")
	}
	// Capture kernel time BEFORE remaining context time; elapsed work can only
	// shorten the serialized expiry, never give a later process a fresh budget.
	now, err := enrollmentMonotonicNow()
	if err != nil {
		return enrollmentWorkerBounds{}, err
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return enrollmentWorkerBounds{}, context.DeadlineExceeded
	}
	if int64(remaining) > math.MaxInt64-now {
		return enrollmentWorkerBounds{}, errors.New("worker monotonic deadline overflow")
	}
	operation := now + int64(remaining)
	handoff := operation
	if int64(10*time.Second) <= math.MaxInt64-now && now+int64(10*time.Second) < handoff {
		handoff = now + int64(10*time.Second)
	}
	return enrollmentWorkerBounds{operation: operation, handoff: handoff}, nil
}

func parseEnrollmentWorkerBounds(environment []string) (enrollmentWorkerBounds, error) {
	values := map[string]int64{}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if key != enrollmentOperationDeadlineEnv && key != enrollmentHandoffDeadlineEnv {
			continue
		}
		if !ok {
			return enrollmentWorkerBounds{}, errors.New("missing worker deadline value")
		}
		if _, duplicate := values[key]; duplicate {
			return enrollmentWorkerBounds{}, errors.New("duplicate worker deadline")
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n <= 0 || strconv.FormatInt(n, 10) != value {
			return enrollmentWorkerBounds{}, errors.New("invalid canonical worker deadline")
		}
		values[key] = n
	}
	b := enrollmentWorkerBounds{operation: values[enrollmentOperationDeadlineEnv], handoff: values[enrollmentHandoffDeadlineEnv]}
	now, err := enrollmentMonotonicNow()
	if err != nil {
		return enrollmentWorkerBounds{}, err
	}
	if b.operation <= now || b.handoff <= now || b.handoff > b.operation {
		return enrollmentWorkerBounds{}, errors.New("expired or inconsistent worker deadlines")
	}
	return b, nil
}

const enrollmentOperationDeadlineEnv = "LITEVIRT_ENROLLMENT_OPERATION_DEADLINE_NS"
const enrollmentHandoffDeadlineEnv = "LITEVIRT_ENROLLMENT_HANDOFF_DEADLINE_NS"

func enrollmentMonotonicNow() (int64, error) {
	var stamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp); err != nil {
		return 0, err
	}
	if stamp.Sec < 0 || stamp.Sec > (math.MaxInt64-stamp.Nsec)/int64(time.Second) || stamp.Nsec < 0 || stamp.Nsec >= int64(time.Second) {
		return 0, errors.New("invalid kernel monotonic clock")
	}
	return stamp.Sec*int64(time.Second) + stamp.Nsec, nil
}

func (b enrollmentWorkerBounds) environment() []string {
	return []string{enrollmentOperationDeadlineEnv + "=" + strconv.FormatInt(b.operation, 10), enrollmentHandoffDeadlineEnv + "=" + strconv.FormatInt(b.handoff, 10)}
}

func (b enrollmentWorkerBounds) context(parent context.Context, handoff bool) (context.Context, context.CancelFunc, error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	reference := time.Now()
	now, err := enrollmentMonotonicNow()
	if err != nil {
		return nil, nil, err
	}
	end := b.operation
	if handoff {
		end = b.handoff
	}
	if end <= now || b.handoff <= 0 || b.operation < b.handoff {
		return nil, nil, context.DeadlineExceeded
	}
	ctx, cancel := context.WithDeadline(parent, reference.Add(time.Duration(end-now)))
	return ctx, cancel, nil
}

type enrollmentReportState uint8

func writeEnrollmentPacket(ctx context.Context, connection *net.UnixConn, value enrollmentHandoff, files []*os.File) error {
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return errors.New("worker packet requires absolute deadline")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	want := value
	want.Ready, want.Completed = false, false
	flag := ""
	if value.Ready {
		flag = "ready"
	}
	if value.Completed {
		flag = "completed"
	}
	if _, err := decodeEnrollmentEnvelope(body, want, flag); err != nil {
		return err
	}
	expected := len(want.FDNames)
	if flag != "" {
		expected = 0
	}
	if len(files) != expected {
		return errors.New("worker packet has wrong outgoing descriptor count")
	}
	fds := make([]int, len(files))
	for i, file := range files {
		if file == nil {
			return errors.New("missing worker capability")
		}
		fds[i] = int(file.Fd())
	}
	var control []byte
	if len(fds) != 0 {
		control = unix.UnixRights(fds...)
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return err
	}
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stop:
		}
	}()
	n, oob, writeErr := connection.WriteMsgUnix(body, control, nil)
	close(stop)
	<-joined
	if ctx.Err() != nil || writeErr != nil || n != len(body) || oob != len(control) {
		_ = connection.Close()
		return errors.Join(errors.New("worker packet send outcome unknown; no replay"), ctx.Err(), writeErr)
	}
	if err := connection.SetWriteDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return err
	}
	return nil
}

func awaitEnrollmentParentGate(ctx context.Context, connection *net.UnixConn, want enrollmentHandoff) error {
	files, err := readEnrollmentPacket(ctx, connection, want, true)
	for _, file := range files {
		_ = file.Close()
	}
	if err != nil {
		_ = connection.Close()
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return err
	}
	return nil
}

func readEnrollmentReportPacket(ctx context.Context, connection *net.UnixConn, peer *unix.Ucred) (body []byte, closed bool, err error) {
	defer func() {
		if err != nil {
			_ = connection.Close()
		}
	}()
	deadline, bounded := ctx.Deadline()
	if !bounded || peer == nil {
		return nil, false, errors.New("bounded credential-bound report receive required")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, false, err
	}
	var inherited int
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		inherited, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED)
	}); err != nil || optionErr != nil || inherited != 1 {
		return nil, false, errors.Join(errors.New("parent report socket did not inherit PASSCRED"), err, optionErr)
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return nil, false, err
	}
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stop:
		}
	}()
	buffer, control := make([]byte, 4097), make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(2*4))
	n, oob, flags, _, readErr := connection.ReadMsgUnix(buffer, control)
	close(stop)
	<-joined
	messages, parseErr := unix.ParseSocketControlMessage(control[:oob])
	var received []int
	defer func() {
		for _, fd := range received {
			_ = unix.Close(fd)
		}
	}()
	credentials, foreign, matching := 0, false, false
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET {
			foreign = true
			continue
		}
		switch message.Header.Type {
		case unix.SCM_RIGHTS:
			rights, err := unix.ParseUnixRights(&message)
			if err != nil {
				parseErr = err
			} else {
				received = append(received, rights...)
			}
		case unix.SCM_CREDENTIALS:
			credentials++
			credential, err := unix.ParseUnixCredentials(&message)
			if err != nil {
				parseErr = err
			} else if *credential == *peer {
				matching = true
			}
		default:
			foreign = true
		}
	}
	// Parse and close every delivered right BEFORE interpreting even wrappedEOF.
	if parseErr != nil || foreign || len(received) != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > 4096 {
		return nil, false, errors.New("invalid worker report ancillary/size")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if n == 0 && oob == 0 && errors.Is(readErr, io.EOF) {
		return nil, true, nil
	}
	if credentials != 1 || !matching {
		return nil, false, errors.New("worker DATA lacks exact actual peer credentials")
	}
	if readErr != nil && !(n == 0 && errors.Is(readErr, io.EOF)) {
		return nil, false, readErr
	}
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return nil, false, err
	}
	return buffer[:n], false, nil // zero DATA with credentials is DATA, never close
}

func (s *enrollmentReportState) receive(body []byte, closed bool, want enrollmentHandoff) error {
	fail := func() error { *s = 5; return errors.New("worker report order/association or termination invalid") }
	switch *s {
	case 0:
		if closed {
			return fail()
		}
		if _, err := decodeEnrollmentHandoff(body, want, true); err != nil {
			return fail()
		}
		*s = 1
		return nil
	case 2:
		if closed {
			return fail()
		}
		if _, err := decodeEnrollmentCompletion(body, want); err != nil {
			return fail()
		}
		*s = 3
		return nil
	case 3:
		if !closed || len(body) != 0 {
			return fail()
		}
		*s = 4
		return nil // report stream only; physical custody gates remain
	default:
		return fail()
	}
}

func (s *enrollmentReportState) acknowledgeGate() error {
	if *s != 1 {
		*s = 5
		return errors.New("worker parent gate out of order")
	}
	*s = 2
	return nil
}

type enrollmentHandoff struct {
	Version   int                  `json:"v"`
	Attempt   string               `json:"attempt"`
	Unit      string               `json:"unit"`
	Kind      enrollmentWorkerKind `json:"kind"`
	FDNames   []string             `json:"fd_names"`
	Ready     bool                 `json:"ready,omitempty"`
	Completed bool                 `json:"completed,omitempty"`
}

func decodeEnrollmentCompletion(raw []byte, want enrollmentHandoff) (enrollmentHandoff, error) {
	return decodeEnrollmentEnvelope(raw, want, "completed")
}

func enrollmentAttemptValid(attempt string) bool {
	if len(attempt) != 12 {
		return false
	}
	for _, c := range attempt {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func enrollmentFDNames(kind enrollmentWorkerKind) []string {
	switch kind {
	case "prepare":
		return []string{"claim"}
	case "apparmor":
		return []string{"claim", "pki-ex"}
	default:
		return nil
	}
}

func decodeEnrollmentHandoff(raw []byte, want enrollmentHandoff, ack bool) (enrollmentHandoff, error) {
	flag := ""
	if ack {
		flag = "ready"
	}
	return decodeEnrollmentEnvelope(raw, want, flag)
}

func decodeEnrollmentEnvelope(raw []byte, want enrollmentHandoff, flag string) (enrollmentHandoff, error) {
	fail := func() (enrollmentHandoff, error) {
		return enrollmentHandoff{}, errors.New("invalid enrollment handoff association")
	}
	if len(raw) > 4096 || !utf8.Valid(raw) || want.Version != 1 || !enrollmentAttemptValid(want.Attempt) {
		return fail()
	}
	names := enrollmentFDNames(want.Kind)
	if names == nil || !slices.Equal(names, want.FDNames) {
		return fail()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return fail()
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return fail()
		}
		switch key {
		case "v", "attempt", "unit", "kind", "fd_names":
		case "ready", "completed":
			if key != flag {
				return fail()
			}
		default:
			return fail()
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return fail()
		}
	}
	last, err := decoder.Token()
	var extra any
	if err != nil || last != json.Delim('}') || decoder.Decode(&extra) != io.EOF || len(seen) != 5+boolEnrollment(flag != "") {
		return fail()
	}
	var got enrollmentHandoff
	if json.Unmarshal(raw, &got) != nil || got.Version != 1 || got.Attempt != want.Attempt || got.Unit != want.Unit ||
		got.Kind != want.Kind || !slices.Equal(got.FDNames, names) || got.Ready != (flag == "ready") || got.Completed != (flag == "completed") {
		return fail()
	}
	return got, nil
}

func boolEnrollment(value bool) int {
	if value {
		return 1
	}
	return 0
}

// Go1.26's Linux UnixConn.ReadMsgUnix uses MSG_CMSG_CLOEXEC in the actual
// recvmsg syscall. Never receive plain descriptors and repair CLOEXEC later.
func readEnrollmentPacket(ctx context.Context, c *net.UnixConn, want enrollmentHandoff, ack bool) ([]*os.File, error) {
	deadline := time.Now().Add(10 * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	if err := c.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-stop:
		}
	}()
	body, control := make([]byte, 4097), make([]byte, unix.CmsgSpace(2*4))
	n, oob, flags, _, readErr := c.ReadMsgUnix(body, control)
	close(stop)
	<-joined
	_ = c.SetReadDeadline(time.Time{})
	var fds []int
	ok := false
	defer func() {
		if !ok {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}
	}()
	messages, parseErr := unix.ParseSocketControlMessage(control[:oob])
	foreign := false
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			foreign = true
			continue
		}
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			parseErr = err
			continue
		}
		fds = append(fds, rights...)
	}
	expected := len(want.FDNames)
	if ack {
		expected = 0
	}
	if readErr != nil || parseErr != nil || foreign || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > 4096 || len(fds) != expected {
		return nil, errors.New("invalid enrollment descriptor packet")
	}
	if _, err := decodeEnrollmentHandoff(body[:n], want, ack); err != nil {
		return nil, err
	}
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		files[i] = os.NewFile(uintptr(fd), want.FDNames[i])
	}
	ok = true
	return files, nil
}

type enrollmentWorkerStage struct {
	directory *os.File
	path      string
	identity  os.FileInfo
	socket    os.FileInfo
}

func openEnrollmentWorkerStage(path string, owner uint32) (*enrollmentWorkerStage, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("canonical absolute existing staging required")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return nil, errors.Join(errors.New("staging symlink or unknown parent"), err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "enrollment-held-stage")
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || stat.Uid != owner {
		file.Close()
		return nil, errors.New("staging must be owned directory0700")
	}
	stage := &enrollmentWorkerStage{directory: file, path: path, identity: info}
	if err = stage.validate(); err != nil {
		file.Close()
		return nil, err
	}
	return stage, nil
}
func (s *enrollmentWorkerStage) validate() error {
	current, err := os.Lstat(s.path)
	if err != nil || !current.IsDir() || !os.SameFile(current, s.identity) || current.Mode().Perm() != 0700 {
		return errors.Join(errors.New("held staging identity changed"), err)
	}
	return nil
}
func (s *enrollmentWorkerStage) address() string {
	return fmt.Sprintf("/proc/self/fd/%d/control.sock", s.directory.Fd())
}
func (s *enrollmentWorkerStage) listen() (*net.UnixListener, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.address()); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Join(errors.New("existing control socket/artifact refuses replacement"), err)
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: s.address(), Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	s.socket, err = os.Lstat(s.address())
	if err != nil {
		listener.Close()
		return nil, err
	}
	raw, err := listener.SyscallConn()
	if err == nil {
		var inner error
		err = raw.Control(func(fd uintptr) { inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) })
		err = errors.Join(err, inner)
	}
	if err != nil {
		listener.Close()
		return nil, errors.Join(err, s.removeSocket())
	}
	return listener, nil
}
func (s *enrollmentWorkerStage) removeSocket() error {
	if s.socket == nil {
		return errors.New("no owned socket binding")
	}
	if err := s.validate(); err != nil {
		return err
	}
	info, err := os.Lstat(s.address())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || !os.SameFile(info, s.socket) {
		return errors.New("foreign control socket/artifact preserved")
	}
	if err = os.Remove(s.address()); err != nil {
		return err
	}
	return s.directory.Sync()
}
func (s *enrollmentWorkerStage) close() error { return s.directory.Close() }
func storeEnrollmentCapabilities(ctx context.Context, address string, names []string, files []*os.File) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("FD store requires original absolute deadline")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(files) < 1 || len(files) > 2 || len(files) != len(names) || names[0] != "claim" || len(names) == 2 && names[1] != "pki-ex" {
		return errors.New("invalid named worker store association")
	}
	for _, f := range files {
		if f == nil {
			return errors.New("nil worker store capability")
		}
	}
	if address == "" || address[0] != '/' && address[0] != '@' {
		return errors.New("missing actual manager notify socket")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unixgram", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	notify, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("notify is not Unix datagram")
	}
	if err = notify.SetWriteDeadline(deadline); err != nil {
		return err
	}
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			notify.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-joined }()
	for i, name := range names {
		if err = ctx.Err(); err != nil {
			return err
		}
		body := []byte("FDSTORE=1\nFDNAME=" + name)
		rights := unix.UnixRights(int(files[i].Fd()))
		// Go UnixConn.WriteMsgUnix refuses connected SOCK_DGRAM even with nil
		// destination. Use this owned pollable socket's raw Write so the same
		// actual deadline/cancellation still interrupts a stalled sendmsg.
		raw, rawErr := notify.SyscallConn()
		n := 0
		var sendErr error
		if rawErr == nil {
			rawErr = raw.Write(func(fd uintptr) bool {
				n, sendErr = unix.SendmsgN(int(fd), body, rights, nil, unix.MSG_NOSIGNAL)
				return sendErr != unix.EAGAIN && sendErr != unix.EWOULDBLOCK
			})
		}
		e := errors.Join(rawErr, sendErr)
		if e != nil || n != len(body) {
			return errors.Join(errors.New("FDSTORE submission outcome unknown; no replay"), e)
		}
	}
	return ctx.Err()
}

func enrollmentSocketPeer(connection *net.UnixConn) (*unix.Ucred, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *unix.Ucred
	var inner error
	if err = raw.Control(func(fd uintptr) { peer, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, err
	}
	return peer, inner
}

// Observe only this retained known unit, on the actual systemd hierarchy. A
// missing v2 events file on a still-existing group is UNKNOWN, never empty.
func enrollmentWorkerCgroupEmpty(unit, group string) (bool, error) {
	if err := enrollmentMainGroup(unit, group); err != nil {
		return false, err
	}
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false, err
	}
	unified := false
	for _, line := range strings.Split(string(membership), "\n") {
		if strings.HasPrefix(line, "0::") {
			unified = true
		}
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	directory, err := enrollmentCgroupDirectory(mounts, group, unified)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, errors.New("known cgroup directory changed type")
	}
	if unified {
		body, err := os.ReadFile(filepath.Join(directory, "cgroup.events"))
		if errors.Is(err, os.ErrNotExist) {
			if _, gone := os.Lstat(directory); errors.Is(gone, os.ErrNotExist) {
				return true, nil
			}
		}
		if err != nil {
			return false, err
		}
		return enrollmentCgroupPopulation(body)
	}
	// Legacy systemd named hierarchy: every descendant's cgroup.procs must be
	// observed empty. This is a known-unit subtree, not a host process census.
	empty, visited := true, 0
	err = filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > 16384 {
			return errors.New("known cgroup subtree exceeds observation bound")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in known cgroup subtree")
		}
		if !entry.IsDir() {
			return nil
		}
		file, err := os.Open(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			return err
		}
		body, e := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		e = errors.Join(e, file.Close())
		if e != nil {
			return e
		}
		if len(body) > 1024*1024 {
			return errors.New("known group membership exceeds bound")
		}
		for _, pid := range strings.Fields(string(body)) {
			if _, err := strconv.ParseUint(pid, 10, 32); err != nil {
				return errors.New("malformed known group membership")
			}
			empty = false
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		if _, gone := os.Lstat(directory); errors.Is(gone, os.ErrNotExist) {
			return true, nil
		}
	}
	return empty && err == nil, err
}
func enrollmentCgroupDirectory(mountinfo []byte, group string, unified bool) (string, error) {
	for _, line := range strings.Split(string(mountinfo), "\n") {
		columns := strings.Fields(line)
		separator := -1
		for i, c := range columns {
			if c == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || len(columns) < separator+4 {
			continue
		}
		fstype, options := columns[separator+1], columns[separator+3]
		if unified && fstype != "cgroup2" || !unified && (fstype != "cgroup" || !strings.Contains(","+options+",", ",name=systemd,")) {
			continue
		}
		decode := func(s string) string {
			return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
		}
		root, mount := decode(columns[3]), decode(columns[4])
		if !filepath.IsAbs(root) || !filepath.IsAbs(mount) || filepath.Clean(root) != root || filepath.Clean(mount) != mount {
			return "", errors.New("noncanonical systemd cgroup mount")
		}
		relative, err := filepath.Rel(root, group)
		if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
			return "", errors.New("known group outside actual systemd mount root")
		}
		return filepath.Join(mount, relative), nil
	}
	return "", errors.New("actual systemd cgroup hierarchy is unknown")
}

// The post-gate monitor uses the ORIGINAL operation deadline, not the handoff
// reader's ten-second bound. It never treats EOF/empty DATA as completion.
func monitorEnrollmentParent(ctx context.Context, channel *net.UnixConn, cancel context.CancelFunc) func() error {
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return func() error { cancel(); return errors.New("parent monitor requires original deadline") }
	}
	if err := channel.SetReadDeadline(deadline); err != nil {
		return func() error { cancel(); return err }
	}
	done := make(chan error, 1)
	stop := make(chan struct{})
	var once sync.Once
	var result error
	go func() {
		var body [4097]byte
		control := make([]byte, unix.CmsgSpace(2*4))
		ctxStop, ctxJoined := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(ctxJoined)
			select {
			case <-ctx.Done():
				channel.Close()
			case <-ctxStop:
			}
		}()
		n, on, flags, _, readErr := channel.ReadMsgUnix(body[:], control)
		close(ctxStop)
		<-ctxJoined
		ancillaryErr := closeEnrollmentUnexpectedRights(control[:on])
		select {
		case <-stop:
			// prepareRead returns zero counts, whereas recvmsg EAGAIN followed by
			// poll timeout preserves n=-1 in the pinned Go implementation. Neither
			// is DATA or EOF. Only our live-context local stop may use this exception.
			if (n == 0 || n == -1) && on == 0 && flags == 0 && ancillaryErr == nil && errors.Is(readErr, os.ErrDeadlineExceeded) && ctx.Err() == nil && time.Now().Before(deadline) {
				// A deadline wakeup may precede a queued packet in Go's netpoller. Probe
				// this SAME socket nonblocking before accepting the local stop request.
				raw, e := channel.SyscallConn()
				var probeErr error
				if e == nil {
					e = raw.Control(func(fd uintptr) {
						pn, po, pf, _, pe := unix.Recvmsg(int(fd), body[:], control, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
						if pe == unix.EAGAIN || pe == unix.EWOULDBLOCK {
							return
						}
						probeErr = errors.Join(errors.New("parent closed or sent extra data during monitor stop"), pe, closeEnrollmentUnexpectedRights(control[:po]))
						_ = pn
						_ = pf
					})
				}
				if e == nil && probeErr == nil {
					done <- channel.SetReadDeadline(time.Time{})
					return
				}
				readErr = errors.Join(readErr, e, probeErr)
			}
		default:
		}
		cancel()
		done <- errors.Join(errors.New("parent retirement or extra packet prevents subsequent utility"), readErr, ancillaryErr, ctx.Err())
	}()
	return func() error {
		once.Do(func() { close(stop); e := channel.SetReadDeadline(time.Now()); result = errors.Join(e, <-done) })
		return result
	}
}
func closeEnrollmentUnexpectedRights(control []byte) error {
	messages, err := unix.ParseSocketControlMessage(control)
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
			fds, e := unix.ParseUnixRights(&message)
			err = errors.Join(err, e)
			for _, fd := range fds {
				err = errors.Join(err, unix.Close(fd))
			}
		}
	}
	return err
}
