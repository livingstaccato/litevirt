package pki

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const nativeProcessAckLimit = 1024

// This helper is inert in a direct test inventory. FD3 carries acknowledgements,
// never PEM bytes; stdin is a bounded parent-controlled start/release barrier.
func TestOperatorCANativeProcessHelper(t *testing.T) {
	mode := os.Getenv("LITEVIRT_NATIVE_PROCESS_MODE")
	if mode == "" {
		return
	}
	dir := os.Getenv("LITEVIRT_NATIVE_PROCESS_DIR")
	ack := os.NewFile(3, "native-ca-ack")
	defer ack.Close()
	input := bufio.NewReaderSize(os.Stdin, nativeProcessAckLimit+1)
	send := func(event string) {
		if len(event) >= nativeProcessAckLimit || strings.ContainsAny(event, "\r\n\x00") {
			t.Fatal("invalid or oversized native process acknowledgement")
		}
		if _, err := fmt.Fprintln(ack, event); err != nil {
			t.Fatal(err)
		}
	}
	hold := func() {
		if line, err := readNativeProcessLine(input); err != nil || line != "release" {
			t.Fatalf("parent release: %q %v", line, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if strings.HasPrefix(mode, "assignment-") {
		runNativeAssignmentProcess(t, ctx, mode, dir, os.Getenv("LITEVIRT_NATIVE_PROCESS_STAGE"), send, hold)
		return
	}
	if mode == "domain" {
		lease, err := AcquireHostDomain(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Release()
		send("domain-held")
		hold()
		return
	}
	stage := os.Getenv("LITEVIRT_NATIVE_PROCESS_STAGE")
	trustDurabilitySeam = func(at string) error {
		if mode == "creator" && at == "native-ca:staged" {
			send("generated")
		}
		// A reopen is immediately after the real atomic rename. The generic
		// seam has no path, so distinguish the exact active file by existence:
		// no record / record only / key without root / root already visible.
		record := nativeProcessExists(dir, ".operator-ca-operation")
		key := nativeProcessExists(dir, "ca.key")
		root := nativeProcessExists(dir, "ca.crt")
		matched := at == stage
		switch stage {
		case "record-renamed":
			matched = at == "reopen" && record && !key && !root
		case "key-before-rename":
			matched = at == "rename" && record && !key && !root
		case "key-renamed", "key-file-sync", "key-directory-sync":
			point := map[string]string{"key-renamed": "reopen", "key-file-sync": "file-sync", "key-directory-sync": "directory-sync"}[stage]
			matched = at == point && record && key && !root
		case "root-renamed":
			matched = at == "reopen" && record && key && root
		}
		if mode == "boundary" && matched {
			send("boundary:" + stage)
			hold()
			t.Fatal("kill boundary unexpectedly released")
		}
		return nil
	}
	if mode == "creator" {
		send("ready")
		hold()
		send("request")
	}
	if err := InitializeOperatorCA(ctx, dir); err != nil {
		t.Fatal(err)
	}
	record, cert, key := inspectNativeCA(t, dir)
	assertNativePublishedPair(t, dir, cert, key)
	send(fmt.Sprintf("result:%x:%x:%x", sha256.Sum256(record), sha256.Sum256(cert), sha256.Sum256(key)))
}

func nativeProcessExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

type nativeCAProcess struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	ack    *os.File
	reader *bufio.Reader
	output nativeProcessOutput
	done   chan struct{}
	err    error
}

// The same bounded capture is used by the existing and assignment helpers.
// Discard excess bytes so a noisy child cannot block its own cleanup; joined
// and cleanup both treat overflow as a test failure.
type nativeProcessOutput struct {
	mu       sync.Mutex
	body     bytes.Buffer
	overflow bool
}

func (b *nativeProcessOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := (64 << 10) - b.body.Len()
	if len(p) > remaining {
		b.overflow = true
	}
	if remaining > len(p) {
		remaining = len(p)
	}
	if remaining > 0 {
		_, _ = b.body.Write(p[:remaining])
	}
	return len(p), nil
}

func (b *nativeProcessOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.body.String()
}

func (b *nativeProcessOutput) exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

func readNativeProcessLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(line) > nativeProcessAckLimit || bytes.ContainsAny(line, "\r\x00") {
		return "", errors.New("invalid or oversized native process line")
	}
	return strings.TrimSuffix(string(line), "\n"), nil
}

func startNativeCAProcess(t *testing.T, mode, dir, stage string, extraEnv ...string) *nativeCAProcess {
	t.Helper()
	ack, childAck, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	p := &nativeCAProcess{ack: ack, reader: bufio.NewReaderSize(ack, nativeProcessAckLimit+1), done: make(chan struct{})}
	p.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOperatorCANativeProcessHelper$", "-test.timeout=18s")
	p.cmd.Env = append(os.Environ(), "LITEVIRT_NATIVE_PROCESS_MODE="+mode, "LITEVIRT_NATIVE_PROCESS_DIR="+dir, "LITEVIRT_NATIVE_PROCESS_STAGE="+stage)
	p.cmd.Env = append(p.cmd.Env, extraEnv...)
	p.cmd.ExtraFiles = []*os.File{childAck}
	p.cmd.Stdout, p.cmd.Stderr = &p.output, &p.output
	p.input, err = p.cmd.StdinPipe()
	if err != nil {
		cancel()
		ack.Close()
		childAck.Close()
		t.Fatal(err)
	}
	if err := p.cmd.Start(); err != nil {
		cancel()
		p.input.Close()
		ack.Close()
		childAck.Close()
		t.Fatal(err)
	}
	childAck.Close()
	// Only this goroutine ever consumes the original Wait. Cleanup and normal
	// assertions join the same completion channel, including after a fatal.
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		p.input.Close()
		cancel()
		select {
		case <-p.done:
			t.Logf("child-reaped pid=%d state=%s error=%v output=%q", p.cmd.Process.Pid, p.cmd.ProcessState, p.err, p.output.String())
		case <-time.After(5 * time.Second):
			t.Error("owned native CA child did not reap")
		}
		ack.Close()
		if p.output.exceeded() {
			t.Error("native CA child output exceeded 64KiB")
		}
	})
	t.Logf("child-start mode=%s stage=%s pid=%d", mode, stage, p.cmd.Process.Pid)
	return p
}

func (p *nativeCAProcess) event(t *testing.T) string {
	t.Helper()
	if err := p.ack.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := readNativeProcessLine(p.reader)
	if err != nil {
		t.Fatalf("child %d acknowledgement: %v", p.cmd.Process.Pid, err)
	}
	t.Logf("child-ack pid=%d %s", p.cmd.Process.Pid, line)
	return line
}

func (p *nativeCAProcess) expect(t *testing.T, want string) {
	t.Helper()
	if got := p.event(t); got != want {
		t.Fatalf("child acknowledgement %q, want %q", got, want)
	}
}

func (p *nativeCAProcess) release(t *testing.T) {
	t.Helper()
	if _, err := io.WriteString(p.input, "release\n"); err != nil {
		t.Fatal(err)
	}
}

func (p *nativeCAProcess) joined(t *testing.T, killed bool) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Fatal("owned child did not exit")
	}
	t.Logf("child-exit pid=%d state=%s error=%v output=%q", p.cmd.Process.Pid, p.cmd.ProcessState, p.err, p.output.String())
	if p.output.exceeded() {
		t.Fatal("native CA child output exceeded 64KiB")
	}
	if killed {
		var exit *exec.ExitError
		if !errors.As(p.err, &exit) {
			t.Fatalf("SIGKILL child returned %v", p.err)
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("child did not die from external SIGKILL: %v", exit)
		}
	} else if p.err != nil {
		t.Fatal("child failed", p.err)
	}
}

func killNativeCAAt(t *testing.T, dir, stage string) {
	t.Helper()
	p := startNativeCAProcess(t, "boundary", dir, stage)
	p.expect(t, "boundary:"+stage)
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	p.joined(t, true)
}

func assertNativePublishedPair(t *testing.T, dir string, cert, key []byte) {
	t.Helper()
	for name, want := range map[string][]byte{"ca.crt": cert, "ca.key": key} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("active pair differs from retained operation", name, err)
		}
	}
}

func TestOperatorCANativeSimultaneousCreatorProcesses(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	var children []*nativeCAProcess
	for _, path := range []string{dir, alias, dir, alias} {
		p := startNativeCAProcess(t, "creator", path, "")
		children = append(children, p)
		p.expect(t, "ready")
	}
	for _, p := range children {
		p.release(t)
	}
	generated := 0
	var result string
	for _, p := range children {
		p.expect(t, "request")
		event := p.event(t)
		if event == "generated" {
			generated++
			event = p.event(t)
		}
		if !strings.HasPrefix(event, "result:") || result != "" && event != result {
			t.Fatalf("creators disagree on independently decoded operation/pair: %q", event)
		}
		result = event
		p.joined(t, false)
	}
	if generated != 1 {
		t.Fatalf("actual source generated %d roots, want exactly one", generated)
	}
	record, cert, key := inspectNativeCA(t, dir)
	if want := fmt.Sprintf("result:%x:%x:%x", sha256.Sum256(record), sha256.Sum256(cert), sha256.Sum256(key)); result != want {
		t.Fatal("parent and independent creators disagree")
	}
	assertNativePublishedPair(t, dir, cert, key)
}

func TestOperatorCANativeExternalKillResume(t *testing.T) {
	for _, stage := range []string{"record-renamed", "native-ca:record-committed", "key-before-rename", "key-renamed", "key-file-sync", "key-directory-sync", "native-ca:key-published", "root-renamed", "native-ca:root-published"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			killNativeCAAt(t, dir, stage)
			record, cert, key := inspectNativeCA(t, dir)
			wantKey := stage != "record-renamed" && stage != "native-ca:record-committed" && stage != "key-before-rename"
			wantRoot := stage == "root-renamed" || stage == "native-ca:root-published"
			for name, want := range map[string]bool{"ca.key": wantKey, "ca.crt": wantRoot} {
				if got := nativeProcessExists(dir, name); got != want {
					t.Fatalf("boundary %s visibility %s=%v want %v", stage, name, got, want)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := InitializeOperatorCA(ctx, dir); err != nil {
				t.Fatal("exact committed retry refused", err)
			}
			again, againCert, againKey := inspectNativeCA(t, dir)
			if !bytes.Equal(record, again) || !bytes.Equal(cert, againCert) || !bytes.Equal(key, againKey) {
				t.Fatal("SIGKILL retry changed retained operation/pair")
			}
			assertNativePublishedPair(t, dir, cert, key)
		})
	}
}

func TestOperatorCANativeExternalKillUncommittedRefuses(t *testing.T) {
	dir := t.TempDir()
	killNativeCAAt(t, dir, "native-ca:staged")
	cert, err := os.ReadFile(filepath.Join(dir, ".operator-ca-native", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, ".operator-ca-native", "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := InitializeOperatorCA(ctx, dir); err == nil {
		t.Fatal("pre-record crash gained publication authority")
	}
	for name, want := range map[string][]byte{"ca.crt": cert, "ca.key": key} {
		got, err := os.ReadFile(filepath.Join(dir, ".operator-ca-native", name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("refusal changed uncommitted staged pair", name, err)
		}
	}
	for _, name := range []string{"ca.crt", "ca.key", ".operator-ca-operation"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("pre-record refusal published active evidence", name, err)
		}
	}
}

func TestOperatorCANativePendingPublicationExcludedByDomainProcess(t *testing.T) {
	dir := t.TempDir()
	killNativeCAAt(t, dir, "native-ca:record-committed")
	record, cert, key := inspectNativeCA(t, dir)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	p := startNativeCAProcess(t, "domain", dir, "")
	p.expect(t, "domain-held")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err := InitializeOperatorCA(ctx, alias)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held actual domain did not exclude pending publication: %v", err)
	}
	again, againCert, againKey := inspectNativeCA(t, dir)
	if !bytes.Equal(record, again) || !bytes.Equal(cert, againCert) || !bytes.Equal(key, againKey) {
		t.Fatal("excluded retry changed retained operation/pair")
	}
	for _, name := range []string{"ca.crt", "ca.key"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("excluded retry published active file", name, err)
		}
	}
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	p.joined(t, true)
	retry, retryCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer retryCancel()
	if err := InitializeOperatorCA(retry, alias); err != nil {
		t.Fatal("pending publication did not progress after domain death/reap", err)
	}
	again, againCert, againKey = inspectNativeCA(t, dir)
	if !bytes.Equal(record, again) || !bytes.Equal(cert, againCert) || !bytes.Equal(key, againKey) {
		t.Fatal("post-domain retry changed retained operation/pair")
	}
	assertNativePublishedPair(t, dir, cert, key)
}

type nativeProcessReservation struct {
	Version            int
	Purpose            string `asn1:"utf8"`
	Operation, Binding []byte
}

type nativeProcessBinding struct {
	Version                 int
	Purpose                 string `asn1:"utf8"`
	Root, ID                []byte
	Host, PKI, Data, Config string `asn1:"utf8"`
}

type nativeProcessAssignment struct {
	record, root []byte
	assignment   nativeAssignmentTestWire
	binding      nativeProcessBinding
}

func nativeProcessRead(t *testing.T, path string, bound int) []byte {
	t.Helper()
	body, err := readNativeCAFile(path, bound)
	if err != nil {
		t.Fatal("bounded native process evidence read", err)
	}
	return body
}

func nativeProcessRequest(t *testing.T, path string) nativeProcessReservation {
	t.Helper()
	body := nativeProcessRead(t, path, 8192)
	var r nativeProcessReservation
	rest, err := asn1.Unmarshal(body, &r)
	canonical, marshalErr := asn1.Marshal(r)
	if err != nil || marshalErr != nil || len(rest) != 0 || !bytes.Equal(canonical, body) || r.Version != 1 || r.Purpose != "litevirt/native-enrollment-reservation" || len(r.Operation) != 32 || bytes.Equal(r.Operation, make([]byte, 32)) {
		t.Fatal("invalid actual native process reservation")
	}
	return r
}

// Independently decode the actual retained checkpoint and signed projection.
// The expected values come from exact read bytes and parsed X509, not the
// production assignment codec or a caller-inserted successful record.
func inspectNativeProcessAssignment(t *testing.T, dir string, original []byte) *nativeProcessAssignment {
	t.Helper()
	record := nativeProcessRead(t, filepath.Join(dir, ".operator-ca-operation"), (2<<20)+(16<<10))
	if len(record) <= 104 || string(record[:8]) != "LVNCA002" {
		t.Fatal("actual assignment checkpoint is missing")
	}
	var a nativeAssignmentTestWire
	rest, err := asn1.Unmarshal(record[8:], &a)
	canonical, marshalErr := asn1.Marshal(a)
	if err != nil || marshalErr != nil || len(rest) != 0 || !bytes.Equal(canonical, record[8:]) || a.Version != 2 || a.Purpose != "litevirt/native-first-member-assignment" || len(a.Original) != 104 || string(a.Original[:8]) != "LVNCA001" || !bytes.Equal(a.Operation, a.Original[8:40]) || bytes.Equal(a.Operation, make([]byte, 32)) {
		t.Fatal("invalid independently decoded assignment")
	}
	if original != nil && !bytes.Equal(original, a.Original) {
		t.Fatal("assignment changed actual original A104")
	}
	h := sha256.Sum256(a.Original)
	if !bytes.Equal(a.OriginalHash, h[:]) {
		t.Fatal("original A104 hash mismatch")
	}
	root := nativeProcessRead(t, filepath.Join(dir, ".operator-ca-native", "ca.crt"), 1<<20)
	rootKey := nativeProcessRead(t, filepath.Join(dir, ".operator-ca-native", "ca.key"), 1<<20)
	for name, want := range map[string][]byte{"ca.crt": root, "ca.key": rootKey} {
		if !bytes.Equal(nativeProcessRead(t, filepath.Join(dir, name), 1<<20), want) {
			t.Fatal("active native pair changed", name)
		}
	}
	rh, kh := sha256.Sum256(root), sha256.Sum256(rootKey)
	if !bytes.Equal(a.Original[40:72], rh[:]) || !bytes.Equal(a.Original[72:], kh[:]) {
		t.Fatal("original A104 no longer pins root/key")
	}
	rootBlock, rootTail := pem.Decode(root)
	if rootBlock == nil || rootBlock.Type != "CERTIFICATE" || len(rootBlock.Headers) != 0 || len(bytes.TrimSpace(rootTail)) != 0 {
		t.Fatal("invalid exact native root PEM")
	}
	ca, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil {
		t.Fatal("actual root is not self-signed", err)
	}
	if _, err := tls.X509KeyPair(root, rootKey); err != nil {
		t.Fatal("actual root key mismatch", err)
	}
	block, tail := pem.Decode(a.Certificate)
	if len(a.Certificate) > 1<<20 || len(a.PrivateKey) > 1<<20 || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 {
		t.Fatal("invalid retained native leaf")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.IsCA || leaf.CheckSignatureFrom(ca) != nil || leaf.Subject.CommonName != a.Host {
		t.Fatal("actual native leaf signature/host mismatch", err)
	}
	if _, err := tls.X509KeyPair(a.Certificate, a.PrivateKey); err != nil {
		t.Fatal("actual retained keypair mismatch", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		explicit := false
		for _, u := range leaf.ExtKeyUsage {
			if u == usage {
				explicit = true
			}
		}
		if !explicit {
			t.Fatal("native leaf lacks explicit usage")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			t.Fatal("native leaf is not current signed enrollment", err)
		}
	}
	rd, spki, ch, kd := sha256.Sum256(ca.Raw), sha256.Sum256(leaf.RawSubjectPublicKeyInfo), sha256.Sum256(a.Certificate), sha256.Sum256(a.PrivateKey)
	if !bytes.Equal(a.Root, rd[:]) || leaf.SerialNumber.Sign() <= 0 || len(a.Serial) == 0 || len(a.Serial) > 20 || a.Serial[0] == 0 || !bytes.Equal(a.Serial, leaf.SerialNumber.Bytes()) || !bytes.Equal(a.SPKI, spki[:]) || !bytes.Equal(a.CertificateHash, ch[:]) || !bytes.Equal(a.KeyHash, kd[:]) {
		t.Fatal("retained native identity pins mismatch")
	}
	var b nativeProcessBinding
	rest, err = asn1.Unmarshal(a.Destination, &b)
	canonical, marshalErr = asn1.Marshal(b)
	if err != nil || marshalErr != nil || len(rest) != 0 || len(a.Destination) > 4096 || !bytes.Equal(canonical, a.Destination) || b.Version != 1 || b.Purpose != "litevirt/native-enrollment-destination" || !bytes.Equal(b.Root, rd[:]) || len(b.ID) != 32 || bytes.Equal(b.ID, make([]byte, 32)) || b.Host != a.Host || b.PKI == "" || b.Data == "" || b.Config == "" {
		t.Fatal("retained native destination mismatch")
	}
	var auth struct {
		Version                   int
		Purpose                   string `asn1:"utf8"`
		Operation, Root           []byte
		Host                      string `asn1:"utf8"`
		Destination, Serial, SPKI []byte
	}
	count := 0
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 61117, 1, 3}) {
			continue
		}
		count++
		rest, err = asn1.Unmarshal(ext.Value, &auth)
		canonical, marshalErr = asn1.Marshal(auth)
		if err != nil || marshalErr != nil || len(rest) != 0 || len(ext.Value) > 8192 || !bytes.Equal(canonical, ext.Value) || ext.Critical || auth.Version != 1 || auth.Purpose != "litevirt/initial-native-member" || !bytes.Equal(auth.Operation, a.Operation) || !bytes.Equal(auth.Root, a.Root) || auth.Host != a.Host || !bytes.Equal(auth.Destination, a.Destination) || !bytes.Equal(auth.Serial, a.Serial) || !bytes.Equal(auth.SPKI, a.SPKI) {
			t.Fatal("real signed native authorization mismatch")
		}
	}
	if count != 1 {
		t.Fatal("native assignment requires exactly one signed authorization")
	}
	var ref struct {
		Version                                          int
		Purpose                                          string `asn1:"utf8"`
		Operation, Root, Destination, Serial, SPKI, Leaf []byte
	}
	rest, err = asn1.Unmarshal(a.Reference, &ref)
	canonical, marshalErr = asn1.Marshal(ref)
	if err != nil || marshalErr != nil || len(rest) != 0 || len(a.Reference) > 8192 || !bytes.Equal(canonical, a.Reference) || ref.Version != 1 || ref.Purpose != "litevirt/native-enrollment-assignment-ref" || !bytes.Equal(ref.Operation, a.Operation) || !bytes.Equal(ref.Root, a.Root) || !bytes.Equal(ref.Destination, a.Destination) || !bytes.Equal(ref.Serial, a.Serial) || !bytes.Equal(ref.SPKI, a.SPKI) || !bytes.Equal(ref.Leaf, ch[:]) {
		t.Fatal("native assignment public reference mismatch")
	}
	return &nativeProcessAssignment{record: record, root: root, assignment: a, binding: b}
}

func nativeAssignmentProcessResult(v *nativeProcessAssignment) string {
	return fmt.Sprintf("result:%x:%x:%x:%x:%x", sha256.Sum256(v.record), sha256.Sum256(v.assignment.Certificate), sha256.Sum256(v.assignment.PrivateKey), sha256.Sum256(v.assignment.Destination), sha256.Sum256(v.assignment.Reference))
}

func nativeAssignmentProcessRefused(v *nativeProcessAssignment, request []byte) string {
	return fmt.Sprintf("refused:%x:%x", sha256.Sum256(v.record), sha256.Sum256(request))
}

func runNativeAssignmentProcess(t *testing.T, ctx context.Context, mode, dir, stage string, send func(string), hold func()) {
	t.Helper()
	path := os.Getenv("LITEVIRT_NATIVE_ASSIGNMENT_REQUEST")
	r := nativeProcessRequest(t, path)
	requestBytes := nativeProcessRead(t, path, 8192)
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	finalReopens := 0
	parentSyncs := 0
	assigning := false
	boundary := func() { send("boundary:" + stage); hold(); t.Fatal("assignment kill boundary unexpectedly released") }
	trustDurabilitySeam = func(at string) error {
		record, err := readNativeCAFile(filepath.Join(canonical, ".operator-ca-operation"), (2<<20)+(16<<10))
		if err != nil {
			return err
		}
		unassigned := len(record) == 104 && string(record[:8]) == "LVNCA001"
		assigned := len(record) > 104 && string(record[:8]) == "LVNCA002"
		if mode == "assignment-contender" && at == "rename" && unassigned {
			if assigning {
				t.Fatal("one helper tried to publish more than one assignment")
			}
			assigning = true
			send("assigning")
		}
		if mode != "assignment-boundary" {
			return nil
		}
		if at == "native-assignment:committed" {
			committed = true
		}
		if committed && at == "reopen" {
			finalReopens++
		}
		if assigned && !committed && at == "directory-sync:"+canonical {
			parentSyncs++
		}
		matched := stage == "before-record-rename" && at == "rename" && unassigned || stage == "record-renamed" && at == "reopen" && assigned && !committed || stage == "record-file-synced-before-parent" && assigned && !committed && at == "directory-sync:"+canonical && parentSyncs == 1 || stage == "record-parent-synced" && assigned && !committed && at == "directory-sync:"+canonical && parentSyncs == 2 || stage == "final-root-sync-before-outward" && committed && at == "reopen" && finalReopens == 5
		if matched {
			boundary()
		}
		return nil
	}
	defer func() { trustDurabilitySeam = nil }()
	if mode == "assignment-contender" {
		send("ready")
		hold()
		send("request")
	}
	if err := InitializeOperatorCA(ctx, dir); err != nil {
		t.Fatal("fresh helper existing owner reopen", err)
	}
	material, assignmentErr := AssignNativeFirstMember(ctx, dir, requestBytes, nil)
	view := inspectNativeProcessAssignment(t, canonical, nil)
	var requestBinding nativeProcessBinding
	if rest, err := asn1.Unmarshal(r.Binding, &requestBinding); err != nil || len(rest) != 0 || !bytes.Equal(r.Operation, view.assignment.Operation) || !bytes.Equal(requestBinding.Root, view.assignment.Root) {
		t.Fatal("actual request does not match retained native domain", err)
	}
	if assignmentErr != nil {
		if mode != "assignment-refuse" && mode != "assignment-contender" {
			t.Fatal("assignment helper unexpectedly refused", assignmentErr)
		}
		if ctx.Err() != nil || material != nil || assignmentErr.Error() != "native operation already assigned to another destination" || bytes.Equal(r.Binding, view.assignment.Destination) {
			t.Fatal("helper did not observe an actual conflicting-destination refusal", assignmentErr)
		}
		send(nativeAssignmentProcessRefused(view, requestBytes))
		return
	}
	if mode == "assignment-refuse" {
		t.Fatal("different genuine destination acquired material")
	}
	if material == nil || !bytes.Equal(r.Binding, view.assignment.Destination) || !bytes.Equal(material.CA, view.root) || !bytes.Equal(material.Certificate, view.assignment.Certificate) || !bytes.Equal(material.PrivateKey, view.assignment.PrivateKey) || !bytes.Equal(material.DestinationBinding, view.assignment.Destination) || !bytes.Equal(material.AssignmentRef, view.assignment.Reference) {
		t.Fatal("real API material differs from independently decoded assignment")
	}
	if mode == "assignment-boundary" {
		if stage != "result-lost" {
			t.Fatal("assignment did not reach selected external kill boundary")
		}
		boundary()
	}
	send(nativeAssignmentProcessResult(view))
}

func nativeAssignmentProcessFixture(t *testing.T) (string, []byte, []byte, []byte, []string) {
	t.Helper()
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	original, root, err := NativeOperatorCAOperation(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	key := nativeProcessRead(t, filepath.Join(dir, ".operator-ca-native", "ca.key"), 1<<20)
	var requests []string
	for i := 0; i < 2; i++ {
		_, reservation := nativeDestinationFixture(t, root, original)
		path := filepath.Join(t.TempDir(), "reservation.der")
		if err := os.WriteFile(path, reservation, 0600); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, path)
	}
	return dir, original, root, key, requests
}

func startNativeAssignmentProcess(t *testing.T, mode, dir, request, stage string) *nativeCAProcess {
	t.Helper()
	return startNativeCAProcess(t, mode, dir, stage, "LITEVIRT_NATIVE_ASSIGNMENT_REQUEST="+request)
}

func resumeNativeAssignmentProcess(t *testing.T, dir, request string, original []byte) *nativeProcessAssignment {
	t.Helper()
	p := startNativeAssignmentProcess(t, "assignment-resume", dir, request, "")
	event := p.event(t)
	p.joined(t, false)
	view := inspectNativeProcessAssignment(t, dir, original)
	if event != nativeAssignmentProcessResult(view) {
		t.Fatal("fresh helper and independent parent disagree on exact assignment")
	}
	return view
}

func refuseNativeAssignmentProcess(t *testing.T, dir, request string, winner *nativeProcessAssignment) {
	t.Helper()
	r := nativeProcessRequest(t, request)
	if bytes.Equal(r.Binding, winner.assignment.Destination) {
		t.Fatal("refusal fixture is not the other genuine destination")
	}
	p := startNativeAssignmentProcess(t, "assignment-refuse", dir, request, "")
	p.expect(t, nativeAssignmentProcessRefused(winner, nativeProcessRead(t, request, 8192)))
	p.joined(t, false)
	after := inspectNativeProcessAssignment(t, dir, winner.assignment.Original)
	if !bytes.Equal(winner.record, after.record) {
		t.Fatal("conflicting fresh process changed assigned operation")
	}
}

func TestNativeFirstMemberExternalKillResume(t *testing.T) {
	for _, stage := range []string{"before-record-rename", "record-renamed", "record-file-synced-before-parent", "record-parent-synced", "final-root-sync-before-outward", "result-lost"} {
		t.Run(stage, func(t *testing.T) {
			dir, original, root, key, requests := nativeAssignmentProcessFixture(t)
			p := startNativeAssignmentProcess(t, "assignment-boundary", dir, requests[0], stage)
			p.expect(t, "boundary:"+stage)
			before := nativeProcessRead(t, filepath.Join(dir, ".operator-ca-operation"), (2<<20)+(16<<10))
			if stage == "before-record-rename" {
				if !bytes.Equal(before, original) {
					t.Fatal("pre-rename kill does not retain original unassigned A104")
				}
			} else {
				view := inspectNativeProcessAssignment(t, dir, original)
				if !bytes.Equal(before, view.record) {
					t.Fatal("kill-boundary snapshot changed")
				}
			}
			if err := p.cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			p.joined(t, true)
			if !bytes.Equal(before, nativeProcessRead(t, filepath.Join(dir, ".operator-ca-operation"), (2<<20)+(16<<10))) {
				t.Fatal("SIGKILL changed observed operation")
			}
			for name, want := range map[string][]byte{"ca.crt": root, "ca.key": key} {
				for _, base := range []string{dir, filepath.Join(dir, ".operator-ca-native")} {
					if !bytes.Equal(nativeProcessRead(t, filepath.Join(base, name), 1<<20), want) {
						t.Fatal("SIGKILL changed original root pair", name)
					}
				}
			}
			// The first reconciliation is in a clean process, not this parent's
			// existing in-memory owner. A precommit leaf was never retained.
			view := resumeNativeAssignmentProcess(t, dir, requests[0], original)
			if stage != "before-record-rename" && !bytes.Equal(before, view.record) {
				t.Fatal("fresh process replaced committed assignment after SIGKILL")
			}
			again := resumeNativeAssignmentProcess(t, dir, requests[0], original)
			if !bytes.Equal(view.record, again.record) || !bytes.Equal(view.assignment.Certificate, again.assignment.Certificate) || !bytes.Equal(view.assignment.PrivateKey, again.assignment.PrivateKey) {
				t.Fatal("fresh exact retry changed actual leaf/key/checkpoint")
			}
			refuseNativeAssignmentProcess(t, dir, requests[1], view)
			t.Logf("CONTROL_NATIVE_ASSIGNMENT_SIGKILL_OK stage=%s killed_and_reaped=true fresh_reopen=true exact_retry=true other_destination_refused=true", stage)
		})
	}
}

func TestNativeFirstMemberSimultaneousAssignmentProcesses(t *testing.T) {
	dir, original, _, _, requests := nativeAssignmentProcessFixture(t)
	alias := filepath.Join(t.TempDir(), "operator")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	var children []*nativeCAProcess
	requestIndex := []int{0, 1, 0, 1}
	for i, path := range []string{dir, alias, alias, dir} {
		p := startNativeAssignmentProcess(t, "assignment-contender", path, requests[requestIndex[i]], "")
		children = append(children, p)
		p.expect(t, "ready")
	}
	for _, p := range children {
		p.release(t)
	}
	assigning := 0
	events := make([]string, len(children))
	for i, p := range children {
		p.expect(t, "request")
		event := p.event(t)
		if event == "assigning" {
			assigning++
			event = p.event(t)
		}
		events[i] = event
		p.joined(t, false)
	}
	view := inspectNativeProcessAssignment(t, dir, original)
	winner := -1
	for i, request := range requests {
		if bytes.Equal(nativeProcessRequest(t, request).Binding, view.assignment.Destination) {
			if winner != -1 {
				t.Fatal("two destinations have the same actual tuple")
			}
			winner = i
		}
	}
	if winner == -1 {
		t.Fatal("assigned tuple is not either genuine destination")
	}
	successes, refusals := 0, 0
	for i, event := range events {
		if requestIndex[i] == winner {
			if event != nativeAssignmentProcessResult(view) {
				t.Fatal("winning destination processes disagree")
			}
			successes++
		} else {
			if event != nativeAssignmentProcessRefused(view, nativeProcessRead(t, requests[requestIndex[i]], 8192)) {
				t.Fatal("losing destination lacks actual conflicting-request refusal")
			}
			refusals++
		}
	}
	if assigning != 1 || successes != 2 || refusals != 2 {
		t.Fatalf("actual once-assignment counts publication=%d success=%d refusal=%d", assigning, successes, refusals)
	}
	fresh := resumeNativeAssignmentProcess(t, dir, requests[winner], original)
	if !bytes.Equal(view.record, fresh.record) {
		t.Fatal("fresh process changed multiprocess winner")
	}
	refuseNativeAssignmentProcess(t, dir, requests[1-winner], view)
	t.Log("CONTROL_NATIVE_ASSIGNMENT_MULTIPROCESS_OK real_helpers=4 real_destinations=2 publications=1 identical_winners=2 conflicting_losers=2 fresh_reopen=true")
}

func TestNativeFirstMemberAssignmentExcludedByDomainProcess(t *testing.T) {
	dir, original, _, _, requests := nativeAssignmentProcessFixture(t)
	p := startNativeCAProcess(t, "domain", dir, "")
	p.expect(t, "domain-held")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	material, err := AssignNativeFirstMember(ctx, dir, nativeProcessRead(t, requests[0], 8192), nil)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || material != nil {
		t.Fatal("real domain process did not exclude assignment", err)
	}
	if !bytes.Equal(original, nativeProcessRead(t, filepath.Join(dir, ".operator-ca-operation"), (2<<20)+(16<<10))) {
		t.Fatal("excluded assignment consumed operation")
	}
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	p.joined(t, true)
	view := resumeNativeAssignmentProcess(t, dir, requests[0], original)
	refuseNativeAssignmentProcess(t, dir, requests[1], view)
	t.Log("CONTROL_NATIVE_ASSIGNMENT_PROCESS_EXCLUSION_OK real_shared_held=true excluded_unchanged=true killed_and_reaped=true fresh_assignment=true")
}
