package pki

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

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
	input := bufio.NewReader(os.Stdin)
	send := func(event string) {
		if _, err := fmt.Fprintln(ack, event); err != nil {
			t.Fatal(err)
		}
	}
	hold := func() {
		if line, err := input.ReadString('\n'); err != nil || line != "release\n" {
			t.Fatalf("parent release: %q %v", line, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
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
	output bytes.Buffer
	done   chan struct{}
	err    error
}

func startNativeCAProcess(t *testing.T, mode, dir, stage string) *nativeCAProcess {
	t.Helper()
	ack, childAck, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	p := &nativeCAProcess{ack: ack, reader: bufio.NewReader(ack), done: make(chan struct{})}
	p.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOperatorCANativeProcessHelper$", "-test.timeout=18s")
	p.cmd.Env = append(os.Environ(), "LITEVIRT_NATIVE_PROCESS_MODE="+mode, "LITEVIRT_NATIVE_PROCESS_DIR="+dir, "LITEVIRT_NATIVE_PROCESS_STAGE="+stage)
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
	})
	t.Logf("child-start mode=%s stage=%s pid=%d", mode, stage, p.cmd.Process.Pid)
	return p
}

func (p *nativeCAProcess) event(t *testing.T) string {
	t.Helper()
	if err := p.ack.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := p.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("child %d acknowledgement: %v", p.cmd.Process.Pid, err)
	}
	line = strings.TrimSuffix(line, "\n")
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
