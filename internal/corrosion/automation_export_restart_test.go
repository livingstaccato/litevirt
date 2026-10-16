package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"google.golang.org/grpc/peer"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Real file-backed SQLite and a killed OS process, separate from the TLS fleet's
// shared-memory semantics. No process-local cursor key or export session survives.
func TestSourceExportFileProcessResume(t *testing.T) {
	dir := t.TempDir()
	p, r, ctx := exportFixtureAt(t, dir)
	r.Component = 3
	r.MaxRecords = 1
	first, e := p.ExportAutomationSource(ctx, r)
	if e != nil || first.Cursor == "" {
		t.Fatal("first page", e)
	}
	next := r
	next.Cursor = first.Cursor
	want, e := p.ExportAutomationSource(ctx, next)
	if e != nil {
		t.Fatal(e)
	}
	write := func(name string, v any) {
		t.Helper()
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("request", r)
	write("expected-first", first)
	write("expected-next", want)
	if e = p.client.Close(); e != nil {
		t.Fatal(e)
	}
	command := func(mode string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSourceExportProcess$", "-test.timeout=20s")
		cmd.Env = append(os.Environ(), "SOURCE_EXPORT_DIR="+dir, "SOURCE_EXPORT_PKI="+p.dir, "SOURCE_EXPORT_MODE="+mode)
		return cmd
	}
	child := command("first")
	var log bytes.Buffer
	child.Stdout = &log
	child.Stderr = &log
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { child.Process.Kill() })
	publicationWaitFile(t, filepath.Join(dir, "export-ready"))
	raw, e := os.ReadFile(filepath.Join(dir, "received"))
	if e != nil {
		t.Fatal(e)
	}
	var got AutomationExportPage
	if e = json.Unmarshal(raw, &got); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, mustExportJSON(t, first)) {
		t.Fatal("fresh process changed initial immutable page/cursor")
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	e = child.Wait()
	var exit *exec.ExitError
	if !errors.As(e, &exit) {
		t.Fatal("export source did not die", e, log.String())
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("source not killed with SIGKILL", e)
	}
	r.Cursor = got.Cursor
	write("request", r)
	out, e := command("resume").CombinedOutput()
	if e != nil {
		t.Fatalf("fresh process continuation: %v\n%s", e, out)
	}
	t.Logf("actual exporting PID %d SIGKILL; fresh process resumed exact cursor/page: %s", child.Process.Pid, out)
}
func mustExportJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestSourceExportProcess(t *testing.T) {
	dir := os.Getenv("SOURCE_EXPORT_DIR")
	if dir == "" {
		t.Skip("OS-process helper only")
	}
	ctx := context.Background()
	c, e := NewLocalClient(dir, "a")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = InitSchema(ctx, c); e != nil {
		t.Fatal(e)
	}
	p := NewAutomationSourcePreparer(c, os.Getenv("SOURCE_EXPORT_PKI"))
	if e = p.InitializePublication(ctx); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "request"))
	if e != nil {
		t.Fatal(e)
	}
	var r AutomationExportRequest
	if e = json.Unmarshal(raw, &r); e != nil {
		t.Fatal(e)
	}
	page, e := p.ExportAutomationSource(peer.NewContext(ctx, mustExportPeer(t, p)), r)
	if e != nil {
		t.Fatal(e)
	}
	actual := mustExportJSON(t, page)
	if os.Getenv("SOURCE_EXPORT_MODE") == "first" {
		if e = os.WriteFile(filepath.Join(dir, "received"), actual, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, "export-ready"), nil, 0600); e != nil {
			t.Fatal(e)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	expected, e := os.ReadFile(filepath.Join(dir, "expected-next"))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("restart changed exact continuation bytes/position/terminal")
	}
	t.Log("fresh file-process continuation equals exact pre-crash oracle")
}
