//go:build linux

package opjournal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

func executionDiskStore(t *testing.T, dir string) (*image.Store, image.ArtifactDiskPlan) {
	t.Helper()
	s := image.NewStore(filepath.Join(dir, "data"))
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(s.ImageDir(), "initial.tmp")
	if err := qcow2.Create(base, 4<<20, nil); err != nil {
		t.Fatal(err)
	}
	digest, err := image.FileDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Publish("base", base, digest); err != nil {
		t.Fatal(err)
	}
	a := contract.ArtifactRecord{ID: "artifact-original", Key: "root", Kind: "disk", Backend: "local", ObjectID: "object-original", ResourceUID: "resource-original", Incarnation: "incarnation-original", OperationID: "operation-original", Origin: contract.ExecutorReference{Generation: 1, Decision: contract.HistoryReference{Sequence: 12, Digest: strings.Repeat("a", 64)}}, HostUID: "host-original", HostIncarnation: "host-incarnation-a", PoolUID: "pool-original", ImageDigest: digest, State: "planned"}
	p, err := s.PrepareArtifactOverlay(a, "web", "root", "base", digest)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func executionDiskFixture(t *testing.T) (*Journal, *ExecutionController, Preparation, *image.Store, image.ArtifactDiskPlan) {
	t.Helper()
	j, c, p := controllerFixture(t)
	s, plan := executionDiskStore(t, j.dir)
	if err := c.PrepareDiskArtifact(context.Background(), p, "disk-effect", 1, plan); err != nil {
		t.Fatal(err)
	}
	return j, c, p, s, plan
}

func TestExecutionArtifactPlanImmutableAndStaleGenerationHasNoEffect(t *testing.T) {
	_, c, p, s, plan := executionDiskFixture(t)
	for _, field := range []string{"uid", "incarnation", "object", "locator", "temporary", "base", "digest", "size", "name", "origin", "effect", "generation"} {
		t.Run(field, func(t *testing.T) {
			changed := plan
			id, gen := "disk-effect", uint64(1)
			switch field {
			case "uid":
				changed.Artifact.ResourceUID = "another-resource"
			case "incarnation":
				changed.Artifact.Incarnation = "another-incarnation"
			case "object":
				changed.Artifact.ObjectID = "another-object"
			case "locator":
				changed.Locator += ".other"
			case "temporary":
				changed.TemporaryLocator += ".other"
			case "base":
				changed.BaseLocator += ".other"
			case "digest":
				changed.ImageDigest = strings.Repeat("b", 64)
			case "size":
				changed.VirtualSize++
			case "name":
				changed.ImageName = "other"
			case "origin":
				changed.Artifact.Origin.Decision.Sequence++
			case "effect":
				id = "other-effect"
			case "generation":
				gen = 2
			}
			if err := c.PrepareDiskArtifact(context.Background(), p, id, gen, changed); err == nil {
				t.Fatal("persisted plan was replaced")
			}
		})
	}
	a := controllerFixtureAdmission(p)
	a.generation = 2
	if err := c.executeArtifactDisk(context.Background(), p, a, s); !errors.Is(err, ErrExecutionUngrant) {
		t.Fatalf("stale generation issued disk: %v", err)
	}
	if _, err := os.Stat(plan.Locator); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("generation refusal created a disk")
	}
	r, err := c.RecoverTarget(context.Background(), p)
	if err != nil || r.Disk.Plan != plan || r.Effect != nil {
		t.Fatal("refusal changed original plan", err)
	}
	r.Disk.Plan.Artifact.ResourceUID = "returned-copy-mutated"
	stored, err := c.RecoverTarget(context.Background(), p)
	if err != nil || stored.Disk.Plan.Artifact.ResourceUID != "resource-original" {
		t.Fatal("returned plan alias mutated owned record")
	}
	if err := c.executeArtifactDisk(context.Background(), p, controllerFixtureAdmission(p), s); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReconcileDiskArtifact(context.Background(), p, s)
	if err != nil || got.ResourceUID != "resource-original" || got.ObjectID != "object-original" {
		t.Fatalf("actual disk consumer/reconciler failed: %+v %v", got, err)
	}
}

func TestExecutionArtifactResultPersistenceUnknownSurvivesColdReopen(t *testing.T) {
	j, c, p, s, plan := executionDiskFixture(t)
	writes := 0
	j.FailWrite = func(string) error {
		writes++
		if writes == 2 {
			return errors.New("result persistence failed")
		}
		return nil
	}
	if err := c.executeArtifactDisk(context.Background(), p, controllerFixtureAdmission(p), s); !errors.Is(err, ErrExecutionUnknown) {
		t.Fatalf("failed result persistence reported success: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	j.FailWrite = nil
	fresh, err := OpenExecutionController(j)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	before, err := fresh.RecoverTarget(context.Background(), p)
	if err != nil || before.Effect.State != "issued" {
		t.Fatalf("original issued record lost: %+v %v", before, err)
	}
	a, err := fresh.ReconcileDiskArtifact(context.Background(), p, s)
	if err != nil || a.ResourceUID != "resource-original" || a.ID != "artifact-original" || a.ObjectID != "object-original" {
		t.Fatalf("same physical artifact not recovered: %+v %v", a, err)
	}
	after, err := fresh.RecoverTarget(context.Background(), p)
	if err != nil || after.Effect.State != "issued" || !fresh.targets[p.Target.Name].reopened {
		t.Fatal("observation upgraded unknown/reopened authority")
	}
	if err := fresh.executeArtifactDisk(context.Background(), p, controllerFixtureAdmission(p), s); !errors.Is(err, ErrExecutionUnknown) {
		t.Fatal("reopened original issued another disk", err)
	}
	if closure, err := fresh.CloseTarget(context.Background(), p); !errors.Is(err, ErrExecutionUnknown) || closure.RuntimeExcluded {
		t.Fatal("physical observation became runtime exclusion")
	}
	if _, err := os.Stat(plan.Locator); err != nil {
		t.Fatal("unknown recovery removed disk")
	}
}

func TestExecutionArtifactObservationRemainsAccountedThroughReturn(t *testing.T) {
	_, c, p, s, _ := executionDiskFixture(t)
	if err := c.executeArtifactDisk(context.Background(), p, controllerFixtureAdmission(p), s); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	executionDiskObservationReturned = func() { close(entered); <-release }
	defer func() { executionDiskObservationReturned = nil }()
	observed := make(chan error, 1)
	go func() { _, err := c.ReconcileDiskArtifact(context.Background(), p, s); observed <- err }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case <-closed:
		close(release)
		<-observed
		t.Fatal("controller Close escaped actual observation return")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestExecutionArtifactPlanStrictDecodeAndLegacyAbsence(t *testing.T) {
	_, c, p, _, _ := executionDiskFixture(t)
	r, err := c.RecoverTarget(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range [][]byte{bytes.Replace(raw, []byte(`"virtual_size":4194304`), []byte(`"virtual_size":4194304,"virtual_size":1`), 1), bytes.Replace(raw, []byte(`"vm_name":"web"`), []byte(`"vm_name":"web","unknown":1`), 1)} {
		if bytes.Equal(corrupt, raw) {
			t.Fatal("strict decode mutation did not bind")
		}
		var got ExecutionRecord
		if err := json.Unmarshal(corrupt, &got); !errors.Is(err, ErrCorrupt) {
			t.Fatal("malformed plan survived owned decode", err)
		}
	}
	plain := ExecutionRecord{Version: 1, Preparation: p, State: "prepared"}
	b, _ := json.Marshal(plain)
	if bytes.Contains(b, []byte(`"Disk"`)) {
		t.Fatal("omitted disk plan changed legacy execution bytes")
	}
}

func TestExecutionArtifactJournalRejectsSemanticFieldAliases(t *testing.T) {
	cases := []string{"size-canonical-first", "size-alias-first", "size-lone-alias", "size-unicode-fold", "plan-canonical-first", "plan-alias-first", "identity-mixed-case", "identity-unicode-fold", "record-lone-alias"}
	for _, kind := range cases {
		t.Run(kind, func(t *testing.T) {
			j, c, p, _, plan := executionDiskFixture(t)
			entry, found, err := j.Read(p.RecordID)
			if err != nil || !found {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(j.path(p.RecordID))
			if err != nil {
				t.Fatal(err)
			}
			var needle, replacement []byte
			switch kind {
			case "size-canonical-first":
				needle = []byte(`"virtual_size":4194304`)
				replacement = []byte(`"virtual_size":1,"Virtual_Size":4194304`)
			case "size-alias-first":
				needle = []byte(`"virtual_size":4194304`)
				replacement = []byte(`"Virtual_Size":1,"virtual_size":4194304`)
			case "size-lone-alias":
				needle = []byte(`"virtual_size":4194304`)
				replacement = []byte(`"Virtual_Size":4194304`)
			case "size-unicode-fold":
				needle = []byte(`"virtual_size":4194304`)
				replacement = []byte(`"virtual_ſize":1,"virtual_size":4194304`)
			case "plan-canonical-first", "plan-alias-first":
				encoded, err := json.Marshal(plan)
				if err != nil {
					t.Fatal(err)
				}
				needle = append([]byte(`"plan":`), encoded...)
				if kind == "plan-canonical-first" {
					replacement = append([]byte(`"plan":{},"Plan":`), encoded...)
				} else {
					replacement = append([]byte(`"Plan":{},"plan":`), encoded...)
				}
			case "identity-mixed-case":
				needle = []byte(`"host_uid":"host-original"`)
				replacement = []byte(`"HoSt_UiD":"wrong-host","host_uid":"host-original"`)
			case "identity-unicode-fold":
				needle = []byte(`"host_uid":"host-original"`)
				replacement = []byte(`"hoſt_uid":"wrong-host","host_uid":"host-original"`)
			case "record-lone-alias":
				needle = []byte(`"Disk":`)
				replacement = []byte(`"Diſk":`)
			}
			if bytes.Count(raw, needle) != 1 {
				t.Fatalf("SETUP alias mutation site count=%d", bytes.Count(raw, needle))
			}
			mutated := bytes.Replace(raw, needle, replacement, 1)
			// Independently bypass only our custom validator to prove standard JSON
			// field folding yields the ORIGINAL typed record/checksum. These are
			// actual checksum-valid corrupt journal bytes, not a checksum failure.
			var outer struct {
				Execution json.RawMessage `json:"execution"`
			}
			if err := json.Unmarshal(mutated, &outer); err != nil {
				t.Fatal(err)
			}
			type unvalidatedRecord ExecutionRecord
			var decoded unvalidatedRecord
			if err := json.Unmarshal(outer.Execution, &decoded); err != nil {
				t.Fatal("SETUP standard decoder did not accept alias", err)
			}
			copyEntry := *entry
			record := ExecutionRecord(decoded)
			copyEntry.Execution = &record
			if copyEntry.checksum() != entry.Checksum {
				t.Fatal("SETUP alias bytes did not preserve original checksum")
			}
			if err := os.WriteFile(j.path(p.RecordID), mutated, 0600); err != nil {
				t.Fatal(err)
			}
			opened, err := OpenExecutionController(j)
			if opened != nil {
				opened.Close()
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Errorf("SEMANTIC_ALIAS_ACCEPTED: checksum-valid raw alias reopened: %v", err)
			}
			if _, err := os.Stat(plan.Locator); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("corrupt plan caused disk work")
			}
		})
	}
}

func TestExecutionArtifactTargetClosingExcludesNewObservation(t *testing.T) {
	_, c, p, s, _ := executionDiskFixture(t)
	if err := c.executeArtifactDisk(context.Background(), p, controllerFixtureAdmission(p), s); err != nil {
		t.Fatal(err)
	}
	closing, releaseClose := make(chan struct{}), make(chan struct{})
	observing, releaseObserve := make(chan struct{}), make(chan struct{})
	var closeOnce, observeOnce sync.Once
	stopClose := func() { closeOnce.Do(func() { close(releaseClose) }) }
	stopObserve := func() { observeOnce.Do(func() { close(releaseObserve) }) }
	executionTargetClosingSnapshot = func() { close(closing); <-releaseClose }
	executionDiskObservationReturned = func() { close(observing); <-releaseObserve }
	defer func() {
		stopClose()
		stopObserve()
		executionTargetClosingSnapshot = nil
		executionDiskObservationReturned = nil
	}()
	type targetResult struct {
		closure LocalClosure
		err     error
	}
	closed := make(chan targetResult, 1)
	go func() { v, e := c.CloseTarget(context.Background(), p); closed <- targetResult{v, e} }()
	<-closing // actual closing persisted and active=nil snapshotted under c.mu
	observed := make(chan error, 1)
	go func() { _, err := c.ReconcileDiskArtifact(context.Background(), p, s); observed <- err }()
	admitted := false
	var observeErr error
	select {
	case <-observing:
		admitted = true
	case observeErr = <-observed:
	case <-time.After(3 * time.Second):
		stopClose()
		stopObserve()
		t.Fatal("observation did not reach its boundary")
	}
	stopClose()
	var result targetResult
	select {
	case result = <-closed:
	case <-time.After(3 * time.Second):
		stopObserve()
		result = <-closed
		if admitted {
			observeErr = <-observed
		}
		t.Fatal("target closure did not finish in controlled window")
	}
	// Complete all actual goroutines before a failed assertion or hook reset.
	stopObserve()
	if admitted {
		observeErr = <-observed
	}
	if admitted && result.closure.CallsResolved {
		t.Fatal("TARGET_CLOSE_FALSE_RESOLUTION: real observation crossed closing after nil snapshot while CallsResolved=true")
	}
	if result.err != nil || !result.closure.CallsResolved || result.closure.RuntimeExcluded {
		t.Fatalf("eligible target close failed: %+v %v", result.closure, result.err)
	}
	if !errors.Is(observeErr, ErrExecutionUnknown) {
		t.Fatalf("closing target admitted new observation: %v", observeErr)
	}
	if _, err := c.ReconcileDiskArtifact(context.Background(), p, s); !errors.Is(err, ErrExecutionUnknown) {
		t.Fatal("closed target admitted new observation", err)
	}
}

func TestExecutionArtifactTargetCloseDrainsAlreadyAdmittedObservation(t *testing.T) {
	_, c, p, s, _ := executionDiskFixture(t)
	if err := c.executeArtifactDisk(context.Background(), p, controllerFixtureAdmission(p), s); err != nil {
		t.Fatal(err)
	}
	observing, release := make(chan struct{}), make(chan struct{})
	snapshot := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(release) }) }
	executionDiskObservationReturned = func() { close(observing); <-release }
	executionTargetClosingSnapshot = func() { close(snapshot) }
	defer func() { stop(); executionDiskObservationReturned = nil; executionTargetClosingSnapshot = nil }()
	observed := make(chan error, 1)
	go func() { _, err := c.ReconcileDiskArtifact(context.Background(), p, s); observed <- err }()
	<-observing // real disk recognized, participating observation still held
	type closeResult struct {
		closure LocalClosure
		err     error
	}
	closed := make(chan closeResult, 1)
	go func() { v, e := c.CloseTarget(context.Background(), p); closed <- closeResult{v, e} }()
	<-snapshot // actual target closing state and non-nil active snapshot
	select {
	case result := <-closed:
		stop()
		<-observed
		t.Fatalf("target resolved before actual observation returned: %+v %v", result.closure, result.err)
	case <-time.After(20 * time.Millisecond):
	}
	stop()
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	result := <-closed
	if result.err != nil || !result.closure.CallsResolved || result.closure.RuntimeExcluded {
		t.Fatalf("target did not drain participating observation: %+v %v", result.closure, result.err)
	}
}

// This fixture tests actual local child death, physical ownership and the
// existing journal only. Its private admission is not native readiness.
func TestExecutionArtifactChildDeathKeepsOriginalDisk(t *testing.T) {
	if dir := os.Getenv("LITEVIRT_ARTIFACT_CHILD"); dir != "" {
		j, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		c, err := OpenExecutionController(j)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		p, err := c.PrepareTarget(context.Background(), controllerTarget())
		if err != nil {
			t.Fatal(err)
		}
		s, plan := executionDiskStore(t, dir)
		if err := c.PrepareDiskArtifact(context.Background(), p, "disk-effect", 1, plan); err != nil {
			t.Fatal(err)
		}
		err = c.execute(context.Background(), p, "disk-effect", controllerFixtureAdmission(p), func() error {
			if err := s.CreateArtifactOverlayDisk(plan); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "DISK_PUBLISHED_BEFORE_RESULT")
			var b [1]byte
			_, err := os.Stdin.Read(b[:])
			return fmt.Errorf("fixture input ended: %v", err)
		})
		t.Fatal("child unexpectedly returned before kill", err)
	}
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestExecutionArtifactChildDeathKeepsOriginalDisk$", "-test.v")
	cmd.Env = append(os.Environ(), "LITEVIRT_ARTIFACT_CHILD="+dir)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited, joined := false, false
	var waitErr error
	readerDone := make(chan struct{})
	ready := make(chan bool, 1)
	var childFailure string
	go func() {
		defer close(readerDone)
		seen := false
		scan := bufio.NewScanner(out)
		for scan.Scan() {
			line := scan.Text()
			if strings.Contains(line, "WARNING: DATA RACE") || strings.Contains(line, "--- FAIL:") || line == "FAIL" || strings.Contains(line, "panic:") || strings.Contains(line, "fatal error:") {
				if len(line) > 1024 {
					line = line[:1024]
				}
				childFailure = line
			}
			if line == "DISK_PUBLISHED_BEFORE_RESULT" && !seen {
				seen = true
				ready <- true
			}
		}
		if !seen {
			ready <- false
		}
	}()
	finish := func() {
		if !waited {
			cmd.Process.Kill()
			waitErr = cmd.Wait()
			waited = true
		}
		if !joined {
			<-readerDone
			joined = true
		}
	}
	defer finish()
	select {
	case ok := <-ready:
		if !ok {
			finish()
			t.Fatalf("child did not reach real published disk: wait=%v stderr=%s", waitErr, stderr.String())
		}
	case <-time.After(15 * time.Second):
		finish()
		t.Fatalf("child disk publication timeout: wait=%v stderr=%s", waitErr, stderr.String())
	}
	killErr := cmd.Process.Kill()
	waitErr = cmd.Wait()
	waited = true
	finish()
	// The expected kill must not hide detector output or a child test failure.
	if childFailure != "" || strings.Contains(stderr.String(), "WARNING: DATA RACE") || strings.Contains(stderr.String(), "FAIL") || strings.Contains(stderr.String(), "panic:") || strings.Contains(stderr.String(), "fatal error:") {
		t.Fatalf("child failed before intended kill: stdout=%s stderr=%s", childFailure, stderr.String())
	}
	if killErr != nil {
		t.Fatalf("owned child kill failed after joined cleanup: %v wait=%v stderr=%s", killErr, waitErr, stderr.String())
	}
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("actual child did not die at intended cut: %v %s", waitErr, stderr.String())
	}

	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, corrupt, err := j.List()
	if err != nil || len(corrupt) != 0 || len(entries) != 1 {
		t.Fatalf("original journal lost: %+v %v %v", entries, corrupt, err)
	}
	original := *entries[0].Execution
	p := original.Preparation
	if original.Effect == nil || original.Effect.State != "issued" {
		t.Fatal("child persisted a result before actual kill")
	}
	c, err := OpenExecutionController(j)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a, err := c.ReconcileDiskArtifact(context.Background(), p, image.NewStore(filepath.Join(dir, "data")))
	if err != nil || a.ID != "artifact-original" || a.ObjectID != "object-original" || a.ResourceUID != "resource-original" || a.Incarnation != "incarnation-original" {
		t.Fatalf("same UID/artifact not recovered after actual death: %+v %v", a, err)
	}
	recovered, err := c.RecoverTarget(context.Background(), p)
	if err != nil || recovered.Effect.State != "issued" || !c.targets["web"].reopened {
		t.Fatal("cold physical observation changed issuance authority")
	}
	tool := os.Getenv("LITEVIRT_ARTIFACT_QEMU")
	if !filepath.IsAbs(tool) {
		t.Fatal("pinned qemu-img absent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, tool, "check", a.Locator).CombinedOutput(); err != nil {
		t.Fatalf("real recovered disk qemu check: %v %s", err, out)
	}
	t.Logf("ACTUAL_CHILD_DEATH pid=%d wait=SIGKILL same UID=%s artifact=%s object=%s journal=issued reopened=true native-authority=false", cmd.Process.Pid, a.ResourceUID, a.ID, a.ObjectID)
}
