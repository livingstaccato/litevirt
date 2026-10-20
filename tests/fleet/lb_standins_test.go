package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/lbtestproc"
)

// Private runtime children survive another fixture's cleanup, even when both
// use the same configuration names. They also cannot match the shell-pattern
// cleanup still used by older branches. Closing the owner kills and reaps its
// children before returning.
func TestLBStandIns_AnotherRunsCleanupLeavesThemAlone(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "shared.conf")
	var owner *lbtestproc.Runtime
	var ownedPID int
	t.Run("run", func(t *testing.T) {
		owner = lbtestproc.New(t, true)
		other := lbtestproc.New(t, true)
		for _, runtime := range []*lbtestproc.Runtime{owner, other} {
			pidfile := filepath.Join(runtime.Dir, "keepalived.pid")
			if err := runtime.StartKeepalived(cfg, pidfile); err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.Run(context.Background(), "conntrackd", "-C", cfg, "-d"); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(pidfile)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(b))
			if err != nil {
				t.Fatal(err)
			}
			if runtime == owner {
				ownedPID = pid
			}
			cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
			if err != nil {
				t.Fatal(err)
			}
			legacy := regexp.MustCompile("sleep 600; : .*" + regexp.QuoteMeta(t.Name()))
			if legacy.MatchString(strings.ReplaceAll(string(cmdline), "\x00", " ")) {
				t.Fatalf("owned child matches another branch's cleanup: %q", cmdline)
			}
		}
		other.Close()
		for _, bin := range []string{"keepalived", "conntrackd"} {
			if !owner.ConfigAlive(bin, cfg) || other.ConfigAlive(bin, cfg) {
				t.Fatalf("%s cleanup did not preserve the other owner", bin)
			}
		}
	})
	if owner == nil {
		return
	}
	for _, bin := range []string{"keepalived", "conntrackd"} {
		if owner.ConfigAlive(bin, cfg) {
			t.Errorf("%s outlived its owner cleanup", bin)
		}
	}
	if ownedPID > 0 && syscall.Kill(ownedPID, 0) != syscall.ESRCH {
		t.Errorf("owned keepalived child %d was not reaped", ownedPID)
	}
}

// The observer's subreaper setting belongs to a separate process, never to the
// fleet test process. Nested test output is retained separately from its names.
func TestLBStandIns_KilledTestLeavesNoneBehind(t *testing.T) {
	dir := os.Getenv("LITEVIRT_LB_RUN_DIR")
	switch os.Getenv("LITEVIRT_LB_ROLE") {
	case "owner":
		lbDeathOwner(t, dir)
		return
	case "observer":
		result := lbDeathObserve(dir)
		body, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "result.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	root := os.Getenv("LITEVIRT_LB_EVIDENCE_DIR")
	if root == "" {
		t.Fatal("SETUP_UNAVAILABLE: LITEVIRT_LB_EVIDENCE_DIR must retain nested logs outside t.TempDir")
	}
	var err error
	dir, err = os.MkdirTemp(root, "lb-owner-death-")
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "observer.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := lbDeathCommand("observer", dir)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		t.Fatalf("observer terminal: %v (retained %s)", err, dir)
	}
	body, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result lbDeathResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.SetupError != "" || result.CleanupError != "" || !result.Cleaned || !result.OwnerKilled || !result.SiblingHeld || !result.SiblingEOF || len(result.AliveBefore) != 3 || len(result.ReapedPIDs) != 3 {
		t.Fatalf("owner-death harness failure: %+v (retained %s)", result, dir)
	}
	if len(result.RuntimePIDs) != 2 || len(result.ExitedNaturally) != 2 {
		t.Fatalf("incomplete owner-death inventory: %+v", result)
	}
	if !result.ExitedNaturally[0] || !result.ExitedNaturally[1] {
		t.Fatalf("PRODUCT_OLD_CHILD_SURVIVED: runtime children %v outlived killed owner; exact children cleaned and reaped (retained %s)", result.RuntimePIDs, dir)
	}
}

type lbDeathManifest struct {
	RuntimePIDs []int
	SiblingPID  int
}

type lbDeathResult struct {
	RuntimePIDs                                   []int
	AliveBefore, ReapedPIDs, EmergencyKills       []int
	ExitedNaturally                               []bool
	OwnerKilled, SiblingHeld, SiblingEOF, Cleaned bool
	SetupError, CleanupError                      string
}

func lbDeathCommand(role, dir string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestLBStandIns_KilledTestLeavesNoneBehind$", "-test.count=1", "-test.timeout=90s")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "LITEVIRT_LB_ROLE=") && !strings.HasPrefix(value, "LITEVIRT_LB_RUN_DIR=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "LITEVIRT_LB_ROLE="+role, "LITEVIRT_LB_RUN_DIR="+dir)
	return cmd
}

// Enumerate only during setup/recovery, then pin exact identities with pidfds.
func lbDeathChildrenOf(parent int) ([]int, error) {
	base := filepath.Join("/proc", strconv.Itoa(parent), "task")
	tasks, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	for _, task := range tasks {
		body, err := os.ReadFile(filepath.Join(base, task.Name(), "children"))
		if errors.Is(err, os.ErrNotExist) {
			continue // an otherwise idle Go thread exited during enumeration
		}
		if err != nil {
			return nil, err
		}
		for _, field := range strings.Fields(string(body)) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 0 {
				return nil, fmt.Errorf("invalid direct child %q", field)
			}
			seen[pid] = true
		}
	}
	var pids []int
	for pid := range seen {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids, nil
}

// Two consecutive exact sets are required while setup owns all child starts.
func lbDeathStableChildren(want []int, count int) ([]int, error) {
	deadline := time.Now().Add(3 * time.Second)
	var previous []int
	for {
		current, err := lbDeathChildrenOf(os.Getpid())
		if err != nil {
			return nil, err
		}
		if len(current) == count && (want == nil || slices.Equal(current, want)) && slices.Equal(current, previous) {
			return current, nil
		}
		previous = current
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("unstable child set %v, want %v count=%d", current, want, count)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The live handle brackets parentage validation; an unvalidated numeric PID
// never enters signal authority, even if it was listed in the manifest.
func lbDeathValidateChild(fd, pid, parent int) error {
	ready, err := lbDeathReady(fd, 0)
	if err != nil || ready {
		return fmt.Errorf("identity %d not live before parentage check: %v", pid, err)
	}
	body, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return err
	}
	end := strings.LastIndexByte(string(body), ')')
	if end < 0 {
		return fmt.Errorf("malformed stat for %d", pid)
	}
	fields := strings.Fields(string(body[end+1:]))
	if len(fields) < 2 {
		return fmt.Errorf("short stat for %d", pid)
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid != parent {
		return fmt.Errorf("identity %d has parent %d, expected %d", pid, ppid, parent)
	}
	ready, err = lbDeathReady(fd, 0)
	if err != nil || ready {
		return fmt.Errorf("identity %d exited during parentage check: %v", pid, err)
	}
	return nil
}

func lbDeathPidfdProbe() error {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := lbDeathValidateChild(fd, os.Getpid(), os.Getppid()); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		return err
	}
	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PIDFD, fd, &info, unix.WEXITED|unix.WNOHANG, nil); err != unix.ECHILD {
		return fmt.Errorf("pidfd wait probe expected ECHILD: %v", err)
	}
	return nil
}

func lbDeathOwner(t *testing.T, dir string) {
	prior, err := lbDeathChildrenOf(os.Getpid())
	if err != nil || len(prior) != 0 {
		t.Fatalf("owner setup already has children: %v %v", prior, err)
	}
	r := lbtestproc.New(t, true)
	cfg, pidfile := filepath.Join(dir, "runtime.conf"), filepath.Join(dir, "keepalived.pid")
	if err := r.StartKeepalived(cfg, pidfile); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background(), "conntrackd", "-C", cfg, "-d"); err != nil {
		t.Fatal(err)
	}
	pids, err := lbDeathStableChildren(nil, 2)
	if err != nil || len(pids) != 2 || !r.ConfigAlive("keepalived", cfg) || !r.ConfigAlive("conntrackd", cfg) {
		t.Fatalf("runtime setup has %v: %v", pids, err)
	}
	body, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatal(err)
	}
	keepPID, err := strconv.Atoi(string(body))
	if err != nil || (pids[0] != keepPID && pids[1] != keepPID) {
		t.Fatalf("runtime pidfile %q differs from actual children %v", body, pids)
	}
	// The observer owns the sole writer. This sibling execs after both runtime
	// starts, and must stay live when the owner dies and runtime pipes close.
	read := os.NewFile(3, "sibling-stdin")
	if read == nil {
		t.Fatal("missing sibling control reader")
	}
	defer read.Close()
	sibling := exec.Command("/bin/cat")
	sibling.Stdin = read
	if err := sibling.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sibling.Process.Kill(); _ = sibling.Wait() }()
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	want := append(append([]int{}, pids...), sibling.Process.Pid)
	sort.Ints(want)
	all, err := lbDeathStableChildren(want, 3)
	if err != nil || !slices.Equal(all, want) {
		t.Fatalf("owner sibling setup children=%v error=%v", all, err)
	}
	manifest := lbDeathManifest{RuntimePIDs: pids, SiblingPID: sibling.Process.Pid}
	body, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path+".tmp", body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		t.Fatal(err)
	}
	// Closing the observer's abort writer returns through actual Cmd cleanup.
	// Keep this independent of the sibling's liveness pipe.
	abort := os.NewFile(4, "owner-abort")
	if abort == nil {
		t.Fatal("missing owner abort reader")
	}
	defer abort.Close()
	var one [1]byte
	if n, err := abort.Read(one[:]); n != 0 || err == nil {
		t.Fatalf("invalid setup-abort message: n=%d err=%v", n, err)
	}
}

func lbDeathReady(fd int, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		ms := int(time.Until(deadline).Milliseconds())
		if ms < 0 {
			ms = 0
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, err
		}
		if n == 0 {
			return false, nil
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			return true, nil
		}
		return false, fmt.Errorf("unexpected pidfd poll events %x", fds[0].Revents)
	}
}

func lbDeathReap(fd int) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PIDFD, fd, &info, unix.WEXITED|unix.WNOHANG, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if info.Signo != int32(unix.SIGCHLD) {
			return fmt.Errorf("pidfd had no reapable adopted terminal: signo=%d", info.Signo)
		}
		return nil
	}
}

func lbDeathObserve(dir string) (result lbDeathResult) {
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		result.SetupError = "SETUP_UNAVAILABLE: subreaper: " + err.Error()
		return
	}
	if err := lbDeathPidfdProbe(); err != nil {
		result.SetupError = "SETUP_UNAVAILABLE: pidfd capabilities: " + err.Error()
		return
	}
	var owner *exec.Cmd
	var ownerDone chan error
	ownerConsumed := false
	fds := map[int]int{}
	reaped := map[int]bool{}
	var siblingWriter, abortWriter *os.File
	ownerFD := -1
	transferred := false
	addCleanupError := func(err error) {
		if err != nil {
			result.CleanupError += err.Error() + "; "
		}
	}
	defer func() {
		if abortWriter != nil {
			addCleanupError(abortWriter.Close())
			abortWriter = nil
		}
		if ownerDone != nil && !ownerConsumed {
			// Before full validated ownership, only EOF-abort may stop owner;
			// its actual Runtime.Close and sibling Cmd.Wait retain cleanup.
			if transferred {
				_ = owner.Process.Kill()
			}
			select {
			case <-ownerDone:
				ownerConsumed = true
			case <-time.After(10 * time.Second):
				addCleanupError(errors.New("owner terminal not consumed"))
			}
		}
		if siblingWriter != nil {
			addCleanupError(siblingWriter.Close())
		}
		// A setup failure before manifest still owns adopted direct children.
		// Pin those identities before signaling, never signal a discovered PID.
		if ownerConsumed && transferred {
			pids, err := lbDeathChildrenOf(os.Getpid())
			addCleanupError(err)
			for _, pid := range pids {
				if _, ok := fds[pid]; !ok {
					fd, err := unix.PidfdOpen(pid, 0)
					addCleanupError(err)
					if err == nil {
						if err := lbDeathValidateChild(fd, pid, os.Getpid()); err != nil {
							addCleanupError(err)
							_ = unix.Close(fd)
						} else {
							fds[pid] = fd
						}
					}
				}
			}
		}
		for pid, fd := range fds {
			if transferred && !reaped[pid] {
				ready, err := lbDeathReady(fd, 0)
				addCleanupError(err)
				if err == nil && !ready {
					addCleanupError(unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0))
				}
				ready, err = lbDeathReady(fd, 10*time.Second)
				addCleanupError(err)
				if err == nil && ready {
					addCleanupError(lbDeathReap(fd))
				} else if err == nil {
					addCleanupError(fmt.Errorf("child %d has no terminal", pid))
				}
			}
			addCleanupError(unix.Close(fd))
		}
		if ownerFD >= 0 {
			addCleanupError(unix.Close(ownerFD))
		}
		remaining, err := lbDeathChildrenOf(os.Getpid())
		addCleanupError(err)
		if len(remaining) != 0 {
			addCleanupError(fmt.Errorf("observer retained children %v", remaining))
		}
		result.Cleaned = result.CleanupError == "" && ownerConsumed
	}()
	read, write, err := os.Pipe()
	if err != nil {
		result.SetupError = err.Error()
		return
	}
	siblingWriter = write
	defer read.Close()
	log, err := os.Create(filepath.Join(dir, "owner.log"))
	if err != nil {
		result.SetupError = err.Error()
		return
	}
	defer log.Close()
	abortRead, abortWrite, err := os.Pipe()
	if err != nil {
		result.SetupError = err.Error()
		return
	}
	abortWriter = abortWrite
	defer abortRead.Close()
	owner = lbDeathCommand("owner", dir)
	owner.ExtraFiles = []*os.File{read, abortRead}
	owner.Stdout, owner.Stderr = log, log
	if err := owner.Start(); err != nil {
		result.SetupError = err.Error()
		return
	}
	ownerDone = make(chan error, 1)
	go func() { ownerDone <- owner.Wait() }()
	if err := abortRead.Close(); err != nil {
		result.SetupError = err.Error()
		return
	}
	ownerFD, err = unix.PidfdOpen(owner.Process.Pid, 0)
	if err != nil {
		result.SetupError = "owner pidfd: " + err.Error()
		return
	}
	if err := lbDeathValidateChild(ownerFD, owner.Process.Pid, os.Getpid()); err != nil {
		result.SetupError = err.Error()
		return
	}
	if err := read.Close(); err != nil {
		result.SetupError = err.Error()
		return
	}
	var manifest lbDeathManifest
	deadline := time.Now().Add(15 * time.Second)
	for {
		body, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err == nil {
			if err := json.Unmarshal(body, &manifest); err != nil {
				result.SetupError = err.Error()
				return
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			result.SetupError = err.Error()
			return
		}
		select {
		case err := <-ownerDone:
			ownerConsumed = true
			result.SetupError = fmt.Sprintf("owner exited before ready: %v", err)
			return
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			result.SetupError = "owner readiness timeout"
			return
		}
	}
	if len(manifest.RuntimePIDs) != 2 || manifest.RuntimePIDs[0] <= 0 || manifest.RuntimePIDs[1] <= 0 || manifest.RuntimePIDs[0] == manifest.RuntimePIDs[1] || manifest.SiblingPID <= 0 || manifest.SiblingPID == manifest.RuntimePIDs[0] || manifest.SiblingPID == manifest.RuntimePIDs[1] {
		result.SetupError = "invalid exact child manifest"
		return
	}
	result.RuntimePIDs = manifest.RuntimePIDs
	for _, pid := range append(append([]int{}, manifest.RuntimePIDs...), manifest.SiblingPID) {
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			result.SetupError = "SETUP_UNAVAILABLE: pidfd: " + err.Error()
			return
		}
		ownerReady, ownerErr := lbDeathReady(ownerFD, 0)
		if ownerErr != nil || ownerReady {
			_ = unix.Close(fd)
			result.SetupError = fmt.Sprintf("owner not held before identity check: %v", ownerErr)
			return
		}
		if err := lbDeathValidateChild(fd, pid, owner.Process.Pid); err != nil {
			_ = unix.Close(fd)
			result.SetupError = err.Error()
			return
		}
		ownerReady, ownerErr = lbDeathReady(ownerFD, 0)
		if ownerErr != nil || ownerReady {
			_ = unix.Close(fd)
			result.SetupError = fmt.Sprintf("owner exited during identity check: %v", ownerErr)
			return
		}
		fds[pid] = fd
		result.AliveBefore = append(result.AliveBefore, pid)
	}
	select {
	case err := <-ownerDone:
		ownerConsumed = true
		result.SetupError = fmt.Sprintf("owner exited before kill: %v", err)
		return
	default:
	}
	transferred = true
	if err := owner.Process.Kill(); err != nil {
		result.SetupError = err.Error()
		return
	}
	select {
	case err := <-ownerDone:
		ownerConsumed = true
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			result.SetupError = fmt.Sprintf("owner kill terminal: %v", err)
			return
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			result.SetupError = fmt.Sprintf("owner terminal was not SIGKILL: %v", err)
			return
		}
		result.OwnerKilled = true
	case <-time.After(10 * time.Second):
		result.SetupError = "owner kill did not yield terminal"
		return
	}
	for _, pid := range manifest.RuntimePIDs {
		ready, err := lbDeathReady(fds[pid], 2*time.Second)
		if err != nil {
			result.SetupError = err.Error()
			return
		}
		result.ExitedNaturally = append(result.ExitedNaturally, ready)
		// Expected RED retains real terminal ownership, including emergency kill.
		if !ready {
			if err := unix.PidfdSendSignal(fds[pid], unix.SIGKILL, nil, 0); err != nil {
				result.SetupError = err.Error()
				return
			}
			result.EmergencyKills = append(result.EmergencyKills, pid)
		}
		ready, err = lbDeathReady(fds[pid], 10*time.Second)
		if err != nil || !ready {
			result.SetupError = fmt.Sprintf("runtime child %d failed terminal: %v", pid, err)
			return
		}
		if err := lbDeathReap(fds[pid]); err != nil {
			result.SetupError = err.Error()
			return
		}
		reaped[pid] = true
		result.ReapedPIDs = append(result.ReapedPIDs, pid)
	}
	ready, err := lbDeathReady(fds[manifest.SiblingPID], 0)
	if err != nil || ready {
		result.SetupError = fmt.Sprintf("independent sibling died with owner: %v", err)
		return
	}
	result.SiblingHeld = true
	if err := siblingWriter.Close(); err != nil {
		result.SetupError = err.Error()
		return
	}
	siblingWriter = nil
	ready, err = lbDeathReady(fds[manifest.SiblingPID], 10*time.Second)
	if err != nil || !ready {
		result.SetupError = fmt.Sprintf("sibling EOF failed terminal: %v", err)
		return
	}
	if err := lbDeathReap(fds[manifest.SiblingPID]); err != nil {
		result.SetupError = err.Error()
		return
	}
	reaped[manifest.SiblingPID] = true
	result.ReapedPIDs = append(result.ReapedPIDs, manifest.SiblingPID)
	result.SiblingEOF = true
	return
}
