package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A resolver must reject the actual process's over-limit output, rather than
// parse a policy-truncated prefix or retain unrestricted diagnostics.
func TestEnrollmentResolverRejectsOutputOverflow(t *testing.T) {
	for _, tc := range []struct {
		name, script string
	}{
		{"stdout", "#!/bin/sh\nexec /usr/bin/head -c 1048577 /dev/zero\n"},
		{"stderr", "#!/bin/sh\nexec /usr/bin/head -c 65537 /dev/zero >&2\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(tc.script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			if _, err := sshG(time.Second, "fixture"); err == nil {
				t.Fatal("ENROLLMENT_RESOLVER_ACCEPTED_OVERSIZE_OUTPUT")
			}
		})
	}
}

func TestEnrollmentResolverCancelledDoesNotDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nprintf started > "+ShellQuote(marker)+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	conn, peer := enrollmentSocketPair(t)
	defer peer.Close()
	diagnostics, err := NewEnrollmentDiagnostics(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer diagnostics.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if target, err := ResolveContext(ctx, "example.invalid", diagnostics); target != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolution continued: target=%v error=%v", target, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("already-cancelled resolver started a process: %v", err)
	}
}

func enrollmentResolverDescendantBoundary(t *testing.T, closedPipes bool) {
	t.Helper()
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "child")
	readyPath := filepath.Join(dir, "child-ready")
	allow := filepath.Join(dir, "parent-exit")
	child := "/bin/sleep 30 &"
	if closedPipes {
		child = "/bin/sleep 30 </dev/null >/dev/null 2>&1 &"
	}
	// Publish readiness only after printf has completed successfully. Opening
	// pidPath itself exposes an empty file before its bytes are written; that
	// is not a complete PID, nor may a valid-looking prefix pin a wrong child.
	script := "#!/bin/sh\n" + child + "\nprintf '%s' $! > " + ShellQuote(pidPath) + " && : > " + ShellQuote(readyPath) + "\nwhile [ ! -f " + ShellQuote(allow) + " ]; do /bin/sleep .01; done\nprintf configuration\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type identity struct {
		pid   int
		start string
	}
	pin := make(chan identity, 1)
	type observed struct {
		err          error
		state, start string
		statErr      error
	}
	done := make(chan observed, 1)
	read := func(pid int) (string, string, error) {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			return "", "", err
		}
		tail := strings.LastIndex(string(b), ") ")
		if tail < 0 {
			return "", "", errors.New("invalid process stat")
		}
		fields := strings.Fields(string(b)[tail+2:])
		if len(fields) < 20 {
			return "", "", errors.New("short process stat")
		}
		return fields[0], fields[19], nil
	}
	go func() {
		_, err := runSSHGContext(ctx, 2*time.Second, "fixture")
		var got observed
		got.err = err
		select {
		case id := <-pin:
			got.state, got.start, got.statErr = read(id.pid)
		default:
			got.statErr = errors.New("original child identity unavailable")
		}
		done <- got
	}()
	joined := false
	var original identity
	defer func() {
		cancel()
		if original.pid > 1 {
			state, start, err := read(original.pid)
			if err == nil && start == original.start && state != "Z" && state != "X" {
				syscall.Kill(original.pid, syscall.SIGKILL)
			}
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("owned resolver did not join")
			}
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		_, err := os.Stat(readyPath)
		if err == nil {
			body, err := os.ReadFile(pidPath)
			if err != nil {
				t.Fatal(err)
			}
			// A published malformed PID still fails immediately; only the
			// causal readiness marker is polled, never incomplete PID bytes.
			pid, err := strconv.Atoi(string(body))
			if err != nil || pid <= 1 {
				t.Fatalf("invalid original child PID %q", body)
			}
			_, start, err := read(pid)
			if err != nil {
				t.Fatal(err)
			}
			original = identity{pid, start}
			break
		}
		if !os.IsNotExist(err) || time.Now().After(deadline) {
			t.Fatalf("real child did not start: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	pin <- original
	if err := os.WriteFile(allow, []byte("exit"), 0600); err != nil {
		t.Fatal(err)
	}
	var got observed
	select {
	case got = <-done:
		joined = true
	case <-time.After(3 * time.Second):
		t.Fatal("resolver did not return")
	}
	if !os.IsNotExist(got.statErr) && (got.statErr != nil || got.start != original.start || got.state != "Z" && got.state != "X") {
		t.Fatalf("ENROLLMENT_RESOLVER_NOT_TERMINAL_AT_RESULT: state=%s start=%s error=%v", got.state, got.start, got.statErr)
	}
	if closedPipes && got.err != nil {
		t.Fatalf("successful parent failed: %v", got.err)
	}
}

func TestEnrollmentResolverRetiresInheritedPipeDescendant(t *testing.T) {
	enrollmentResolverDescendantBoundary(t, false)
}
func TestEnrollmentResolverSuccessfulParentRetiresClosedPipeChild(t *testing.T) {
	enrollmentResolverDescendantBoundary(t, true)
}

func TestEnrollmentResolverAcceptsExactOutputBound(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         int
	}{{"stdout", "#!/bin/sh\nexec /usr/bin/head -c 1048576 /dev/zero\n", 1048576}, {"stderr", "#!/bin/sh\nexec /usr/bin/head -c 65536 /dev/zero >&2\n", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(tc.script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			body, err := sshG(time.Second, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if len(body) != tc.want {
				t.Fatalf("output len%d want%d", len(body), tc.want)
			}
		})
	}
}
