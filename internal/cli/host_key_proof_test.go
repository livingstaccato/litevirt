package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// stubOpenSSL installs a script as the machine's openssl.
func stubOpenSSL(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "openssl")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := openSSLBin
	openSSLBin = p
	t.Cleanup(func() { openSSLBin = old })
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Re-review 2 follow-up a (its TestRR2_ReplayedSignatureIsRefused): an
// openssl that records the first real signature and replays it on every
// later challenge. Once the real key is gone, the replayed signature proves
// nothing, because each challenge is a fresh nonce.
//
// Mutation: a fixed (all-zero) nonce — the replay verifies, red.
func TestKeyProof_AReplayedSignatureIsRefused(t *testing.T) {
	f := newAddFixture(t)
	crt := parseCerts(f.before["host.crt"])[0]
	rec := filepath.Join(t.TempDir(), "rec.bin")
	stubOpenSSL(t, `if [ -s '`+rec+`' ]; then cat '`+rec+`'; else /usr/bin/openssl "$@" > '`+rec+`' && cat '`+rec+`'; fi`)
	if proved, err := signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt); !proved || err != nil {
		t.Fatalf("recording run: proved %v, %v", proved, err)
	}
	_, other := ourSigned(t, f, "host")
	writeFile(t, filepath.Join(f.targetPKI, "host.key"), other)
	if proved, err := signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt); proved || err == nil {
		t.Fatalf("replayed signature: proved %v, %v; want refused", proved, err)
	}
	anotherClustersState(t, f)
	f.before = map[string][]byte{"host.crt": f.before["host.crt"]}
	refusedUntouched(t, f, f.add(t), "does not sign")
}

// Re-review 2 follow-up a (its TestRR2_PKIDirShellInjection): the config's
// pki_dir comes from the machine, and the challenge command names the key
// under it. Quotes, $(...), ; and backticks in it run nothing, and the proof
// still goes through openssl over that path.
//
// Mutation: leave the key path unquoted in keyProofCmd — a command runs, red.
func TestKeyProof_AnOddPKIDirRunsNothing(t *testing.T) {
	pwned := filepath.Join(t.TempDir(), "pwned-"+randHex(t, 4))
	f := newAddFixture(t)
	crt, key := f.before["host.crt"], f.before["host.key"]
	noIdentity(t, f)
	anotherClustersState(t, f)
	ourCAOnTarget(t, f)
	evil := "/srv/a'$(touch " + pwned + ")'b;touch " + pwned + ";`touch " + pwned + "`"
	writeTargetConfig(t, f, "host_name: node-5\npki_dir: \""+strings.ReplaceAll(evil, `"`, `\"`)+"\"\n", 0o644)
	dir := mkdirOnTarget(t, f.target, evil)
	writeFile(t, filepath.Join(dir, "ca.crt"), mustRead(t, filepath.Join(f.opPKI, "ca.crt")))
	writeFile(t, filepath.Join(dir, "host.crt"), crt)
	writeFile(t, filepath.Join(dir, "host.key"), key)
	_ = f.add(t) // accepted or not, nothing may run
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("a command in pki_dir ran")
	}
	if proved, err := signedChallenge(f.target, filepath.Join(evil, "host.key"), parseCerts(crt)[0]); !proved || err != nil {
		t.Fatalf("challenge over the odd path: proved %v, %v", proved, err)
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("a command in the key path ran")
	}
}

// Re-review 2 follow-up b: a host.key that is not a regular file (a link to
// /dev/zero, a FIFO) hung the preflight in openssl. It is refused before
// openssl runs, and the add is refused, promptly.
//
// Mutation: drop the [ -f ] test — the FIFO case blocks until the test's
// deadline, red.
func TestKeyProof_ASpecialFileIsRefusedWithoutRunningOpenSSL(t *testing.T) {
	for _, kind := range []string{"link to /dev/zero", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			f := newAddFixture(t)
			crt := parseCerts(f.before["host.crt"])[0]
			ran := filepath.Join(t.TempDir(), "ran")
			stubOpenSSL(t, `touch '`+ran+`'; exec /usr/bin/openssl "$@"`)
			key := filepath.Join(f.targetPKI, "host.key")
			if err := os.Remove(key); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(key, 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Symlink("/dev/zero", key); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan struct{})
			var proved bool
			var err error
			go func() {
				defer close(done)
				proved, err = signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt)
			}()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("the challenge hung on a key that is not a regular file")
			}
			if proved || err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("proved %v, %v; want refused as not a regular file", proved, err)
			}
			if _, serr := os.Stat(ran); serr == nil {
				t.Error("openssl ran on a key that is not a regular file")
			}
		})
	}
}

// Follow-up b, the bound: an openssl that does not return is ended after
// keyProofTimeout, and the challenge answers NOSIGN (the in-memory
// comparison takes over) instead of hanging the add.
//
// Mutation: drop the timeout — the run blocks past the test's deadline, red.
func TestKeyProof_AHungOpenSSLIsBounded(t *testing.T) {
	f := newAddFixture(t)
	crt := parseCerts(f.before["host.crt"])[0]
	stubOpenSSL(t, `exec sleep 60`)
	old := keyProofTimeout
	keyProofTimeout = 1
	t.Cleanup(func() { keyProofTimeout = old })
	start := time.Now()
	done := make(chan struct{})
	var proved bool
	var err error
	go func() {
		defer close(done)
		proved, err = signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the challenge was not bounded")
	}
	if proved || err != nil {
		t.Fatalf("proved %v, %v; want neither (fall back to the in-memory comparison)", proved, err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("took %v", d)
	}
	// End to end, the fallback then proves the real key.
	anotherClustersState(t, f)
	if err := f.add(t); err != nil {
		t.Fatalf("add after a bounded openssl: %v", err)
	}
}

// Follow-up c: what openssl signs is the challenge with its domain prefix,
// never a bare nonce, and the signature is verified over the same bytes.
//
// Mutation: drop the prefix on both sides — the recorded input has none,
// red.
func TestKeyProof_SignsADomainSeparatedChallenge(t *testing.T) {
	f := newAddFixture(t)
	crt := parseCerts(f.before["host.crt"])[0]
	in := filepath.Join(t.TempDir(), "in")
	stubOpenSSL(t, `tee '`+in+`' | /usr/bin/openssl "$@"`)
	if proved, err := signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt); !proved || err != nil {
		t.Fatalf("proved %v, %v", proved, err)
	}
	got := string(mustRead(t, in))
	if !strings.HasPrefix(got, "litevirt-host-add-proof-v1:") || len(got) != len("litevirt-host-add-proof-v1:")+64 {
		t.Fatalf("signed %q, want the domain prefix and a 32-byte hex nonce", got)
	}
}

// A target with no `timeout` binary drops the remote bound, so a hung
// openssl must still be ended by the client's own deadline. The proof
// refuses (the connection is not trusted to answer a key read either); it
// never waits forever, and it leaves nothing running: the shell, the
// command substitution's subshell, the hung openssl, base64 and tr are all
// killed before it returns.
//
// Mutations: run the command with no client-side deadline — the challenge
// blocks on the 30s sleep past the test's limit, red. Give up at the
// deadline without stopping the command (7f288a4bf) — the command runs in
// the test's own process group and the hung openssl outlives the proof, red.
func TestKeyProof_NoTimeoutBinaryStillBoundedByClientDeadline(t *testing.T) {
	assertHungProofLeavesNothing(t, []string{"sh", "base64", "tr", "printf", "sleep"},
		func(marker string) string { return `echo $$ > '` + marker + `'; exec sleep 30` })
}

// A target WITH coreutils timeout, and an openssl that ignores SIGTERM (the
// rc8 lab drill 3 leftover). Without --foreground, timeout moves itself and
// openssl to a process group of their own, so a kill of the command's group
// missed both, and they ran on after the proof refused. Now timeout stays in
// the group, and the command's whole session is killed in any case.
//
// Mutations: plain `timeout 30` together with a group-only kill (d2fa715ff)
// — timeout and openssl outlive the proof, red. Either change alone is
// enough to pass; each is pinned by its own test (the session kill by
// TestLocalShellContext_KillsTheSession and the internal/ssh session tests,
// --foreground by TestKeyProofCmd_TimeoutStaysInTheGroup).
func TestKeyProof_RealTimeoutAndATermIgnoringOpenSSLLeaveNothing(t *testing.T) {
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("no timeout(1)")
	}
	assertHungProofLeavesNothing(t, []string{"sh", "base64", "tr", "printf", "sleep", "timeout"},
		func(marker string) string { return `trap '' TERM; echo $$ > '` + marker + `'; exec sleep 30` })
}

// assertHungProofLeavesNothing runs the challenge on a machine whose PATH
// holds only tools, with an openssl stub that records its pid in the file it
// is given and hangs, and asserts that the proof refuses at the client's
// deadline and that nothing in the stub's process group or session, nor the
// stub, is left running.
func assertHungProofLeavesNothing(t *testing.T, tools []string, stub func(marker string) string) {
	t.Helper()
	f := newAddFixture(t)
	crt := parseCerts(f.before["host.crt"])[0]
	bin := t.TempDir()
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	if _, err := exec.LookPath("timeout"); err == nil != slices.Contains(tools, "timeout") {
		t.Fatalf("timeout on the fake target: %v, want %v", err == nil, slices.Contains(tools, "timeout"))
	}
	marker := filepath.Join(t.TempDir(), "openssl.pid")
	stubOpenSSL(t, stub(marker))
	old := keyProofDeadline
	// Headroom for a saturated host to start the stub before the deadline.
	keyProofDeadline = 3 * time.Second
	t.Cleanup(func() { keyProofDeadline = old })

	start := time.Now()
	done := make(chan struct{})
	var proved bool
	var err error
	go func() {
		defer close(done)
		proved, err = signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt)
	}()
	// The hung openssl's pid, process group and session, read while it runs.
	pid, pgid, sid := 0, 0, 0
	for pid == 0 && time.Since(start) < 10*time.Second {
		if b, rerr := os.ReadFile(marker); rerr == nil && strings.HasSuffix(string(b), "\n") {
			if pid, rerr = strconv.Atoi(strings.TrimSpace(string(b))); rerr != nil {
				t.Fatal(rerr)
			}
			if pgid, rerr = syscall.Getpgid(pid); rerr != nil {
				t.Fatalf("the stub (pid %d) is already gone: %v", pid, rerr)
			}
			if sid, rerr = unix.Getsid(pid); rerr != nil {
				t.Fatalf("the stub (pid %d) is already gone: %v", pid, rerr)
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the proof was not bounded by the client's deadline")
	}
	if proved || err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("proved %v, %v; want a refusal naming the deadline", proved, err)
	}
	if d := time.Since(start); d > 12*time.Second {
		t.Errorf("took %v", d)
	}
	if pid == 0 {
		t.Fatal("the stub openssl never ran")
	}
	if own, _ := unix.Getsid(0); pgid == syscall.Getpgrp() || sid == own {
		t.Fatalf("the challenge ran in the test's own process group (%d) or session (%d): it cannot be killed whole", pgid, sid)
	}
	if live := liveProcesses(t, pgid, sid, pid); len(live) > 0 {
		t.Fatalf("after the proof returned, still running: %v", live)
	}
}

// The local target kills the command's whole session at its deadline, so a
// child that moved to a process group of its own is killed too.
//
// Mutation: kill only the command's process group (cmdbound.Command) —
// timeout and its TERM-ignoring child run on, red.
func TestLocalShellContext_KillsTheSession(t *testing.T) {
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("no timeout(1)")
	}
	marker := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := (&LocalAddTarget{}).ShellContext(ctx, keyProofKind,
			`timeout 30 sh -c 'trap "" TERM; echo $$ > '"'`+marker+`'"'; exec sleep 30'`)
		done <- err
	}()
	pid, pgid, sid := 0, 0, 0
	for pid == 0 && time.Since(start) < 10*time.Second {
		if b, rerr := os.ReadFile(marker); rerr == nil && strings.HasSuffix(string(b), "\n") {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			pgid, _ = syscall.Getpgid(pid)
			sid, _ = unix.Getsid(pid)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a killed command reported success")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("ShellContext was not bounded by its context")
	}
	if pid == 0 || sid <= 0 {
		t.Fatal("the command never ran")
	}
	if own, _ := unix.Getsid(0); sid == own {
		t.Fatalf("the command ran in the test's own session (%d)", sid)
	}
	if live := liveProcesses(t, pgid, sid, pid); len(live) > 0 {
		t.Fatalf("after ShellContext returned, still running: %v", live)
	}
}

// keyProofCmd runs openssl under `timeout --foreground` where timeout takes
// it, so timeout does not move itself and openssl out of the command's
// process group.
//
// Mutation: plain `timeout 30` — timeout's group is not the shell's, red.
func TestKeyProofCmd_TimeoutStaysInTheGroup(t *testing.T) {
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("no timeout(1)")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "host.key")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "groups")
	// The stub records its own process group.
	stubOpenSSL(t, `read -r l < /proc/$$/stat; set -- ${l##*") "}; echo "$3" > '`+out+`'`)
	cmd := exec.Command("sh", "-c", keyProofCmd(key, "c"))
	if b, err := cmd.Output(); err != nil || strings.TrimSpace(string(b)) != "NOSIGN" {
		t.Fatalf("%q, %v", b, err)
	}
	fs := strings.Fields(string(mustRead(t, out)))
	if len(fs) != 1 || fs[0] != strconv.Itoa(syscall.Getpgrp()) {
		t.Fatalf("openssl ran in group %v; want the command's group %d", fs, syscall.Getpgrp())
	}
}

// liveProcesses lists the processes, other than zombies, that are in process
// group pgid or session sid or are pid, a moment after a kill (a killed
// process may need a few milliseconds to exit). It reads /proc.
func liveProcesses(t *testing.T, pgid, sid, pid int) []string {
	t.Helper()
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc to read process groups from")
	}
	var live []string
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		live = live[:0]
		dirs, _ := filepath.Glob("/proc/[0-9]*/stat")
		for _, statPath := range dirs {
			b, err := os.ReadFile(statPath)
			if err != nil {
				continue // exited meanwhile
			}
			s := string(b)
			k := strings.LastIndexByte(s, ')')
			if k < 0 {
				continue
			}
			// After "pid (comm)": state, ppid, pgrp, session.
			fs := strings.Fields(s[k+1:])
			if len(fs) < 4 || fs[0] == "Z" {
				continue
			}
			p, _ := strconv.Atoi(strings.Fields(s)[0])
			g, _ := strconv.Atoi(fs[2])
			sess, _ := strconv.Atoi(fs[3])
			if g == pgid || sess == sid || p == pid {
				live = append(live, s[:k+1])
			}
		}
		if len(live) == 0 || time.Now().After(deadline) {
			return live
		}
	}
}
