package cli

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
