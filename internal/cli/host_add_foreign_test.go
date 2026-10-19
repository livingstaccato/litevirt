package cli

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// installPair writes a certificate and key minted by the CA in caDir (a new
// CA when caDir is "") as the target's host.crt and host.key, and returns
// the certificate's serial.
func installPair(t *testing.T, f *addFixture, caDir, name string) string {
	t.Helper()
	if caDir == "" {
		caDir = t.TempDir()
		if err := pki.GenerateCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key")); err != nil {
			t.Fatal(err)
		}
	}
	tmp := t.TempDir()
	if err := pki.GenerateHostCert(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"),
		filepath.Join(tmp, "h.crt"), filepath.Join(tmp, "h.key"), name, net.IPv4(10, 0, 0, 9)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"crt", "key"} {
		if err := os.WriteFile(filepath.Join(f.targetPKI, "host."+n), mustRead(t, filepath.Join(tmp, "h."+n)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return installedSerial(mustRead(t, filepath.Join(tmp, "h.crt")))
}

// revoke adds serial to the operator's CRL, as `lv host rm` does.
func revoke(t *testing.T, opPKI, serial string) {
	t.Helper()
	if err := pki.AppendToCRL(filepath.Join(opPKI, "ca.crt"), filepath.Join(opPKI, "ca.key"),
		filepath.Join(opPKI, "crl.pem"), serial); err != nil {
		t.Fatal(err)
	}
}

// reachedInstall reports whether events show the add stopping the daemon or
// installing anything.
func reachedInstall(events []string) bool {
	for _, e := range events {
		if e == "sh install" || e == "sh binary" || strings.Contains(e, "systemctl stop") {
			return true
		}
	}
	return false
}

// strandedAdd runs a first add of node-9 that is admitted and whose setup
// fails: its rollback puts the machine's identity back and leaves the
// admitted pair staged, and node-9 is joining. It returns the admitted
// serial.
func strandedAdd(t *testing.T, f *addFixture) string {
	t.Helper()
	f.target.FailSetup = fmt.Errorf("setup failed")
	if err := f.add(t); err == nil {
		t.Fatal("the first add succeeded")
	}
	f.target.FailSetup = nil
	f.identityUnchanged(t)
	return f.client.admitted[0]
}

// Codex hostadd-foreign I2, findings (a), (b), (c), (e): a retry of a
// stranded admission compared the machine's certificate with what IT found
// when it began, so a certificate B another installer put there after the
// first attempt was the retry's baseline: the retry reused the staged pair,
// the same-name record returned before any revocation check, and it
// stopped the daemon and installed over B. The CRL check, where reached,
// tested the record's serial, not B. A retry keeps the first attempt's
// recorded expectation (what the machine served before it) now: B is
// neither that nor the admission's certificate nor revoked by this
// cluster, so the retry stops nothing, installs nothing, and names the one
// command that settles the admission while leaving B, not a rerun.
//
// Mutations: take the retry's own observation as the expectation — every
// case installs over B; test the record's serial for revocation instead of
// the installed certificate — "another name's revoked install" installs
// over B.
func TestHostAdd_ARetryNeverInstallsOverACertificateNotProvenItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker func(t *testing.T, f *addFixture, serial string) string
	}{
		{"no record", func(*testing.T, *addFixture, string) string { return "" }},
		{"the stranded add's stale claim", func(_ *testing.T, _ *addFixture, serial string) string {
			return fmt.Sprintf("node-9 %s 1 deadbeef0000 installing\n", serial)
		}},
		{"another name's revoked install", func(t *testing.T, f *addFixture, _ string) string {
			x := installPair(t, f, f.opPKI, "node-x")
			revoke(t, f.opPKI, x)
			return fmt.Sprintf("node-x %s %d cafecafe0000 installed\n", x, time.Now().Unix())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddFixture(t)
			serial := strandedAdd(t, f)
			if m := tc.marker(t, f, serial); m != "" {
				writeMarker(t, f.target, m)
			}
			b := installPair(t, f, "", "foreign")
			bBytes := mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
			f.target.Events = nil
			err := f.add(t)
			if err == nil {
				t.Fatal("the retry installed over a certificate nothing proves is its own")
			}
			for _, want := range []string{b, "lv host rm node-9 --serial " + serial + " --address 10.0.0.9"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("retry = %v, want it to name %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "lv host add") {
				t.Errorf("retry = %v: it advertises a rerun", err)
			}
			if reachedInstall(f.target.Events) {
				t.Errorf("the retry stopped the daemon or installed: %v", f.target.Events)
			}
			if !bytes.Equal(mustRead(t, filepath.Join(f.targetPKI, "host.crt")), bBytes) {
				t.Error("the machine's certificate B was replaced")
			}
		})
	}
}

// The control: a certificate this cluster's CA issued and revoked (a host
// removed with `lv host rm`) is proven to be no live admission's, and a
// retry finishes the stranded add over it; so does a retry that finds what
// the first attempt found. A foreign CA's certificate with a revoked serial
// is not this cluster's revocation, and is refused.
//
// Mutation: drop the issuer check — "a foreign certificate of a revoked
// serial" installs.
func TestHostAdd_ARetryFinishesOverWhatItProves(t *testing.T) {
	t.Run("revoked by this cluster", func(t *testing.T) {
		f := newAddFixture(t)
		serial := strandedAdd(t, f)
		revoke(t, f.opPKI, installPair(t, f, f.opPKI, "removed"))
		if err := f.add(t); err != nil {
			t.Fatalf("retry over a revoked certificate: %v", err)
		}
		servesItsAdmittedPair(t, f.targetPKI, serial)
	})
	t.Run("what the first attempt found", func(t *testing.T) {
		f := newAddFixture(t)
		serial := strandedAdd(t, f)
		otherOperator(t, f.opPKI)
		if err := f.add(t); err != nil {
			t.Fatalf("retry over the machine as the first attempt found it: %v", err)
		}
		servesItsAdmittedPair(t, f.targetPKI, serial)
	})
	t.Run("a foreign certificate of a revoked serial", func(t *testing.T) {
		f := newAddFixture(t)
		strandedAdd(t, f)
		revoke(t, f.opPKI, installPair(t, f, "", "foreign"))
		f.target.Events = nil
		if err := f.add(t); err == nil || reachedInstall(f.target.Events) {
			t.Fatalf("retry over another CA's certificate = %v (events %v), want refused", err, f.target.Events)
		}
	})
}

// Codex hostadd-foreign (c): the stranded admission's row not listed (the
// replica asked has not received it), the retry was a fresh add with its
// own baseline, and installed over B. The first attempt's record on the
// machine still says what it found: a fresh add that finds an unsettled
// attempt's record and a certificate that attempt did not find changes
// nothing, not even an admission.
//
// Mutation: skip the record check — the fresh add installs over B.
func TestHostAdd_AFreshAddKeepsAnUnsettledAttemptsExpectation(t *testing.T) {
	f := newAddFixture(t)
	serial := strandedAdd(t, f)
	installPair(t, f, "", "foreign")
	bBytes := mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
	lagging := &hostAddTestClient{target: f.target, hosts: f.client.hosts[:1]}
	f.client = lagging
	f.target.Events = nil
	err := f.add(t)
	if err == nil || !strings.Contains(err.Error(), "lv host rm node-9 --serial "+serial+" --address 10.0.0.9") {
		t.Fatalf("fresh add = %v, want the refusal naming the unsettled admission", err)
	}
	if len(lagging.admitted) != 0 || reachedInstall(f.target.Events) {
		t.Errorf("admitted %v, events %v: want nothing admitted or installed", lagging.admitted, f.target.Events)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(f.targetPKI, "host.crt")), bBytes) {
		t.Error("the machine's certificate B was replaced")
	}
}

// Codex hostadd-foreign (e): a record of the same name returned before the
// revocation check, so an install under the name by another admission, an
// unrevoked certificate the machine serves, was replaced by a fresh add of
// the name. The same name decides nothing now: another admission's recent
// install that this cluster has not revoked keeps the machine.
//
// Mutation: restore the same-name return — the add installs over it.
func TestHostAdd_TheSameNameDoesNotBypassAnotherAdmissionsInstall(t *testing.T) {
	f := newAddFixture(t)
	x := installPair(t, f, f.opPKI, "node-9")
	xBytes := mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
	writeMarker(t, f.target, fmt.Sprintf("node-9 %s %d cafecafe0000 installed\n", x, time.Now().Unix()))
	err := f.add(t)
	if err == nil || !strings.Contains(err.Error(), x) || !strings.Contains(err.Error(), "installs nothing") {
		t.Fatalf("add = %v, want the refusal naming the other admission's certificate", err)
	}
	if !strings.Contains(err.Error(), "lv host rm node-9 --serial "+f.client.admitted[0]) {
		t.Errorf("add = %v, want it to name the removal of its own admission by serial", err)
	}
	if reachedInstall(f.target.Events) {
		t.Errorf("installed over another admission's install: %v", f.target.Events)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(f.targetPKI, "host.crt")), xBytes) {
		t.Error("the other admission's certificate was replaced")
	}
}
