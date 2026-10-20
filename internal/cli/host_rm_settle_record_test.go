package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// otherInstall replaces m's foreign certificate with another admission's
// install: node-x's certificate from this cluster's CA, not revoked, and its
// install record dated at. It returns the record and node-x's serial.
func (m *settleMachine) otherInstall(t *testing.T, at time.Time) (string, string) {
	t.Helper()
	x := installPair(t, m.f, m.f.opPKI, "node-x")
	m.bBytes = mustRead(t, filepath.Join(m.f.targetPKI, "host.crt"))
	rec := fmt.Sprintf("node-x %s %d cafecafe0000 installed\n", x, at.Unix())
	writeMarker(t, m.f.target, rec)
	return rec, x
}

// recordIs fails unless the machine's install record is want exactly, and
// neither a copy of it nor the settle's claim of the serial is left.
func (m *settleMachine) recordIs(t *testing.T, want string) {
	t.Helper()
	got, err := os.ReadFile(m.f.target.Path(addInstalledMarker))
	if err != nil || string(got) != want {
		t.Errorf("install record = %q (%v), want %q", got, err, want)
	}
	for _, p := range []string{settlePriorPath(m.serial), settleClaimPath(m.serial)} {
		if _, err := os.Stat(m.f.target.Path(p)); !os.IsNotExist(err) {
			t.Errorf("%s is left (stat: %v)", p, err)
		}
	}
}

// keyUntouched fails unless the machine's key is still the installed one.
func (m *settleMachine) keyUntouched(t *testing.T, key []byte) {
	t.Helper()
	if !bytes.Equal(mustRead(t, filepath.Join(m.f.targetPKI, "host.key")), key) {
		t.Error("the machine's installed key was replaced")
	}
}

// freshAdd is `lv host add node-7 root@10.0.0.9` from a replica that does
// not list node-x yet.
func (m *settleMachine) freshAdd(t *testing.T) (*hostAddTestClient, error) {
	t.Helper()
	m.f.target.Events = nil
	cl := &hostAddTestClient{target: m.f.target,
		hosts: []*pb.Host{{Name: "node-1", Address: "10.0.0.1", State: pb.HostState_HOST_ACTIVE, CertSerial: "a1"}}}
	return cl, HostAddOn(context.Background(), cl, m.f.target, "node-7", "10.0.0.9")
}

// Both reviews' I1 (Codex N2): the settle a fresh add's refusal prints,
// `lv host rm node-9 --serial S --address <ip>`, claimed the machine by
// replacing the install record it found, another admission's (node-x,
// minutes old, not a member this replica lists, not revoked), and its
// cleanup then deleted the record as its own claim. node-x's certificate
// stayed, but its record, by which a fresh add is kept out for an hour (the
// user's ruling), was gone: the next fresh add stopped node-x's daemon and
// installed over it. The settle's claim is a file of the serial's own now
// (settleClaimPath), and the install record is never written by it: node-x's
// record stays exactly through every failure and rerun. Composed with the
// next fresh add: refused while node-x's install is under an hour old,
// allowed from an hour (the control).
//
// Mutations: claim in the install record as before — every case loses
// node-x's record; drop the undo after a failed revocation — "the
// revocation fails" leaves the claim.
func TestHostRemoveSerial_SettlingKeepsAnotherAdmissionsInstallRecord(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	again := func(m *settleMachine) string {
		return "lv host rm node-9 --serial " + m.serial + " --address 10.0.0.9"
	}
	type schedule struct {
		name string
		// fail sets up a first run that fails; nil runs the settle once.
		fail func(t *testing.T, m *settleMachine, c *serialRemoveClient) (undo func())
		// revokes says whether the failed first run revoked the serial.
		revokes bool
	}
	for _, sc := range []schedule{
		{"the settle", nil, false},
		{"the publish fails, then its command", func(_ *testing.T, _ *settleMachine, c *serialRemoveClient) func() {
			c.publishErr = errors.New("unavailable")
			return func() { c.publishErr = nil }
		}, true},
		{"removing the staged files fails, then its command", func(t *testing.T, m *settleMachine, _ *serialRemoveClient) func() {
			m.dial(t, &failingShell{LocalAddTarget: m.f.target, kind: "unstage", nth: 1})
			return func() { m.dial(t, m.f.target) }
		}, true},
		{"removing the settle's claim fails, then its command", func(t *testing.T, m *settleMachine, _ *serialRemoveClient) func() {
			m.dial(t, &failingShell{LocalAddTarget: m.f.target, kind: "unstage", nth: 2})
			return func() { m.dial(t, m.f.target) }
		}, true},
		{"the revocation fails, then the command again", func(t *testing.T, m *settleMachine, _ *serialRemoveClient) func() {
			key := filepath.Join(m.f.opPKI, "ca.key")
			if err := os.Rename(key, key+".away"); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.Rename(key+".away", key); err != nil {
					t.Fatal(err)
				}
			}
		}, false},
	} {
		for _, age := range []time.Duration{5 * time.Minute, freshInstall - time.Second, freshInstall, 2 * time.Hour} {
			t.Run(fmt.Sprintf("%s, node-x installed %v ago", sc.name, age), func(t *testing.T) {
				fixAddClock(t, now)
				m := newSettleMachine(t)
				rec, x := m.otherInstall(t, now.Add(-age))
				key := mustRead(t, filepath.Join(m.f.targetPKI, "host.key"))
				c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
				if sc.fail != nil {
					undo := sc.fail(t, m, c)
					err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false)
					if err == nil {
						t.Fatal("the failing first run succeeded")
					}
					if sc.revokes && !strings.Contains(err.Error(), again(m)) {
						t.Errorf("first run = %v, want it to name %q", err, again(m))
					}
					if serialInCRL(t, m.f.opPKI, m.serial) != sc.revokes {
						t.Errorf("first run revoked %v, want %v", !sc.revokes, sc.revokes)
					}
					undo()
					if !sc.revokes {
						// Nothing was revoked: the record is as it was now.
						m.recordIs(t, rec)
					}
					// Between the runs, a fresh add installs nothing over node-x
					// while its record is under an hour old (or, nothing revoked,
					// while the stranded attempt's record stands).
					if !sc.revokes || age < freshInstall {
						if _, err := m.freshAdd(t); err == nil || reachedInstall(m.f.target.Events) {
							t.Errorf("a fresh add between the runs = %v, events %v: want refused, nothing stopped or installed",
								err, m.f.target.Events)
						}
						m.untouched(t)
						m.keyUntouched(t, key)
					}
				}
				if err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false); err != nil {
					t.Fatalf("the settle: %v", err)
				}
				if !serialInCRL(t, m.f.opPKI, m.serial) || serialInCRL(t, m.f.opPKI, x) {
					t.Errorf("revoked: stranded %v, node-x %v; want the stranded serial only",
						serialInCRL(t, m.f.opPKI, m.serial), serialInCRL(t, m.f.opPKI, x))
				}
				for _, p := range stagedOnTarget(t, m.f.target.Root) {
					if strings.Contains(filepath.Base(p), m.serial) {
						t.Errorf("left on the machine: %s", p)
					}
				}
				m.recordIs(t, rec)
				m.untouched(t)
				m.keyUntouched(t, key)

				cl, err := m.freshAdd(t)
				if age >= freshInstall {
					// The ruling: a stale install may be replaced.
					if err != nil {
						t.Fatalf("a fresh add over node-x's %v-old install: %v", age, err)
					}
					servesItsAdmittedPair(t, m.f.targetPKI, cl.admitted[0])
					return
				}
				if err == nil || !strings.Contains(err.Error(), x) {
					t.Errorf("a fresh add over node-x's %v-old install = %v, want refused naming %s", age, err, x)
				}
				if reachedInstall(m.f.target.Events) {
					t.Errorf("the fresh add stopped the daemon or installed: %v", m.f.target.Events)
				}
				m.recordIs(t, rec)
				m.untouched(t)
				m.keyUntouched(t, key)
			})
		}
	}
}

// Our review m4: a member H renewed from S1 to S2 keeps its install record of
// S1. Settling S1 (no row holds it, the record is its trace) revokes the
// superseded S1 and deleted H's record. The record stays now: it is an
// install, not S1's add's claim. A rerun of the command leaves it too.
//
// Mutation: release the record as a row's removal does (releaseRemoved) —
// H's record is deleted.
func TestHostRemoveSerial_SettlingARenewedMembersPredecessorKeepsItsInstallRecord(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fixAddClock(t, now)
	f := newAddFixture(t)
	s1 := installPair(t, f, f.opPKI, "node-h")
	s2 := installPair(t, f, f.opPKI, "node-h")
	crt := mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
	rec := fmt.Sprintf("node-h %s %d cafecafe0000 installed\n", s1, now.Add(-5*time.Minute).Unix())
	writeMarker(t, f.target, rec)
	m := &settleMachine{f: f, serial: s1, bBytes: crt}
	m.dial(t, f.target)
	c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{},
		hosts: []*pb.Host{{Name: "node-h", Address: "10.0.0.9", State: pb.HostState_HOST_ACTIVE, CertSerial: s2}}}
	for run := 1; run <= 2; run++ {
		if err := HostRemoveAdmission(context.Background(), c, "node-h", s1, "10.0.0.9", false); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if !serialInCRL(t, f.opPKI, s1) || serialInCRL(t, f.opPKI, s2) {
			t.Errorf("run %d: want S1 revoked and S2 not", run)
		}
		m.recordIs(t, rec)
		m.untouched(t)
	}
}

// strandedAddAs is strandedAdd under name.
func strandedAddAs(t *testing.T, f *addFixture, name string) string {
	t.Helper()
	f.target.FailSetup = fmt.Errorf("setup failed")
	if err := HostAddOn(context.Background(), f.client, f.target, name, "10.0.0.9"); err == nil {
		t.Fatal("the first add succeeded")
	}
	f.target.FailSetup = nil
	f.identityUnchanged(t)
	return f.client.admitted[0]
}

// Codex foreign-install I2 (our review m1): a host name with a blank is one
// an add records (quoted). `lv host rm 'a b'` of its joining row revoked the
// serial and removed the row, its cleanup failed, and it printed
// `lv host rm 'a b' --serial S --address <ip>` to finish; that command found
// no row and refused the name as not one the CLI takes, for good. With no row
// it takes a name that prints safely now, which the machine's trace must
// name exactly before a revocation; the printed command finishes the
// cleanup, with no row left and with a same-name row of another admission.
//
// Mutation: refuse a name validHostName refuses again — every retry fails;
// match the trace's name loosely (any record of the serial) — "a name the
// trace does not name" revokes.
func TestHostRemoveSerial_AnExistingNameWithABlankIsFinishedByItsPrintedCommand(t *testing.T) {
	const name = "a b"
	newMachine := func(t *testing.T) *settleMachine {
		f := newAddFixture(t)
		serial := strandedAddAs(t, f, name)
		writeMarker(t, f.target, markerLine(name, serial, 1, "0123456789ab", "installing")+"\n")
		installPair(t, f, "", "foreign")
		m := &settleMachine{f: f, serial: serial, bBytes: mustRead(t, filepath.Join(f.targetPKI, "host.crt"))}
		m.dial(t, f.target)
		return m
	}
	printed := func(m *settleMachine) string {
		return "lv host rm 'a b' --serial " + m.serial + " --address 10.0.0.9"
	}
	for _, sameName := range []bool{false, true} {
		t.Run(fmt.Sprintf("the row's removal, its cleanup fails, then its command; a same-name row %v", sameName), func(t *testing.T) {
			m := newMachine(t)
			m.dial(t, &failingShell{LocalAddTarget: m.f.target, kind: "unstage", nth: 1})
			c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}, gone: true,
				hosts: []*pb.Host{{Name: name, CertSerial: m.serial, State: pb.HostState_HOST_JOINING, Address: "10.0.0.9"}}}
			err := HostRemoveAdmission(context.Background(), c, name, m.serial, "10.0.0.9", false)
			if err == nil || !strings.Contains(err.Error(), printed(m)) || countCalls(c.calls, "remove") != 1 {
				t.Fatalf("first run = %v (calls %v), want the removal done and the cleanup failure naming %q",
					err, c.calls, printed(m))
			}
			if sameName {
				c.gone = false
				c.hosts = []*pb.Host{{Name: name, CertSerial: "b0b0", State: pb.HostState_HOST_ACTIVE, Address: "10.0.0.9"}}
			}
			m.dial(t, m.f.target)
			if err := HostRemoveAdmission(context.Background(), c, name, m.serial, "10.0.0.9", false); err != nil {
				t.Fatalf("`%s`: %v", printed(m), err)
			}
			if countCalls(c.calls, "remove") != 1 || serialInCRL(t, m.f.opPKI, "b0b0") {
				t.Errorf("calls %v, b0b0 revoked %v: the retry touched the other admission", c.calls, serialInCRL(t, m.f.opPKI, "b0b0"))
			}
			m.settledClean(t)
		})
	}
	t.Run("no row from the start", func(t *testing.T) {
		m := newMachine(t)
		c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
		if err := HostRemoveAdmission(context.Background(), c, name, m.serial, "10.0.0.9", false); err != nil {
			t.Fatalf("settle of %q: %v", name, err)
		}
		if !serialInCRL(t, m.f.opPKI, m.serial) {
			t.Error("not revoked")
		}
		m.settledClean(t)
	})
	for _, other := range []string{"a", "a  b", "b"} {
		t.Run("a name the trace does not name: "+other, func(t *testing.T) {
			m := newMachine(t)
			c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
			err := HostRemoveAdmission(context.Background(), c, other, m.serial, "10.0.0.9", false)
			if err == nil || !strings.Contains(err.Error(), "no staged file") {
				t.Fatalf("settle of %q = %v, want refused for no trace", other, err)
			}
			if serialInCRL(t, m.f.opPKI, m.serial) || countCalls(c.calls, "publish") != 0 {
				t.Error("revoked or published")
			}
		})
	}
	// Still refused before anything: names that do not print safely, or read
	// as a flag.
	for _, bad := range []string{"", "a\nb", "a\x1bb", "-a", strings.Repeat("a", 300)} {
		c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
		if err := HostRemoveAdmission(context.Background(), c, bad, "a1a1", "10.0.0.9", false); err == nil {
			t.Errorf("name %q accepted", bad)
		}
		if len(c.preflight) != 0 || len(c.calls) != 0 {
			t.Errorf("name %q reached the cluster: %v", bad, c.calls)
		}
	}
}

// The copy a settle's claim kept (settlePriorPath) is put back only while it
// is still the one read: one that changed between the read and the locked
// command (another settle of the serial, say) is not put back over the
// record, and neither the record nor the copy is changed.
//
// Mutation: drop the copy's compare from releaseInstallRecord's condition —
// the copy read first is written over the record and the newer copy removed.
func TestReleaseInstallRecord_PutsBackOnlyTheCopyAsRead(t *testing.T) {
	const serial = "a0a0"
	for _, how := range []releaseMode{releaseSettled, releaseRemoved} {
		root := t.TempDir()
		r := &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "etc", "litevirt", "pki")}
		claim := markerLine("node-9", serial, 1_800_000_000, "0123456789ab", "installing") + "\n"
		writeMarker(t, r, claim)
		copyPath := r.Path(settlePriorPath(serial))
		if err := os.WriteFile(copyPath, []byte("node-x b0b0 1799999700 cafecafe0000 installed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		newer := "node-y c0c0 1799999800 beefbeef0000 installed\n"
		afterMarkerRead = func() {
			if err := os.WriteFile(copyPath, []byte(newer), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		err := releaseInstallRecord(r, serial, how)
		afterMarkerRead = nil
		if err != nil {
			t.Fatalf("mode %d: %v", how, err)
		}
		if got := string(mustRead(t, r.Path(addInstalledMarker))); got != claim {
			t.Errorf("mode %d: install record = %q, want the claim %q left", how, got, claim)
		}
		if got, err := os.ReadFile(copyPath); err != nil || string(got) != newer {
			t.Errorf("mode %d: copy = %q (%v), want the newer copy %q left", how, got, err, newer)
		}
	}
}
