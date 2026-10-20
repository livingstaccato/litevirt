package cli

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/safename"
	"google.golang.org/grpc"
)

// strandedOn adds name to f's machine with a setup that fails, as
// strandedAdd does, and returns the admitted serial.
func strandedOn(t *testing.T, f *addFixture, name string) string {
	t.Helper()
	f.target.FailSetup = errors.New("setup failed")
	if err := HostAddOn(context.Background(), f.client, f.target, name, "10.0.0.9"); err == nil {
		t.Fatalf("the add of %s succeeded", name)
	}
	f.target.FailSetup = nil
	return f.client.admitted[len(f.client.admitted)-1]
}

// strandedMachine is f's machine with the stranded admissions of names
// (their rows gone), and node-x installed there at installed: its record
// and serial are returned.
func strandedMachine(t *testing.T, names []string, installed time.Time) (*addFixture, []string, string, string) {
	t.Helper()
	f := newAddFixture(t)
	var serials []string
	for _, n := range names {
		serials = append(serials, strandedOn(t, f, n))
		f.client.hosts = f.client.hosts[:1] // its row is gone (the settle's reason)
	}
	x := installPair(t, f, f.opPKI, "node-x")
	rec := fmt.Sprintf("node-x %s %d cafecafe0000 installed\n", x, installed.Unix())
	writeMarker(t, f.target, rec)
	return f, serials, x, rec
}

// dialTo makes every `lv host rm` reach *r, or fail to when *down is set.
func dialTo(t *testing.T, r *addRemote, down *bool) {
	t.Helper()
	old := dialAdmissionMachine
	dialAdmissionMachine = func(string) (addRemote, func(), error) {
		if *down {
			return nil, nil, errors.New("no route to host")
		}
		return *r, func() {}, nil
	}
	t.Cleanup(func() { dialAdmissionMachine = old })
}

// freshAddOn is `lv host add node-7 root@10.0.0.9` from a replica that lists
// none of the machine's admissions.
func freshAddOn(t *testing.T, f *addFixture) error {
	t.Helper()
	f.target.Events = nil
	cl := &hostAddTestClient{target: f.target,
		hosts: []*pb.Host{{Name: "node-1", Address: "10.0.0.1", State: pb.HostState_HOST_ACTIVE, CertSerial: "a1"}}}
	return HostAddOn(context.Background(), cl, f.target, "node-7", "10.0.0.9")
}

// Round-4 review I1: two settles on one machine (S of node-9, T of node-8),
// both with a publish outage, T's taken more than staleClaim after S's.
// Their claims were the install record, each keeping the one it replaced:
// T's copy held S's claim, and S's rerun, finding T's claim, dropped the
// copy that held node-x's record. A settle's claim is its serial's own file
// now and the install record is never written by it, so node-x's record
// stays exactly, in either order of the reruns, and keeps the fresh add out.
//
// Mutation: claim in the install record as well — the record is the
// claim after the first run.
func TestHostRemoveSerial_TwoInterleavedSettlesKeepTheInstallRecord(t *testing.T) {
	for _, sFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("S's rerun first %v", sFirst), func(t *testing.T) {
			t0 := time.Unix(1_800_000_000, 0)
			fixAddClock(t, t0)
			f, serials, x, rec := strandedMachine(t, []string{"node-9", "node-8"}, t0.Add(-5*time.Minute))
			S, T := serials[0], serials[1]
			crt := mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
			var r addRemote = f.target
			down := false
			dialTo(t, &r, &down)
			c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{publishErr: errors.New("unavailable")}}
			check := func(step string) {
				t.Helper()
				if got := string(mustRead(t, f.target.Path(addInstalledMarker))); got != rec {
					t.Fatalf("%s: install record = %q, want node-x's %q", step, got, rec)
				}
			}
			if err := HostRemoveAdmission(context.Background(), c, "node-9", S, "10.0.0.9", false); err == nil {
				t.Fatal("S with publish down succeeded")
			}
			check("S's first run")
			fixAddClock(t, t0.Add(11*time.Minute))
			if err := HostRemoveAdmission(context.Background(), c, "node-8", T, "10.0.0.9", false); err == nil {
				t.Fatal("T with publish down succeeded")
			}
			check("T's first run")
			c.publishErr = nil
			order := []struct{ name, serial string }{{"node-9", S}, {"node-8", T}}
			if !sFirst {
				order[0], order[1] = order[1], order[0]
			}
			for _, o := range order {
				if err := HostRemoveAdmission(context.Background(), c, o.name, o.serial, "10.0.0.9", false); err != nil {
					t.Fatalf("rerun of %s: %v", o.serial, err)
				}
				check("rerun of " + o.serial)
			}
			if err := HostRemoveAdmission(context.Background(), c, "node-9", S, "10.0.0.9", false); err != nil {
				t.Fatalf("S's command once more: %v", err)
			}
			check("S's command once more")
			for _, s := range serials {
				if !serialInCRL(t, f.opPKI, s) {
					t.Errorf("%s not revoked", s)
				}
				if _, err := os.Stat(f.target.Path(settleClaimPath(s))); !os.IsNotExist(err) {
					t.Errorf("the settle's claim of %s is left", s)
				}
			}
			fixAddClock(t, t0.Add(12*time.Minute))
			if err := freshAddOn(t, f); err == nil || !strings.Contains(err.Error(), x) || reachedInstall(f.target.Events) {
				t.Errorf("a fresh add over node-x's 17m-old install = %v, events %v: want refused naming %s", err, f.target.Events, x)
			}
			check("the fresh add")
			if got := mustRead(t, filepath.Join(f.targetPKI, "host.crt")); string(got) != string(crt) {
				t.Error("node-x's certificate was replaced")
			}
		})
	}
}

// The coordinator's round-5 brief: two or three settles and one fresh add,
// interleaved at random, each settle run failing at a random step (no
// route, its claim command lost, the revocation, the publication, each
// cleanup command, the listing of its records, or dying right after its
// claim) and rerun until it finishes. After every step the machine's install
// record is byte for byte what its last installer wrote (node-x's, or the
// fresh add's when it was allowed), with its age, and its certificate is
// that install's. The fresh add installs exactly when the ruling allows it:
// every stranded admission is revoked and node-x's install is an hour old or
// more. At the end, every settle has revoked its serial and left nothing of
// it; and, where no fresh add installed, the hour is the line: refused one
// second before it, installed at it.
//
// Mutations: claim in the install record (as round 4 did) — a step finds the
// claim; release any record of the serial in a settle (releaseRemoved) or
// a record of any serial — the fresh add's or node-x's record goes; never
// drop the settle's claim — "left" at the end.
func TestHostRemoveSerial_InterleavedSettlesAndAFreshAddKeepEveryRecord(t *testing.T) {
	ages := []time.Duration{5 * time.Minute, 30 * time.Minute, freshInstall - time.Second, freshInstall, 2 * time.Hour}
	for seed := int64(1); seed <= 60; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			t0 := time.Unix(1_800_000_000, 0)
			clock := t0
			old := addNow
			addNow = func() time.Time { return clock }
			t.Cleanup(func() { addNow = old })

			names := []string{"node-9", "node-8", "node-6"}[:2+rng.Intn(2)]
			xAt := t0.Add(-ages[rng.Intn(len(ages))])
			f, serials, x, rec := strandedMachine(t, names, xAt)
			want, wantCrt := rec, mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
			var r addRemote = f.target
			down := false
			dialTo(t, &r, &down)
			c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
			var log []string
			check := func(step string) {
				t.Helper()
				log = append(log, step)
				got, _, _ := f.target.ReadFile(addInstalledMarker)
				if string(got) != want {
					t.Fatalf("after %v: install record = %q, want %q", log, got, want)
				}
				if got := mustRead(t, filepath.Join(f.targetPKI, "host.crt")); string(got) != string(wantCrt) {
					t.Fatalf("after %v: the installed certificate was replaced", log)
				}
				if left, _ := filepath.Glob(f.target.Path(addInstalledMarker) + ".settle-*"); len(left) != 0 {
					t.Fatalf("after %v: a copy of the record was written: %v", log, left)
				}
				if serialInCRL(t, f.opPKI, x) {
					t.Fatalf("after %v: node-x's certificate was revoked", log)
				}
			}
			allRevoked := func() bool {
				for _, s := range serials {
					if !serialInCRL(t, f.opPKI, s) {
						return false
					}
				}
				return true
			}
			freshDone, installedFresh := rng.Intn(4) == 0, false // a quarter of the runs leave it to the end
			done := make([]bool, len(serials))
			fails := make([]int, len(serials))
			for {
				var open []int
				for i := range serials {
					if !done[i] {
						open = append(open, i)
					}
				}
				if len(open) == 0 && freshDone {
					break
				}
				clock = clock.Add(time.Duration(rng.Intn(13)) * time.Minute)
				if !freshDone && (len(open) == 0 || rng.Intn(len(open)+1) == 0) {
					freshDone = true
					allow := want == rec && clock.Sub(xAt) >= freshInstall && allRevoked()
					err := freshAddOn(t, f)
					if allow {
						if err != nil {
							t.Fatalf("after %v: a fresh add over node-x's %v-old install with every admission revoked: %v",
								log, clock.Sub(xAt), err)
						}
						installedFresh = true
						want = string(mustRead(t, f.target.Path(addInstalledMarker)))
						wantCrt = mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
					} else if err == nil || reachedInstall(f.target.Events) {
						t.Fatalf("after %v: a fresh add the ruling refuses = %v, events %v", log, err, f.target.Events)
					}
					check(fmt.Sprintf("fresh add at +%v (installed %v)", clock.Sub(t0), allow))
					continue
				}
				i := open[rng.Intn(len(open))]
				fault := 0
				if fails[i] < 3 {
					fault = rng.Intn(10)
				}
				if fault == 8 && serialRevokedHere(f.opPKI, serials[i]) {
					fault = 0
				}
				undo := func() {}
				switch fault {
				case 1:
					down = true
					undo = func() { down = false }
				case 2:
					r = &failingShell{LocalAddTarget: f.target, kind: "claim", nth: 1}
				case 3:
					key := filepath.Join(f.opPKI, "ca.key")
					if err := os.Rename(key, key+".away"); err != nil {
						t.Fatal(err)
					}
					undo = func() {
						if err := os.Rename(key+".away", key); err != nil {
							t.Fatal(err)
						}
					}
				case 4:
					c.publishErr = errors.New("unavailable")
					undo = func() { c.publishErr = nil }
				case 5, 6, 7:
					r = &failingShell{LocalAddTarget: f.target, kind: "unstage", nth: fault - 4}
				case 9:
					r = &failingShell{LocalAddTarget: f.target, kind: "records", nth: 1}
				}
				var err error
				if fault == 8 {
					err = claimForSettle(f.target, names[i], serials[i], "10.0.0.9")
					if err == nil {
						err = errors.New("died after its claim")
					}
				} else {
					err = HostRemoveAdmission(context.Background(), c, names[i], serials[i], "10.0.0.9", false)
				}
				undo()
				r = f.target
				if err == nil {
					done[i] = true
					if !serialInCRL(t, f.opPKI, serials[i]) {
						t.Fatalf("after %v: settle of %s finished without revoking it", log, serials[i])
					}
				} else {
					if fault == 0 {
						t.Fatalf("after %v: a settle of %s with no fault failed: %v", log, serials[i], err)
					}
					fails[i]++
				}
				check(fmt.Sprintf("settle %s at +%v fault %d (finished %v)", names[i], clock.Sub(t0), fault, err == nil))
			}
			for _, s := range serials {
				for _, p := range stagedOnTarget(t, f.target.Root) {
					if strings.Contains(filepath.Base(p), s) {
						t.Errorf("after %v: left on the machine: %s", log, p)
					}
				}
				if _, err := os.Stat(f.target.Path(settleClaimPath(s))); !os.IsNotExist(err) {
					t.Errorf("after %v: the settle's claim of %s is left", log, s)
				}
			}
			t.Logf("node-x %v old at the start; steps: %v", t0.Sub(xAt), log)
			if installedFresh {
				return
			}
			// The ruling's line: one second short of the hour is refused, the
			// hour itself replaces the stale install.
			if clock.Before(xAt.Add(freshInstall - time.Second)) {
				clock = xAt.Add(freshInstall - time.Second)
				if err := freshAddOn(t, f); err == nil || !strings.Contains(err.Error(), x) || reachedInstall(f.target.Events) {
					t.Fatalf("after %v: a fresh add one second short of the hour = %v, want refused naming %s", log, err, x)
				}
				check("fresh add one second short of the hour")
			}
			if clock.Before(xAt.Add(freshInstall)) {
				clock = xAt.Add(freshInstall)
			}
			if err := freshAddOn(t, f); err != nil {
				t.Fatalf("after %v: a fresh add over node-x's %v-old install: %v", log, clock.Sub(xAt), err)
			}
			if got := string(mustRead(t, f.target.Path(addInstalledMarker))); !strings.HasPrefix(got, "node-7 ") {
				t.Errorf("after the stale replace: install record = %q, want node-7's", got)
			}
		})
	}
}

// Round-4 review m1: a settle that dies right after its claim, before the
// revocation, so no undo runs. Its claim is its serial's own file: node-x's
// record is untouched throughout, a retry of the stranded admission's add is
// refused naming the settle's command (and is neither staged nor admitted),
// a fresh add is judged by node-x's record alone, and the settle's command
// finishes at once, with no wait for its own claim to go stale.
//
// Mutations: skip the add's check of the settle's claim (refuseSettling in
// refuseUnproven) — the retry is staged and asks for an admission.
func TestHostRemoveSerial_ASettleThatDiesAfterItsClaim(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	fixAddClock(t, t0)
	f, serials, x, rec := strandedMachine(t, []string{"node-9"}, t0.Add(-5*time.Minute))
	S := serials[0]
	if err := claimForSettle(f.target, "node-9", S, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.target.Path(settleClaimPath(S))); err != nil {
		t.Fatalf("no claim: %v", err)
	}
	if got := string(mustRead(t, f.target.Path(addInstalledMarker))); got != rec {
		t.Fatalf("the claim wrote the install record: %q", got)
	}
	// The stranded admission's own retry: its row is listed again.
	f.client.hosts = append(f.client.hosts, &pb.Host{Name: "node-9", Address: "10.0.0.9", State: pb.HostState_HOST_JOINING, CertSerial: S})
	admitted, staged := len(f.client.admitted), len(f.staged(t))
	f.target.Events = nil
	err := f.add(t)
	want := "lv host rm node-9 --serial " + S + " --address 10.0.0.9"
	if err == nil || !strings.Contains(err.Error(), want) || reachedInstall(f.target.Events) {
		t.Fatalf("the admission's retry = %v, events %v: want refused naming %q", err, f.target.Events, want)
	}
	if len(f.client.admitted) != admitted || len(f.staged(t)) != staged {
		t.Errorf("the refused retry asked for an admission (%d -> %d) or staged files (%d -> %d)",
			admitted, len(f.client.admitted), staged, len(f.staged(t)))
	}
	f.client.hosts = f.client.hosts[:1]
	for _, d := range []time.Duration{time.Minute, 11 * time.Minute} {
		fixAddClock(t, t0.Add(d))
		if err := freshAddOn(t, f); err == nil || !strings.Contains(err.Error(), x) || reachedInstall(f.target.Events) {
			t.Errorf("fresh add at +%v = %v: want refused by node-x's record", d, err)
		}
	}
	fixAddClock(t, t0.Add(time.Minute))
	var r addRemote = f.target
	down := false
	dialTo(t, &r, &down)
	c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
	if err := HostRemoveAdmission(context.Background(), c, "node-9", S, "10.0.0.9", false); err != nil {
		t.Fatalf("the settle's command at +1m: %v", err)
	}
	m := &settleMachine{f: f, serial: S, bBytes: mustRead(t, filepath.Join(f.targetPKI, "host.crt"))}
	m.recordIs(t, rec)
	if !serialInCRL(t, f.opPKI, S) || serialInCRL(t, f.opPKI, x) {
		t.Error("want S revoked and node-x not")
	}
}

// admitHook is hostAddTestClient running hook on the nth AdmitHost.
type admitHook struct {
	*hostAddTestClient
	nth, seen int
	hook      func()
}

func (c *admitHook) AdmitHost(ctx context.Context, req *pb.AdmitHostRequest, opts ...grpc.CallOption) (*pb.AdmitHostResponse, error) {
	c.seen++
	if c.seen == c.nth {
		c.hook()
	}
	return c.hostAddTestClient.AdmitHost(ctx, req, opts...)
}

// No command of an add runs past a settle's claim of its admission: one
// taken between the add's checks and its claim fails the claim, and one
// taken after the claim stops every later command, whatever the install
// record says.
//
// Mutations: machineClaim.holds ignores the settle's claim — the add claims
// the install record over it, and the late command runs.
func TestHostAdd_NoCommandRunsPastASettleClaimOfItsAdmission(t *testing.T) {
	t.Run("taken before the add's claim", func(t *testing.T) {
		f := newAddFixture(t)
		S := strandedAdd(t, f)
		hook := &admitHook{hostAddTestClient: f.client, nth: 2, hook: func() {
			if err := os.WriteFile(f.target.Path(settleClaimPath(S)), []byte(markerLine("node-9", S, 1, "0123456789ab", "settling")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}}
		_, hadRecord, _ := f.target.ReadFile(addInstalledMarker)
		f.target.Events = nil
		err := HostAddOn(context.Background(), hook, f.target, "node-9", "10.0.0.9")
		if err == nil || reachedInstall(f.target.Events) {
			t.Fatalf("retry = %v, events %v: want refused before anything is stopped or installed", err, f.target.Events)
		}
		if !strings.Contains(err.Error(), "lv host rm node-9 --serial "+S) {
			t.Errorf("retry = %v: want the settle's command named", err)
		}
		if _, ok, _ := f.target.ReadFile(addInstalledMarker); ok != hadRecord {
			t.Errorf("the install record was written over the settle's claim")
		}
		f.identityUnchanged(t)
	})
	t.Run("taken after the add's claim", func(t *testing.T) {
		root := t.TempDir()
		r := &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "etc", "litevirt", "pki")}
		m := machineClaim{r: r, mine: markerLine("node-9", "a0a0", 1, "0123456789ab", "installing"), settle: settleClaimPath("a0a0")}
		writeMarker(t, r, m.mine+"\n")
		if err := os.WriteFile(r.Path(settleClaimPath("a0a0")), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ran := r.Path("/etc/litevirt/ran")
		_, err := r.Shell("late", m.cmd("touch "+ran))
		if exitStatus(err) != notOurMachine {
			t.Errorf("late command = %v, want refused as not this add's machine", err)
		}
		if _, err := os.Stat(ran); !os.IsNotExist(err) {
			t.Error("a late command of the add ran past the settle's claim")
		}
	})
}

// The undo of a failed revocation removes only the claim its own run took:
// one a later run of the command took since is left.
//
// Mutation: drop the compare — the later run's claim goes.
func TestDropSettleClaim_RemovesOnlyItsOwnClaim(t *testing.T) {
	root := t.TempDir()
	r := &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "etc", "litevirt", "pki")}
	p := r.Path(settleClaimPath("a0a0"))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	later := markerLine("node-9", "a0a0", 2, "bbbbbbbbbbbb", "settling")
	if err := os.WriteFile(p, []byte(later+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := dropSettleClaim(r, "a0a0", markerLine("node-9", "a0a0", 1, "aaaaaaaaaaaa", "settling")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != later+"\n" {
		t.Fatalf("the later claim = %q (%v), want it left", got, err)
	}
	if err := dropSettleClaim(r, "a0a0", later); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("its own claim is left")
	}
}

// Round-4 review m4: `lv host add` took a name `lv host rm --serial` refuses
// with no row (a control or format character, longer than a host name, a
// leading '-'), and then printed that command as the way out. It refuses
// such a name before anything now.
//
// Mutation: drop the check — each is staged and admitted.
func TestHostAdd_RefusesANameItsSettleCommandCannotTake(t *testing.T) {
	for _, name := range []string{"a\x01b", "a‮b", "-rf", strings.Repeat("a", safename.MaxNameLen+1), ""} {
		f := newAddFixture(t)
		f.target.Events = nil
		err := HostAddOn(context.Background(), f.client, f.target, name, "10.0.0.9")
		if err == nil || len(f.client.admitted) != 0 || len(f.staged(t)) != 0 || len(f.target.Events) != 0 {
			t.Errorf("add of %q = %v, admitted %v, staged %v, events %v: want refused before anything",
				name, err, f.client.admitted, f.staged(t), f.target.Events)
		}
		f.identityUnchanged(t)
	}
}

// The same for a joining row's removal whose cleanup fails: a row name the
// no-row command refuses is not printed in a command.
//
// Mutation: print settleRmCmd for every name — "-x"'s command is printed.
func TestHostRemove_ARowNameTheSettleRefusesGetsNoCommand(t *testing.T) {
	rmTestPKI(t)
	old := removeStagedAdmission
	removeStagedAdmission = func(string, string) error { return errors.New("no route to host") }
	t.Cleanup(func() { removeStagedAdmission = old })
	for _, name := range []string{"-x", "a\x01b"} {
		c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{},
			hosts: []*pb.Host{{Name: name, CertSerial: "a1b2c3", State: pb.HostState_HOST_JOINING, Address: "10.0.0.9"}}}
		err := HostRemove(context.Background(), c, name, false)
		if err == nil || strings.Contains(err.Error(), "--address") || !strings.Contains(err.Error(), "check that machine") {
			t.Errorf("removal of %q = %v: want the cleanup failure with no command", name, err)
		}
	}
	c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{},
		hosts: []*pb.Host{{Name: "a b", CertSerial: "a1b2c3", State: pb.HostState_HOST_JOINING, Address: "10.0.0.9"}}}
	if err := HostRemove(context.Background(), c, "a b", false); err == nil || !strings.Contains(err.Error(), "lv host rm 'a b' --serial a1b2c3") {
		t.Errorf("control: removal of %q = %v, want its command", "a b", err)
	}
}

// Round-4 review m2 and m3: a settle whose publication failed left its claim
// as the install record, which kept a fresh add out until an hour past the
// claim, however stale the install it replaced, and which an earlier
// release's add read as the settled admission's own install. Its claim is
// its own file now: the record stays node-x's, so a fresh add (of this
// release or an earlier one) judges node-x itself. Two hours old, it is
// replaced while the settle is unfinished, and the settle's command then
// finishes, leaving the new install's record.
//
// Mutation: claim in the install record — the fresh add is refused.
func TestHostRemoveSerial_AnUnfinishedSettleKeepsNoStaleInstallFromBeingReplaced(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	fixAddClock(t, t0)
	f, serials, x, rec := strandedMachine(t, []string{"node-9"}, t0.Add(-2*time.Hour))
	S := serials[0]
	var r addRemote = f.target
	down := false
	dialTo(t, &r, &down)
	c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{publishErr: errors.New("unavailable")}}
	if err := HostRemoveAdmission(context.Background(), c, "node-9", S, "10.0.0.9", false); err == nil {
		t.Fatal("the settle with publish down succeeded")
	}
	if got := string(mustRead(t, f.target.Path(addInstalledMarker))); got != rec {
		t.Fatalf("after the failed publish the install record = %q, want node-x's %q", got, rec)
	}
	fixAddClock(t, t0.Add(time.Minute))
	if err := freshAddOn(t, f); err != nil {
		t.Fatalf("a fresh add over node-x's two-hour-old install while the settle is unfinished: %v", err)
	}
	installed := string(mustRead(t, f.target.Path(addInstalledMarker)))
	if !strings.HasPrefix(installed, "node-7 ") {
		t.Fatalf("install record = %q, want node-7's", installed)
	}
	c.publishErr = nil
	if err := HostRemoveAdmission(context.Background(), c, "node-9", S, "10.0.0.9", false); err != nil {
		t.Fatalf("the settle's command: %v", err)
	}
	(&settleMachine{f: f, serial: S}).recordIs(t, installed)
	if serialInCRL(t, f.opPKI, x) || !serialInCRL(t, f.opPKI, S) {
		t.Error("want S revoked and node-x not")
	}
}

// A retry of the admission a settle has claimed the machine for is refused
// before it stages anything or asks for an admission, naming the settle's
// command, also on a machine that still serves what its first attempt found
// (where nothing else refuses it).
//
// Mutations: drop the check from refuseUnproven — the retry stages and is
// admitted again before its claim fails; make it refuse nothing — the
// refusal names no command.
func TestHostAdd_ARetryUnderASettleClaimIsRefusedBeforeAnything(t *testing.T) {
	f := newAddFixture(t)
	S := strandedAdd(t, f)
	if err := claimForSettle(f.target, "node-9", S, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	admitted, staged := len(f.client.admitted), len(f.staged(t))
	f.target.Events = nil
	err := f.add(t)
	want := "lv host rm node-9 --serial " + S + " --address 10.0.0.9"
	if err == nil || !strings.Contains(err.Error(), want) || reachedInstall(f.target.Events) {
		t.Fatalf("the retry = %v, events %v: want refused naming %q", err, f.target.Events, want)
	}
	if len(f.client.admitted) != admitted || len(f.staged(t)) != staged {
		t.Errorf("the refused retry asked for an admission (%d -> %d) or staged files (%d -> %d)",
			admitted, len(f.client.admitted), staged, len(f.staged(t)))
	}
	f.identityUnchanged(t)
}

// Round-5 review m3: a settle that died after its claim, then an add of the
// serial completed on the machine (an earlier release's, which does not read
// the claim). Every rerun refused, as the machine serves the serial, and
// left the claim for good. It goes with the staged files now: nothing is
// revoked, and nothing it held off is to be held off.
//
// Mutation: leave the claim on that path — it is still there.
func TestHostRemoveSerial_AClaimGoesWhenTheMachineServesTheSerial(t *testing.T) {
	m := newSettleMachine(t)
	if err := claimForSettle(m.f.target, "node-9", m.serial, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	staged, _ := filepath.Glob(filepath.Join(m.f.targetPKI, ".host.*.add-"+m.serial+"-*"))
	for _, p := range staged {
		if strings.HasSuffix(p, ".before") {
			continue
		}
		n := "host.crt"
		if strings.Contains(p, ".host.key.") {
			n = "host.key"
		}
		if err := os.WriteFile(filepath.Join(m.f.targetPKI, n), mustRead(t, p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
	err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false)
	if err == nil || !strings.Contains(err.Error(), "completed add") {
		t.Fatalf("removal = %v, want the refusal of a possibly completed add", err)
	}
	if serialInCRL(t, m.f.opPKI, m.serial) {
		t.Error("a served certificate was revoked")
	}
	if _, err := os.Stat(m.f.target.Path(settleClaimPath(m.serial))); !os.IsNotExist(err) {
		t.Errorf("the earlier run's claim is left (stat: %v)", err)
	}
}

// Round-5 review m2, R1: the settle's claim is taken only while the
// machine's certificate is the one it checked, whatever the install record
// says. An add whose claim is already stale (an earlier release's, or a slow
// one) installing the serial between the settle's checks and its claim
// changes only host.crt; the settle then revokes nothing.
//
// Mutation: drop the certificate compare from the claim — S is revoked
// while the machine serves it.
func TestHostRemoveSerial_AClaimNeedsTheCertificateItChecked(t *testing.T) {
	m := newSettleMachine(t)
	staged, _ := filepath.Glob(filepath.Join(m.f.targetPKI, ".host.crt.add-"+m.serial+"-*"))
	var crt []byte
	for _, p := range staged {
		if !strings.HasSuffix(p, ".before") {
			crt = mustRead(t, p)
		}
	}
	if crt == nil {
		t.Fatal("no staged certificate")
	}
	beforeSettleClaim = func() {
		if err := os.WriteFile(filepath.Join(m.f.targetPKI, "host.crt"), crt, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { beforeSettleClaim = nil })
	c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
	err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false)
	if err == nil || !strings.Contains(err.Error(), "changed while it was checked") {
		t.Fatalf("removal = %v, want refused as changed while checked", err)
	}
	if serialInCRL(t, m.f.opPKI, m.serial) || countCalls(c.calls, "publish") != 0 {
		t.Error("the serial the machine now serves was revoked")
	}
	if _, err := os.Stat(m.f.target.Path(settleClaimPath(m.serial))); !os.IsNotExist(err) {
		t.Error("a claim was taken")
	}
}

// claimRacer is the machine with a second run of the same command taking
// its own claim right after this run's claim.
type claimRacer struct {
	*LocalAddTarget
	serial, other string
}

func (c *claimRacer) Shell(kind, cmd string) ([]byte, error) {
	out, err := c.LocalAddTarget.Shell(kind, cmd)
	if kind == "claim" && err == nil {
		if werr := os.WriteFile(c.Path(settleClaimPath(c.serial)), []byte(c.other+"\n"), 0o600); werr != nil {
			return nil, werr
		}
	}
	return out, err
}

// Round-5 review m2, R13: two runs of S's command at once. A's revocation
// fails, and its undo removes only the claim A took: B's, taken since,
// keeps S's adds held off through B's revocation.
//
// Mutation: undo with no compare (dropSettleClaim(r, serial, "")) — B's
// claim goes.
func TestHostRemoveSerial_AFailedRevocationLeavesAnotherRunsClaim(t *testing.T) {
	m := newSettleMachine(t)
	other := markerLine("node-9", m.serial, 2, "bbbbbbbbbbbb", "settling")
	m.dial(t, &claimRacer{LocalAddTarget: m.f.target, serial: m.serial, other: other})
	key := filepath.Join(m.f.opPKI, "ca.key")
	if err := os.Rename(key, key+".away"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Rename(key+".away", key) })
	c := &serialRemoveClient{hostRemoveTestClient: &hostRemoveTestClient{}}
	if err := HostRemoveAdmission(context.Background(), c, "node-9", m.serial, "10.0.0.9", false); err == nil {
		t.Fatal("the run whose revocation fails succeeded")
	}
	if got, err := os.ReadFile(m.f.target.Path(settleClaimPath(m.serial))); err != nil || string(got) != other+"\n" {
		t.Errorf("the other run's claim = %q (%v), want it left", got, err)
	}
}

// Round-5 review m2, R11: the refusal of a retry under a settle's claim
// prints the settle's command with the name as one shell word, for a name
// with a blank and shell metacharacters.
//
// Mutation: print the name unquoted in refuseSettling — the command splits
// and runs what follows the ';'.
func TestHostAdd_ARetryUnderASettleClaimPrintsAShellSafeCommand(t *testing.T) {
	const name = "a b;touch${IFS}pwned"
	f := newAddFixture(t)
	S := strandedAddAs(t, f, name)
	if err := claimForSettle(f.target, name, S, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	err := HostAddOn(context.Background(), f.client, f.target, name, "10.0.0.9")
	if err == nil || !strings.Contains(err.Error(), "has not finished") {
		t.Fatalf("the retry = %v, want refused under the settle's claim", err)
	}
	msg := err.Error()
	i := strings.LastIndex(msg, "`lv host rm ")
	j := strings.LastIndex(msg, "` finishes it")
	if i < 0 || j <= i {
		t.Fatalf("no settle command in %q", msg)
	}
	dir := t.TempDir()
	got := shellWords(t, dir, msg[i+1:j])
	want := []string{"lv", "host", "rm", name, "--serial", S, "--address", "10.0.0.9"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("printed %q splits as %q, want %q", msg[i+1:j], got, want)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("evaluating the printed command ran something: %v", ents)
	}
}
