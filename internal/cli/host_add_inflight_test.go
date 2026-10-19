package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// deferringTarget is a LocalAddTarget whose file commands of one kind are
// sent but not run until runDeferred: a command the add issued whose remote
// process is delayed, and outlives the add's connection (a non-PTY command
// is not killed when its SSH channel closes).
type deferringTarget struct {
	*LocalAddTarget
	kind     string
	deferred []string
}

func (d *deferringTarget) Shell(kind, cmd string) ([]byte, error) {
	if kind == d.kind {
		d.Events = append(d.Events, "sh "+kind+" (deferred)")
		d.deferred = append(d.deferred, cmd)
		return nil, errors.New("connection lost")
	}
	return d.LocalAddTarget.Shell(kind, cmd)
}

// runDeferred runs the delayed commands now, as the host would once they
// resume, whatever happened meanwhile.
func (d *deferringTarget) runDeferred(t *testing.T) {
	t.Helper()
	for _, c := range d.deferred {
		_ = exec.Command("sh", "-c", c).Run()
	}
}

// ageMarker makes the install record on the machine an hour and more old,
// as one left by an add whose connection dropped long ago.
func ageMarker(t *testing.T, r *LocalAddTarget) {
	t.Helper()
	b, err := os.ReadFile(r.Path(addInstalledMarker))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b))
	f[2] = "1"
	if err := os.WriteFile(r.Path(addInstalledMarker), []byte(strings.Join(f, " ")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Codex 446f3a39 I2: an add's rollback was a remote command apart from the
// process that held the machine's lock. Issued, then delayed past the add's
// lost connection, it ran after the lock was gone, after a rerun of the same
// admission had installed and finished, and put the old identity back over
// it. Every command an add runs on the machine after it claims it checks,
// in the process that holds the lock, that the machine still records the
// add's own claim: a late one finds the rerun's and does nothing.
//
// Mutation: run the rollback without the claim check — the old identity is
// put back over the rerun's install.
func TestHostAdd_ALateRollbackAfterARerunFinishedDoesNothing(t *testing.T) {
	f := newAddFixture(t)
	a := &deferringTarget{LocalAddTarget: f.target, kind: "restore"}
	f.target.OnSetup = func() error { return errors.New("setup failed (connection lost)") }
	if err := hostAddTo(context.Background(), f.client, a, hostAddPlan{pkiDir: f.opPKI, hostName: "node-9",
		hostAddr: "10.0.0.9", peersYAML: "[]", binPath: f.target.Binary, rerun: "lv host add --name node-9 root@10.0.0.9"}); err == nil {
		t.Fatal("A's failed setup reported success")
	}
	if len(a.deferred) == 0 {
		t.Fatal("A issued no rollback")
	}
	// A's connection is long gone; a rerun of the same admission finishes.
	ageMarker(t, f.target)
	f.target.OnSetup = nil
	otherOperator(t, f.opPKI)
	if err := f.add(t); err != nil {
		t.Fatalf("the rerun: %v", err)
	}
	served := installedSerial(mustRead(t, filepath.Join(f.targetPKI, "host.crt")))
	mig := mustRead(t, filepath.Join(f.targetPKI, "migration", "host.key"))
	a.runDeferred(t)
	if got := installedSerial(mustRead(t, filepath.Join(f.targetPKI, "host.crt"))); got != served {
		t.Errorf("A's late rollback undid the rerun: the machine serves %s, not %s", got, served)
	}
	if got := mustRead(t, filepath.Join(f.targetPKI, "migration", "host.key")); string(got) != string(mig) {
		t.Error("A's late rollback replaced the rerun's migration key")
	}
}

// Without flock(1) on the host, a guarded command refuses rather than
// change the machine unlocked.
//
// Mutation: drop the flock check — the body runs.
func TestLockedCmd_RefusesWithoutFlock(t *testing.T) {
	root := t.TempDir()
	r := &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "etc", "litevirt", "pki")}
	probe := filepath.Join(t.TempDir(), "acted")
	c := exec.Command("/bin/sh", "-c", lockedCmd(r, "true", ": > "+probe))
	c.Env = []string{"PATH=" + t.TempDir()} // no flock, nor anything else
	err := c.Run()
	if exitStatus(err) != 98 {
		t.Errorf("without flock = %v, want exit 98", err)
	}
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Error("the body ran without the lock")
	}
}
