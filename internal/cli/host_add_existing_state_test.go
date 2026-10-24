package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// writeOnTarget writes body at the machine path p (as the host names it).
func writeOnTarget(t *testing.T, m *LocalAddTarget, p, body string) {
	t.Helper()
	full := m.Path(p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// foundOwnCluster gives the target what `lv host init --local` leaves: a CA
// of its own (certificate and key) beside its host pair, and a database.
func foundOwnCluster(t *testing.T, f *addFixture) {
	t.Helper()
	installPair(t, f, "", "node-5") // a host pair from a fresh CA...
	other := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key")); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ca.crt", "ca.key"} { // ...and a CA that is not this cluster's
		if err := os.WriteFile(filepath.Join(f.targetPKI, n), mustRead(t, filepath.Join(other, n)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeOnTarget(t, f.target, "/var/lib/litevirt/state.db", "SQLite format 3\x00")
	f.target.DaemonState = "active"
}

// noIdentity removes the fixture's host pair: the machine holds no host
// certificate.
func noIdentity(t *testing.T, f *addFixture) {
	t.Helper()
	for _, n := range []string{"host.crt", "host.key"} {
		if err := os.Remove(filepath.Join(f.targetPKI, n)); err != nil {
			t.Fatal(err)
		}
	}
	f.before = map[string][]byte{}
}

// mkdirOnTarget creates the machine directory p and returns where it is.
func mkdirOnTarget(t *testing.T, m *LocalAddTarget, p string) string {
	t.Helper()
	full := m.Path(p)
	if err := os.MkdirAll(full, 0o700); err != nil {
		t.Fatal(err)
	}
	return full
}

// ourCAOnTarget puts this cluster's CA certificate on the target, as every
// add (and so every removed host) has it.
func ourCAOnTarget(t *testing.T, f *addFixture) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.targetPKI, "ca.crt"), mustRead(t, filepath.Join(f.opPKI, "ca.crt")), 0o644); err != nil {
		t.Fatal(err)
	}
}

// refusedUntouched checks an add was refused for the machine's state,
// naming want, before anything was admitted, staged or installed.
func refusedUntouched(t *testing.T, f *addFixture, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("the add went ahead over another cluster's state")
	}
	for _, w := range append(want, "not this cluster's", "move", "aside", "other direction") {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal = %v\nwant it to name %q", err, w)
		}
	}
	if len(f.client.admitted) != 0 {
		t.Errorf("AdmitHost was asked: %v", f.client.admitted)
	}
	for _, e := range f.target.Events {
		if strings.HasPrefix(e, "write ") || reachedInstall([]string{e}) {
			t.Errorf("the refused add reached the machine: %v", f.target.Events)
			break
		}
	}
	f.identityUnchanged(t)
}

// Lab 4 finding 1: `lv host add` against a machine that founded its own
// cluster (`lv host init --local`) pushed this cluster's CA and kept the
// machine's state.db: its users (a second admin), its audit genesis and its
// latches would have been merged into this cluster, and its own gossip key
// kept in force. The add refuses, names what it found and the two ways
// forward, and changes nothing.
//
// Mutation: drop the refuseForeignState call in hostAddTo — every case
// installs over the other cluster's state.
func TestHostAdd_RefusesAMachineWithAnotherClustersState(t *testing.T) {
	t.Run("founded its own cluster", func(t *testing.T) {
		f := newAddFixture(t)
		foundOwnCluster(t, f)
		f.before["host.crt"] = mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
		f.before["host.key"] = mustRead(t, filepath.Join(f.targetPKI, "host.key"))
		refusedUntouched(t, f, f.add(t), "/etc/litevirt/pki/ca.crt", "a CA that is not this cluster's")
	})
	t.Run("a database with no host certificate", func(t *testing.T) {
		f := newAddFixture(t)
		noIdentity(t, f)
		writeOnTarget(t, f.target, "/var/lib/litevirt/state.db", "x")
		refusedUntouched(t, f, f.add(t), "/var/lib/litevirt/state.db")
	})
	t.Run("a capability latch with no host certificate", func(t *testing.T) {
		f := newAddFixture(t)
		noIdentity(t, f)
		writeOnTarget(t, f.target, "/var/lib/litevirt/split_brain_activated.voter_config_v1", "")
		refusedUntouched(t, f, f.add(t), "split_brain_activated.voter_config_v1")
	})
	t.Run("a database in the config's own data dir", func(t *testing.T) {
		f := newAddFixture(t)
		noIdentity(t, f)
		writeTargetConfig(t, f, "host_name: node-5\ndata_dir: /srv/lv\n", 0o644)
		writeOnTarget(t, f.target, "/srv/lv/state.db", "x")
		refusedUntouched(t, f, f.add(t), "/srv/lv/state.db")
	})
	t.Run("a CA in the config's own pki dir", func(t *testing.T) {
		f := newAddFixture(t)
		ourCAOnTarget(t, f)
		writeTargetConfig(t, f, "host_name: node-5\npki_dir: /srv/pki\n", 0o644)
		other := f.target.Path("/srv/pki")
		if err := os.MkdirAll(other, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := pki.GenerateCA(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key")); err != nil {
			t.Fatal(err)
		}
		refusedUntouched(t, f, f.add(t), "/srv/pki/ca.crt")
	})
	t.Run("a running daemon with no host certificate", func(t *testing.T) {
		f := newAddFixture(t)
		noIdentity(t, f)
		f.target.DaemonState = "active"
		refusedUntouched(t, f, f.add(t), "running litevirt.service")
	})
	t.Run("a CA key with no CA certificate", func(t *testing.T) {
		f := newAddFixture(t)
		writeOnTarget(t, f.target, "/etc/litevirt/pki/ca.key", "k")
		refusedUntouched(t, f, f.add(t), "CA key")
	})
	t.Run("this CA, but another CA's host certificate over a database", func(t *testing.T) {
		f := newAddFixture(t)
		ourCAOnTarget(t, f)
		installPair(t, f, "", "node-5")
		f.before["host.crt"] = mustRead(t, filepath.Join(f.targetPKI, "host.crt"))
		f.before["host.key"] = mustRead(t, filepath.Join(f.targetPKI, "host.key"))
		writeOnTarget(t, f.target, "/var/lib/litevirt/state.db", "x")
		refusedUntouched(t, f, f.add(t), "a host certificate this cluster's CA did not issue")
	})
	// Review I1: ca.crt is public, so this cluster's CA beside another
	// cluster's database and daemon, with no host certificate, proves nothing.
	t.Run("this CA, no host certificate, another cluster's database and daemon", func(t *testing.T) {
		f := newAddFixture(t)
		noIdentity(t, f)
		ourCAOnTarget(t, f)
		writeOnTarget(t, f.target, "/var/lib/litevirt/state.db", "SQLite format 3\x00")
		f.target.DaemonState = "active"
		refusedUntouched(t, f, f.add(t), "no host certificate at /etc/litevirt/pki/host.crt", "running litevirt.service")
	})
	// Review I2: the daemon loads host.crt from the config's pki_dir. This
	// cluster's pair at /etc/litevirt/pki proves nothing when the config
	// points the daemon at another directory holding another cluster's.
	t.Run("this cluster's pair in /etc/litevirt/pki, another's in the config's pki_dir", func(t *testing.T) {
		f := newAddFixture(t)
		ourCAOnTarget(t, f)
		writeTargetConfig(t, f, "host_name: node-5\npki_dir: /srv/pki\n", 0o644)
		installPair(t, &addFixture{targetPKI: mkdirOnTarget(t, f.target, "/srv/pki")}, "", "node-5")
		writeOnTarget(t, f.target, "/var/lib/litevirt/state.db", "x")
		refusedUntouched(t, f, f.add(t), "/srv/pki/host.crt, a host certificate this cluster's CA did not issue")
	})
	t.Run("a config that does not parse", func(t *testing.T) {
		f := newAddFixture(t)
		writeTargetConfig(t, f, "data_dir: [unclosed\n", 0o644)
		refusedUntouched(t, f, f.add(t), "does not parse")
	})
}

// The control: a host `lv host rm` removed keeps every file it had (this
// cluster's CA, its revoked certificate, its database with its tombstone,
// even a daemon still running), and is re-added as before. So is a fresh
// machine, and one this cluster's add left a database on.
//
// Mutation: make refuseForeignState refuse whenever a state.db exists —
// "removed host" is refused.
func TestHostAdd_ReAddsAHostThisClusterRemoved(t *testing.T) {
	t.Run("removed host", func(t *testing.T) {
		f := newAddFixture(t)
		ourCAOnTarget(t, f)
		revoke(t, f.opPKI, installedSerial(f.before["host.crt"]))
		writeOnTarget(t, f.target, "/var/lib/litevirt/state.db", "x")
		writeOnTarget(t, f.target, "/var/lib/litevirt/split_brain_activated.voter_config_v1", "")
		f.target.DaemonState = "active"
		if err := f.add(t); err != nil {
			t.Fatalf("re-add of a removed host: %v", err)
		}
		if len(f.client.admitted) == 0 {
			t.Fatal("the re-add asked no admission")
		}
	})
	t.Run("fresh machine", func(t *testing.T) {
		f := newAddFixture(t)
		if err := f.add(t); err != nil {
			t.Fatalf("add of a machine with no state: %v", err)
		}
	})
	// An add that failed after its admission, on a fresh machine whose daemon
	// had already started: its rollback removed the host pair it installed
	// (there was none before), and left the admitted pair staged. The rerun
	// finishes it: the staged pair of this cluster's joining admission is the
	// proof, not a host.crt.
	//
	// Mutation: drop the admitted case in refuseForeignState — refused.
	t.Run("an add that failed after its daemon started", func(t *testing.T) {
		f := newAddFixture(t)
		noIdentity(t, f)
		serial := strandedAdd(t, f)
		if _, err := os.Stat(filepath.Join(f.targetPKI, "host.crt")); !os.IsNotExist(err) {
			t.Fatalf("the rollback left a host.crt (%v): the case is not reached", err)
		}
		writeOnTarget(t, f.target, "/var/lib/litevirt/state.db", "x")
		f.target.DaemonState = "active"
		if err := f.add(t); err != nil {
			t.Fatalf("finishing this cluster's admission: %v", err)
		}
		servesItsAdmittedPair(t, f.targetPKI, serial)
	})
}

// `lv host init root@...` pushes this machine's CA (minting one when it has
// none) and keeps the target's database: over another cluster's state it
// merges the two just as add does. It refuses the same way, and --force,
// which overrides the join_peers check, does not override this one. A
// half-finished first node of this machine's own CA is re-initialised as
// before.
//
// Mutation: drop the refuseForeignState call from initPreflight — the
// foreign cases pass.
func TestHostInitPreflight_RefusesAnotherClustersState(t *testing.T) {
	newTarget := func(t *testing.T) *LocalAddTarget {
		root := t.TempDir()
		return &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "etc", "litevirt", "pki")}
	}
	foreignCA := func(t *testing.T, m *LocalAddTarget) {
		if err := os.MkdirAll(m.PKIDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := pki.GenerateCA(filepath.Join(m.PKIDir, "ca.crt"), filepath.Join(m.PKIDir, "ca.key")); err != nil {
			t.Fatal(err)
		}
	}
	for _, force := range []bool{false, true} {
		t.Run("another CA, force="+map[bool]string{false: "no", true: "yes"}[force], func(t *testing.T) {
			addOperatorPKI(t)
			m := newTarget(t)
			foreignCA(t, m)
			writeOnTarget(t, m, "/var/lib/litevirt/state.db", "x")
			err := initPreflight(m, "root@10.0.0.5", "", true, force)
			if err == nil || !strings.Contains(err.Error(), "refusing to init") || !strings.Contains(err.Error(), "ca.crt") {
				t.Fatalf("init over another cluster = %v, want refused", err)
			}
		})
		t.Run("no CA here, a database there, force="+map[bool]string{false: "no", true: "yes"}[force], func(t *testing.T) {
			t.Setenv("LV_CONFIG_DIR", t.TempDir()) // this machine has no CA yet
			m := newTarget(t)
			writeOnTarget(t, m, "/var/lib/litevirt/state.db", "x")
			if err := initPreflight(m, "root@10.0.0.5", "", true, force); err == nil || !strings.Contains(err.Error(), "state.db") {
				t.Fatalf("init with a new CA over a database = %v, want refused", err)
			}
		})
	}
	t.Run("half-finished first node of this CA", func(t *testing.T) {
		op := addOperatorPKI(t)
		m := newTarget(t)
		writeOnTarget(t, m, "/etc/litevirt/pki/ca.crt", string(mustRead(t, filepath.Join(op, "ca.crt"))))
		writeOnTarget(t, m, "/var/lib/litevirt/state.db", "x")
		m.DaemonState = "active"
		// Init pushes this CA's host pair before setup, so it is there.
		if err := pki.GenerateHostCert(filepath.Join(op, "ca.crt"), filepath.Join(op, "ca.key"),
			filepath.Join(m.PKIDir, "host.crt"), filepath.Join(m.PKIDir, "host.key"), "node-1", net.IPv4(10, 0, 0, 5)); err != nil {
			t.Fatal(err)
		}
		if err := initPreflight(m, "root@10.0.0.5", "host_name: node-1\n", false, false); err != nil {
			t.Fatalf("re-init of this CA's founder: %v", err)
		}
		// Without it, the database and daemon are not proven this CA's.
		if err := os.Remove(filepath.Join(m.PKIDir, "host.crt")); err != nil {
			t.Fatal(err)
		}
		if err := initPreflight(m, "root@10.0.0.5", "host_name: node-1\n", false, false); err == nil {
			t.Fatal("init over a database and daemon with no host certificate went ahead")
		}
	})
	t.Run("fresh machine", func(t *testing.T) {
		t.Setenv("LV_CONFIG_DIR", t.TempDir())
		if err := initPreflight(newTarget(t), "root@10.0.0.5", "", true, false); err != nil {
			t.Fatalf("init of a fresh machine: %v", err)
		}
	})
}

// The probe commands run under sh: the data dir's state files are listed
// (a glob that matches nothing lists nothing), and an unknown or stopped
// unit is not running.
func TestStateProbeCommands(t *testing.T) {
	dir := t.TempDir()
	m := &LocalAddTarget{Root: dir, PKIDir: filepath.Join(dir, "pki")}
	out, err := m.Shell(stateProbeKind, stateFilesCmd(dir))
	if err != nil || strings.TrimSpace(string(out)) != "" {
		t.Fatalf("empty data dir: %q, %v", out, err)
	}
	for _, n := range []string{"state.db", "split_brain_activated.x", "other"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, _ = m.Shell(stateProbeKind, stateFilesCmd(dir))
	got := strings.Fields(string(out))
	if len(got) != 2 || filepath.Base(got[0]) != "state.db" || filepath.Base(got[1]) != "split_brain_activated.x" {
		t.Errorf("listed %v, want state.db and the latch", got)
	}
	for in, want := range map[string]bool{"active\n": true, "activating": true, "inactive\n": false,
		"failed": false, "unknown": false, "none": false, "": false} {
		if daemonRunning(in) != want {
			t.Errorf("daemonRunning(%q) = %v, want %v", in, !want, want)
		}
	}
}
