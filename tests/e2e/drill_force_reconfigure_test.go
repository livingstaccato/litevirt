package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Drill 6 (docs/design/recovery-claims.md §7.3): three of five hosts are lost
// for good. The two survivors confirm the fences, force a 2-member voter
// generation, recover the lost hosts' workloads with no workaround, then the
// lost hosts are rebuilt from scratch, added back, and made voters again.
//
// It is the slowest drill and the only one that DESTROYS hosts (lab.sh destroy
// and create), so it runs only with LITEVIRT_E2E_DESTRUCTIVE=1. The procedure
// is the lab's kvm003:~/drill-evidence/d6-b3368d7c/RESTORE.md, minus the
// workarounds the finished build should not need.

// rebuildBy bounds a rebuilt node's first boot (cloud-init installs qemu,
// libvirt and friends; ~80 s on kvm003).
const rebuildBy = 10 * time.Minute

// d6 is the drill's progress, so the cleanup finishes the restore from
// wherever a failure left it.
type d6 struct {
	l         *lab
	via       string
	survivors []string
	lost      []string
	forced    bool
	removed   map[string]bool
	rebuilt   map[string]bool
	added     map[string]bool
	lxc       map[string]bool
	cts       map[string]ctInfo // containers whose row named a lost host
}

func TestDrill6_ForceReconfigureAndRebuild(t *testing.T) {
	if os.Getenv("LITEVIRT_E2E_DESTRUCTIVE") != "1" {
		t.Skip("destructive: set LITEVIRT_E2E_DESTRUCTIVE=1 to destroy and rebuild three lab hosts")
	}
	skipUnlessFixed(t, "N3", "N4")
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	survivors, lost := l.hosts[:2], l.hosts[2:]
	q := survivors[0]
	if out, err := l.ssh(q, 20*time.Second, "test -s /root/.config/litevirt/pki/ca.key && echo CA"); err != nil || !strings.Contains(out, "CA") {
		t.Fatalf("%s holds no cluster CA key; host add must run where the CA is", q)
	}
	d := &d6{l: l, via: q, survivors: survivors, lost: lost, removed: map[string]bool{},
		rebuilt: map[string]bool{}, added: map[string]bool{}, lxc: map[string]bool{}, cts: map[string]ctInfo{}}
	for _, h := range lost {
		d.lxc[h] = b.lxcHosts[h]
	}
	for n, c := range b.cts {
		if contains(lost, c.Host) {
			d.cts[n] = c
		}
	}
	// Registered after restoreOnCleanup, so it runs first: rebuild and re-add
	// whatever the drill did not get to.
	t.Cleanup(d.finish)

	target := l.leastLoaded(q, lost)
	test := l.createVMs(q, "d6", target)[target]
	key := "vm/" + test
	lostKeys := l.relocatableOn(q, b, lost...)
	survivorKeys := l.recoverableOn(q, survivors...)
	home := map[string]string{}
	for _, v := range l.vms(q) {
		home["vm/"+v.Name] = v.HostName
	}
	for _, c := range l.containers(q) {
		home["ct/"+c.Name] = c.Host
	}
	l.mark("drill6: survivors %v, lost %v; recoverable VMs on the lost hosts %v", survivors, lost, lostKeys)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, []string{key}, target)

	// ── 1. lose three hosts; confirm the fences during the outage ──────────
	off := l.powerOff(lost...)
	for _, h := range lost {
		if !l.waitHostNot(q, h, "HOST_ACTIVE", hostDownBy) {
			t.Fatalf("%s still active %v after losing power", h, hostDownBy)
		}
	}
	for _, h := range lost {
		if out, err := l.lv(q, "host", "fence-confirm", h); err != nil {
			t.Fatalf("fence-confirm %s: %v\n%s", h, err, out)
		}
	}
	l.mark("drill6: fences confirmed for %v", lost)

	// ── 2. force the 2-member generation ───────────────────────────────────
	lostArg := strings.Join(lost, ",")
	if out, err := l.lv(q, "cluster", "voter", "force-reconfigure", "--lost", lostArg, "--dry-run"); err != nil {
		t.Fatalf("force-reconfigure --dry-run: %v\n%s", err, out)
	}
	out, err := l.lv(q, "cluster", "voter", "force-reconfigure", "--lost", lostArg, "--yes")
	l.saveEvidence("force-reconfigure.txt", out)
	if err != nil {
		t.Fatalf("force-reconfigure: %v\n%s", err, out)
	}
	d.forced = true
	forced := l.mark("drill6: forced")
	if _, members, err := l.voterSet(q); err != nil || strings.Join(members, ",") != strings.Join(survivors, ",") {
		t.Fatalf("after force-reconfigure: members %v (err %v), want %v", members, err, survivors)
	}

	// ── 3. the survivors resume; the lost hosts' workloads recover ──────────
	resumed := waitEach(s, forced, resumeBy, survivorKeys, func(r round, k string) bool {
		return r.state(home[k], k) == "running"
	})
	for _, k := range survivorKeys {
		if _, ok := resumed[k]; !ok {
			t.Errorf("%s did not resume on survivor %s within %v of the forced generation\n  %s", k, home[k], resumeBy, s.last())
		}
	}
	recovered := waitEach(s, off, recoverBy, []string{key}, func(r round, k string) bool {
		hs := r.executing(k)
		return len(hs) == 1 && contains(survivors, hs[0])
	})
	if _, ok := recovered[key]; !ok {
		t.Errorf("%s was not recovered on a survivor within %v, with no workaround (N3: missing_witness?)\n  %s", key, recoverBy, s.last())
		t.Logf("coordinator decisions:\n%s%s", l.journalSince(survivors[0], since, "decision gate|no eligible host|rescheduling"),
			l.journalSince(survivors[1], since, "decision gate|no eligible host|rescheduling"))
	}
	for _, k := range lostKeys {
		if k == key {
			continue
		}
		if hs := s.last().executing(k); len(hs) == 0 {
			l.mark("drill6: note %s not recovered (two survivors may lack the memory)", k)
		}
	}

	// ── 4. remove, rebuild, re-add, re-vote ─────────────────────────────────
	if !d.removeDead() || !d.rebuild() || !d.addBack() || !d.voteBack() {
		t.FailNow()
	}
	d.recreateStranded()
	l.waitAllActive(q, 6*time.Minute)
	if gen, members, err := l.voterSet(q); err != nil || strings.Join(members, ",") != strings.Join(l.hosts, ",") {
		t.Errorf("final voters %v (generation %d, err %v), want %v", members, gen, err, l.hosts)
	} else {
		for _, h := range l.hosts {
			rows, err := l.sql(h, "SELECT MAX(generation) FROM local_voter_adoption")
			if err != nil || len(rows) == 0 || rows[0][0] != fmt.Sprint(gen) {
				t.Errorf("%s adopted generation %v (err %v), want %d", h, rows, err, gen)
			}
		}
	}
	time.Sleep(returnWatch)
	s.Stop()
	assertNeverTwice(t, s.snapshot())
	if hs := s.last().executing(key); len(hs) != 1 {
		t.Errorf("%s executing on %v after the restore, want exactly one host", key, hs)
	}
	assertNoDualRun(t, l, q, since, time.Now().Add(-returnWatch))
}

// finish completes whatever part of the rebuild the drill did not reach.
func (d *d6) finish() {
	if !d.forced {
		return // nothing irreversible happened; the generic restore powers hosts on
	}
	d.l.mark("drill6: cleanup finishing the rebuild")
	if d.removeDead() && d.rebuild() && d.addBack() && d.voteBack() {
		d.recreateStranded()
	}
}

// removeDead runs `lv host rm --dead` for every lost host still present.
func (d *d6) removeDead() bool {
	l := d.l
	for _, h := range d.lost {
		if d.removed[h] {
			continue
		}
		out, err := l.lv(d.via, "host", "rm", h, "--dead")
		if err != nil && !strings.Contains(out+err.Error(), "not found") {
			l.t.Errorf("host rm %s --dead: %v\n%s", h, err, out)
			return false
		}
		d.removed[h] = true
		l.mark("drill6: host rm --dead %s", h)
	}
	return true
}

// rebuild destroys and recreates each lost node and waits for its first boot.
func (d *d6) rebuild() bool {
	l := d.l
	var todo []string
	for _, h := range d.lost {
		if !d.rebuilt[h] {
			todo = append(todo, h)
		}
	}
	if len(todo) == 0 {
		return true
	}
	nums := l.nums(todo)
	if _, err := l.labsh(2*time.Minute, nil, append([]string{"destroy"}, nums...)...); err != nil {
		l.t.Errorf("rebuild: %v", err)
		return false
	}
	if _, err := l.labsh(2*time.Minute, []string{"SSH_KEY=" + l.key + ".pub"}, append([]string{"create"}, nums...)...); err != nil {
		l.t.Errorf("rebuild: %v", err)
		return false
	}
	if _, err := l.labsh(2*time.Minute, nil, append([]string{"up"}, nums...)...); err != nil {
		l.t.Errorf("rebuild: %v", err)
		return false
	}
	for _, h := range todo {
		l.closeMaster(h)
		deadline := time.Now().Add(rebuildBy)
		for {
			out, err := l.ssh(h, 30*time.Second, "test -f /var/lib/cloud/lab-ready && cloud-init status | head -1")
			if err == nil && strings.Contains(out, "done") {
				break
			}
			if time.Now().After(deadline) {
				l.t.Errorf("rebuild: %s not ready within %v: %v %s", h, rebuildBy, err, out)
				return false
			}
			time.Sleep(10 * time.Second)
		}
		d.rebuilt[h] = true
		l.mark("drill6: %s rebuilt", h)
	}
	return true
}

// addBack adds each rebuilt node to the cluster, one at a time, from the host
// that holds the CA, and waits for it to be active.
func (d *d6) addBack() bool {
	l := d.l
	for i := len(d.lost) - 1; i >= 0; i-- {
		h := d.lost[i]
		if d.added[h] {
			continue
		}
		ip := l.ip[h]
		l.ssh(d.via, 20*time.Second, "ssh-keygen -R "+ip+" >/dev/null 2>&1; true")
		out, err := l.ssh(d.via, 15*time.Minute, shellQuote(l.lvPath)+" host add root@"+ip+" --name "+h)
		l.saveEvidence("host-add-"+h+".txt", out)
		if err != nil {
			l.t.Errorf("host add %s: %v", h, err)
			return false
		}
		if err := l.waitDaemon(h, 5*time.Minute); err != nil {
			l.t.Errorf("host add %s: %v", h, err)
			return false
		}
		// The drills read state.db with sqlite3; the LXC host needs lxc back and
		// a restart so its daemon labels it litevirt.lxc=true again.
		pkgs := "sqlite3"
		if d.lxc[h] {
			pkgs += " lxc"
		}
		if _, err := l.ssh(h, 10*time.Minute, "DEBIAN_FRONTEND=noninteractive apt-get install -y -q "+pkgs+" >/dev/null"); err != nil {
			l.t.Errorf("install %s on %s: %v", pkgs, h, err)
		}
		if d.lxc[h] {
			if err := l.restartDaemon(h); err != nil {
				l.t.Errorf("%v", err)
			}
		}
		l.waitAllActive(d.via, 6*time.Minute)
		d.added[h] = true
		l.mark("drill6: %s added back", h)
	}
	return true
}

// voteBack adds each re-added host back to the voter set, one member per
// generation.
func (d *d6) voteBack() bool {
	l := d.l
	_, members, err := l.voterSet(d.via)
	if err != nil {
		l.t.Errorf("voter ls: %v", err)
		return false
	}
	for i := len(d.lost) - 1; i >= 0; i-- {
		h := d.lost[i]
		if contains(members, h) {
			continue
		}
		if out, err := l.lv(d.via, "cluster", "voter", "add", h); err != nil {
			l.t.Errorf("voter add %s: %v\n%s", h, err, out)
			return false
		}
		l.mark("drill6: voter add %s", h)
	}
	return true
}

// recreateStranded brings back a container whose host was lost and that no
// survivor could relocate (no survivor runs LXC): its row survives the host's
// removal but its rootfs did not (RESTORE.md R4), so it is re-created from its
// own create spec.
func (d *d6) recreateStranded() {
	l := d.l
	now := l.containers(d.via)
	for name, c := range d.cts {
		if cur, ok := now[name]; ok && cur.State == "running" {
			continue
		}
		if out, err := l.lv(d.via, "ct", "start", name, "--host", c.Host); err == nil {
			l.mark("drill6: started stranded container %s", name)
			continue
		} else {
			l.t.Logf("ct start %s: %v %s", name, err, out)
		}
		var spec struct{ Distro, Release, Arch string }
		_ = json.Unmarshal([]byte(c.CreateSpec), &spec)
		args := []string{"ct", "create", name, "--host", c.Host}
		if c.OnHostFailure != "" {
			args = append(args, "--on-host-failure", c.OnHostFailure)
		}
		if spec.Distro != "" {
			args = append(args, "--distro", spec.Distro, "--release", spec.Release)
		}
		l.lv(d.via, "ct", "rm", name, "--host", c.Host)
		if out, err := l.lv(d.via, args...); err != nil {
			l.t.Errorf("re-create %s: %v\n%s", name, err, out)
			continue
		}
		if out, err := l.lv(d.via, "ct", "start", name, "--host", c.Host); err != nil {
			l.t.Errorf("start re-created %s: %v\n%s", name, err, out)
			continue
		}
		l.mark("drill6: re-created stranded container %s on %s", name, c.Host)
	}
}

// leastLoaded returns the host among hosts with the least memory in use, per
// `lv host ls` (MEMORY "used/total MiB"): after the earlier drills have moved
// workloads around, a fixed choice can be full.
func (l *lab) leastLoaded(via string, hosts []string) string {
	l.t.Helper()
	best, bestUsed := "", -1
	for _, line := range strings.Split(l.mustLV(via, "host", "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !contains(hosts, f[0]) {
			continue
		}
		used, _, ok := strings.Cut(f[4], "/")
		if !ok {
			continue
		}
		var n int
		if _, err := fmt.Sscan(used, &n); err != nil {
			continue
		}
		if bestUsed < 0 || n < bestUsed {
			best, bestUsed = f[0], n
		}
	}
	if best == "" {
		l.t.Fatalf("no memory figures for %v in host ls", hosts)
	}
	return best
}
