package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/health"
)

// waitProbeFailures waits until via's connectivity table (`lv health`) shows
// via failing each target at least n consecutive times.
func (l *lab) waitProbeFailures(via string, targets []string, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := l.lv(via, "health") // exits non-zero while degraded
		ok := true
		for _, h := range targets {
			re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(via) + `\s+` + regexp.QuoteMeta(h) + `\s+\S+\s+(\d+)\s*$`)
			f := 0
			if m := re.FindStringSubmatch(out); m != nil {
				fmt.Sscan(m[1], &f)
			}
			if f < n {
				ok = false
			}
		}
		if ok {
			l.mark("%s counts %v failing %d+ probes", via, targets, n)
			return true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

// Drill 6 (docs/design/recovery-claims.md §7.3): three of five hosts are lost
// for good. The two survivors confirm the fences, force a 2-member voter
// generation, recover the lost hosts' workloads with no workaround, then the
// lost hosts are rebuilt from scratch, added back, and made voters again.
//
// It is the slowest drill and the only one that DESTROYS hosts (lab.sh destroy
// and create), so it runs only with LITEVIRT_E2E_DESTRUCTIVE=1. The procedure
// is the lab's kvm003:~/drill-evidence/d6-b3368d7c/RESTORE.md, minus the
// workarounds the finished build does not need: recovery on the forced
// generation (N3), the claim destination re-checked on adoption (N4), a
// rebuilt host never fenced during its join (R1/B6), and the rebuilt hosts
// joining gossip with the original ones (the island) all hold without help.
//
// A removed name is re-admitted only once no workload is recorded on it
// (AdmitHost, R4). Before the rebuilt hosts are added back, every workload
// still recorded on a lost host is either recovered by the coordinator or
// removed by the operator; the removed ones that belong to the lab are put
// back on their hosts once those have joined.

// rebuildBy bounds a rebuilt node's first boot (cloud-init installs qemu,
// libvirt and friends; ~80 s on kvm003).
const rebuildBy = 10 * time.Minute

// removedRecoverBy is how long the coordinator's removed-host pass gets to
// recover the recoverable workloads still recorded on a removed host before the
// drill removes what is left.
const removedRecoverBy = 4 * time.Minute

// joinWatch is how long a re-added host is watched once it is active: finding
// R1 was a coordinator fencing a host in the seconds after it joined.
const joinWatch = 60 * time.Second

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
	// cleared: no workload is recorded on a lost host any more.
	cleared bool
	// stacks holds the exported compose YAML of each stack a removed lab VM
	// belonged to, goneVMs each removed lab VM's recorded host, and goneCts
	// the lab containers removed, all put back by putBack once their hosts
	// have joined. putBack drops each entry once it is back, so a cleanup
	// resuming after a partial put-back does not create anything twice.
	stacks  map[string]string
	goneVMs map[string]string
	goneCts map[string]ctInfo
}

func TestDrill6_ForceReconfigureAndRebuild(t *testing.T) {
	if os.Getenv("LITEVIRT_E2E_DESTRUCTIVE") != "1" {
		t.Skip("destructive: set LITEVIRT_E2E_DESTRUCTIVE=1 to destroy and rebuild three lab hosts")
	}
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	survivors, lost := l.hosts[:2], l.hosts[2:]
	q := survivors[0]
	if out, err := l.ssh(q, 20*time.Second, "test -s /root/.config/litevirt/pki/ca.key && echo CA"); err != nil || !strings.Contains(out, "CA") {
		t.Fatalf("%s holds no cluster CA key; host add must run where the CA is", q)
	}
	d := &d6{l: l, via: q, survivors: survivors, lost: lost, removed: map[string]bool{},
		rebuilt: map[string]bool{}, added: map[string]bool{}, lxc: map[string]bool{}, cts: map[string]ctInfo{},
		stacks: map[string]string{}, goneVMs: map[string]string{}, goneCts: map[string]ctInfo{}}
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

	// The audit verdict before anything is destroyed. A rebuilt host re-added
	// under its old name used to fork its own audit chain (seq 1, prev_hash "")
	// and start its new key's contract at seq 0, and nothing here looked: every
	// run passed while each one added findings `lv audit verify` reports for good.
	auditBefore, auditErr := l.lv(q, "audit", "verify")
	auditCleanBefore := auditErr == nil
	l.saveEvidence("audit-verify-before.txt", auditBefore)

	since := l.nodeNow(q)
	s := l.startSampler()
	waitAllAt(t, s, []string{key}, target)

	// ── 1. lose three hosts; confirm the fences during the outage ──────────
	off := l.powerOff(lost...)
	// Two survivors of five hold no quorum, so nobody fences the lost hosts
	// and their state stays active. A confirmation counts only once the
	// survivors have watched them fail, so wait for F consecutive probe
	// failures of each in q's own probes.
	if !l.waitProbeFailures(q, lost, health.FailuresToFence, hostDownBy) {
		t.Fatalf("%s did not see %v fail %d probes within %v", q, lost, health.FailuresToFence, hostDownBy)
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
	var onSurvivor []string
	for _, k := range lostKeys {
		if hs := s.last().executing(k); len(hs) == 1 && contains(survivors, hs[0]) {
			onSurvivor = append(onSurvivor, k)
		} else if k != key {
			l.mark("drill6: note %s not recovered (two survivors may lack the memory)", k)
		}
	}
	if _, ok := recovered[key]; !ok {
		// Two survivors cannot hold three hosts' guests, and the coordinator
		// places host by host, so the test VM can find them full. That is not
		// the drill's failure when the coordinator said so and recovered others
		// on the forced generation; anything else is (N3: missing_witness).
		full := regexp.MustCompile(`no eligible host for VM.*vm=` + regexp.QuoteMeta(test) + `\b|batch placement failed.*host=` + regexp.QuoteMeta(target) + `\b`)
		decisions := l.journalSince(survivors[0], since, "decision gate|no eligible host|batch placement failed|rescheduling") +
			l.journalSince(survivors[1], since, "decision gate|no eligible host|batch placement failed|rescheduling")
		l.saveEvidence("coordinator-decisions.txt", decisions)
		if full.MatchString(decisions) && len(onSurvivor) > 0 {
			l.mark("drill6: %s not recovered: the survivors are full (coordinator said so); recovered on the forced generation: %v", key, onSurvivor)
		} else {
			t.Errorf("%s was not recovered on a survivor within %v of the power-off (N3: missing_witness?); recovered: %v\n  %s", key, recoverBy, onSurvivor, s.last())
			t.Logf("coordinator decisions:\n%s", decisions)
		}
	}

	// ── 4. remove, rebuild, clear, re-add, re-vote, put back ────────────────
	if !d.run() {
		t.FailNow()
	}
	if states, err := l.hostStates(q); err != nil {
		t.Errorf("host ls: %v", err)
	} else {
		for _, h := range l.hosts {
			if states[h] != "HOST_ACTIVE" {
				t.Errorf("%s is %s after the rebuild, want HOST_ACTIVE with no undrain", h, states[h])
			}
		}
	}
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

	// Every node, the rebuilt ones included, still verifies the audit log as it
	// did before. A lab whose log already carried findings cannot show this —
	// signed rows are never repaired (docs/audit-log.md, "Rebuilding a host
	// under its old name") — so it is only checked from a clean start.
	for _, h := range l.hosts {
		out, err := l.lv(h, "audit", "verify")
		l.saveEvidence("audit-verify-after-"+h+".txt", out)
		switch {
		case auditCleanBefore && err != nil:
			t.Errorf("%s: the audit log verified clean before the drill and does not after it:\n%s", h, out)
		case !auditCleanBefore:
			t.Logf("%s: the audit log already carried findings before the drill, so the rebuild's effect "+
				"on it is not checked (see audit-verify-before.txt)", h)
		}
	}
}

// finish completes whatever part of the rebuild the drill did not reach.
func (d *d6) finish() {
	if !d.forced {
		return // nothing irreversible happened; the generic restore powers hosts on
	}
	d.l.mark("drill6: cleanup finishing the rebuild")
	d.run()
}

// run takes the rebuild from wherever it stands to the end, stopping at the
// first step that fails. The lost machines are destroyed straight after their
// removal, before anything that can fail: a removed machine booted again by a
// restore would come back with its old replica, which still names it the owner
// of its workloads.
func (d *d6) run() bool {
	return d.removeDead() && d.rebuild() && d.clearRemoved() && d.addBack() && d.voteBack() && d.putBack()
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
		if !l.isUp(h) { // a cleanup resuming after a host was powered off in its join
			if _, err := l.labsh(2*time.Minute, nil, "up", l.nums([]string{h})[0]); err != nil {
				l.t.Errorf("power on %s: %v", h, err)
			}
			l.closeMaster(h)
		}
		if out, _ := l.ssh(d.via, 2*time.Minute, shellQuote(l.lvPath)+" host ls"); strings.Contains(out, h+" ") {
			// Added already (an earlier attempt got that far): just wait for it.
			if err := l.waitDaemon(h, 5*time.Minute); err != nil {
				l.t.Errorf("%v", err)
				return false
			}
			d.added[h] = true
			continue
		}
		ip := l.ip[h]
		l.ssh(d.via, 20*time.Second, "ssh-keygen -R "+ip+" >/dev/null 2>&1; true")
		addAt := l.nodeNow(d.via)
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
		// Watch the join until the host is active and for joinWatch after:
		// finding R1 was a coordinator fencing a host in the seconds after its
		// add (the probe failures it counted while the host was being installed
		// carried over), which powered the rebuilt node off. A fence here is a
		// failure, and the host is not powered back on or undrained to hide it.
		if !d.watchJoin(h, addAt) {
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
		if d.lxc[h] && !d.watchJoin(h, addAt) {
			return false
		}
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
		if err := l.voterAdd(d.via, h); err != nil {
			l.t.Errorf("%v", err)
			return false
		}
	}
	return true
}

// watchJoin waits until h is HOST_ACTIVE and then watches it for joinWatch,
// failing on any sign that it was fenced since addAt (node clock): a fencing_log
// row, a fenced hosts row, or its machine powered off.
func (d *d6) watchJoin(h, addAt string) bool {
	l := d.l
	deadline := time.Now().Add(6 * time.Minute)
	var activeAt time.Time
	for {
		if !l.isUp(h) {
			l.t.Errorf("R1: %s was powered off during its join (added at %s); fencing_log:\n%s", h, addAt, d.fenceRows(h, addAt))
			return false
		}
		if rows := d.fenceRows(h, addAt); rows != "" {
			l.t.Errorf("R1: %s was fenced during its join (added at %s):\n%s", h, addAt, rows)
			return false
		}
		states, err := l.hostStates(d.via)
		if err == nil && states[h] == "HOST_ACTIVE" && activeAt.IsZero() {
			activeAt = l.mark("drill6: %s active after its join", h)
		}
		if !activeAt.IsZero() && time.Since(activeAt) >= joinWatch {
			return true
		}
		if time.Now().After(deadline) {
			l.t.Errorf("%s not active within 6m of its add: %v (err %v)", h, states, err)
			return false
		}
		time.Sleep(5 * time.Second)
	}
}

// fenceRows lists the fencing_log rows for h since addAt, and its hosts row if
// that says fenced, in via's replica ("" when there are none).
func (d *d6) fenceRows(h, addAt string) string {
	var b strings.Builder
	rows, _ := d.l.sql(d.via, fmt.Sprintf("SELECT method,result,timestamp,COALESCE(detail,'') FROM fencing_log WHERE host_name='%s' AND timestamp >= '%s'", h, addAt))
	for _, r := range rows {
		b.WriteString(strings.Join(r, "|") + "\n")
	}
	if st, _ := d.l.sql(d.via, fmt.Sprintf("SELECT state FROM hosts WHERE name='%s' AND deleted_at IS NULL", h)); len(st) > 0 && st[0][0] == "fenced" {
		b.WriteString("hosts.state=fenced\n")
	}
	return b.String()
}

// recorded lists the live VM and container rows recorded on a lost host, as
// "vm/<name>" and "ct/<name>" → host: what AdmitHost refuses a re-admission
// over (corrosion.WorkloadsOnRemovedHost).
func (d *d6) recorded() (map[string]string, error) {
	q := "SELECT 'vm/'||name, host_name FROM vms WHERE deleted_at IS NULL AND host_name IN ('" + strings.Join(d.lost, "','") + "')" +
		" UNION SELECT 'ct/'||name, host_name FROM containers WHERE deleted_at IS NULL AND is_template=0 AND host_name IN ('" + strings.Join(d.lost, "','") + "')"
	rows, err := d.l.sql(d.via, q)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, r := range rows {
		if len(r) >= 2 {
			m[r[0]] = r[1]
		}
	}
	return m, nil
}

// clearRemoved leaves no workload recorded on a lost host, so the rebuilt
// machines can take the names (AdmitHost refuses a name the removed machine
// left workloads on, R4). The coordinator's removed-host pass recovers what it
// can; the drill waits for that, then removes what is left (a policy-none VM,
// a container no survivor can run, a VM the survivors have no room for) the
// way the refusal says: `lv rm <vm>` and `lv ct rm <ct> --host <removed>`,
// which delete the rows of a workload on a removed host without dialling it.
// No --force: there is nothing on a removed machine to stop. Nothing here
// edits a database or removes and re-adds a host to get past the refusal.
// Lab workloads removed here are put back by putBack.
func (d *d6) clearRemoved() bool {
	if d.cleared {
		return true
	}
	l := d.l
	survivorLXC := false
	for _, h := range d.survivors {
		if l.labels(d.via, h)["litevirt.lxc"] == "true" {
			survivorLXC = true
		}
	}
	vms := l.vms(d.via)
	// movable: what the removed-host pass may still recover.
	movable := func(k string) bool {
		kind, name, _ := strings.Cut(k, "/")
		if kind == "ct" {
			return survivorLXC && d.cts[name].recoverable()
		}
		v, ok := vms[name]
		return ok && v.recoverable()
	}
	var left map[string]string
	deadline := time.Now().Add(removedRecoverBy)
	for {
		var err error
		left, err = d.recorded()
		if err == nil {
			waiting := false
			for k := range left {
				if movable(k) {
					waiting = true
				}
			}
			if len(left) == 0 || !waiting || time.Now().After(deadline) {
				break
			}
		} else if time.Now().After(deadline) {
			l.t.Errorf("workloads on the removed hosts: %v", err)
			return false
		}
		time.Sleep(10 * time.Second)
	}
	l.mark("drill6: recorded on the removed hosts after the removed-host pass: %v", left)
	if out, err := l.lv(d.via, "health"); out != "" {
		l.saveEvidence("health-before-clear.txt", out+fmt.Sprint(err))
	}
	for k, h := range left {
		kind, name, _ := strings.Cut(k, "/")
		if kind == "vm" {
			if !strings.HasPrefix(name, "e2e-") {
				rows, _ := l.sql(d.via, "SELECT COALESCE(stack_name,'') FROM vms WHERE name='"+name+"' AND deleted_at IS NULL")
				if len(rows) == 0 || rows[0][0] == "" {
					l.t.Errorf("%s on removed %s has no stack to restore it from; not removing it", k, h)
					return false
				}
				stack := rows[0][0]
				if _, ok := d.stacks[stack]; !ok {
					y, err := l.lv(d.via, "compose", "export", stack)
					if err != nil {
						l.t.Errorf("compose export %s: %v", stack, err)
						return false
					}
					d.stacks[stack] = y
					l.saveEvidence("stack-"+stack+".yaml", y)
				}
				d.goneVMs[name] = h
			}
			if out, err := l.lv(d.via, "rm", name); err != nil {
				l.t.Errorf("R4: %s is recorded on removed %s and `lv rm %s` fails, so %s cannot be added back: %v\n%s", k, h, name, h, err, out)
				return false
			}
		} else {
			if c, ok := d.cts[name]; ok {
				d.goneCts[name] = c
			}
			if out, err := l.lv(d.via, "ct", "rm", name, "--host", h); err != nil {
				l.t.Errorf("R4: %s is recorded on removed %s and `lv ct rm %s --host %s` fails, so %s cannot be added back: %v\n%s", k, h, name, h, h, err, out)
				return false
			}
		}
		l.mark("drill6: removed %s, recorded on removed %s", k, h)
	}
	// Every replica the add may run against must agree.
	deadline = time.Now().Add(2 * time.Minute)
	for {
		left, err := d.recorded()
		if err == nil && len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			l.t.Errorf("still recorded on the removed hosts after the removals: %v (err %v)", left, err)
			return false
		}
		time.Sleep(5 * time.Second)
	}
	d.cleared = true
	return true
}

// putBack restores the lab workloads clearRemoved removed: each exported stack
// is brought up again (compose creates only what is missing, which the plan
// must say before it runs), and each container is re-created from its own
// create spec on its own host.
//
// A removed VM goes back on the host it was recorded on, which is the rebuilt
// machine under the same name. Its exported placement still names the host it
// was first pinned to, and failover had moved it from there long before: the
// survivors now hold what the coordinator recovered onto them, so that host
// can be full ("no eligible host ... memory").
func (d *d6) putBack() bool {
	l := d.l
	ok := true
	for stack, y := range d.stacks {
		y, err := repinVMs(y, d.goneVMs)
		if err != nil {
			l.t.Errorf("restore stack %s: %v", stack, err)
			ok = false
			continue
		}
		file := "/tmp/e2e-d6-restore-" + stack + ".yaml"
		l.mustSSH(d.via, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(y))+" | base64 -d > "+file)
		plan, err := l.lv(d.via, "compose", "diff", "-f", file)
		if err != nil || !regexp.MustCompile(`Plan: \d+ to create, 0 to update, 0 to delete`).MatchString(plan) {
			l.t.Errorf("restore stack %s: plan is not create-only (err %v):\n%s", stack, err, plan)
			ok = false
			continue
		}
		if out, err := l.lv(d.via, "compose", "up", "-f", file, "-y"); err != nil {
			l.t.Errorf("restore stack %s: %v\n%s", stack, err, out)
			ok = false
			continue
		}
		l.mark("drill6: stack %s brought back: %s", stack, strings.TrimSpace(strings.SplitN(plan, "\n", 2)[0]))
		delete(d.stacks, stack)
	}
	for name, c := range d.goneCts {
		var spec struct{ Distro, Release, Arch string }
		_ = json.Unmarshal([]byte(c.CreateSpec), &spec)
		args := []string{"ct", "create", name, "--host", c.Host}
		if c.OnHostFailure != "" {
			args = append(args, "--on-host-failure", c.OnHostFailure)
		}
		if spec.Distro != "" {
			args = append(args, "--distro", spec.Distro, "--release", spec.Release)
		}
		if out, err := l.lv(d.via, args...); err != nil {
			l.t.Errorf("re-create %s: %v\n%s", name, err, out)
			ok = false
			continue
		}
		if out, err := l.lv(d.via, "ct", "start", name, "--host", c.Host); err != nil {
			l.t.Errorf("start re-created %s: %v\n%s", name, err, out)
			ok = false
			continue
		}
		l.mark("drill6: re-created container %s on %s", name, c.Host)
		delete(d.goneCts, name)
	}
	return ok
}

// repinVMs rewrites the placement host of each VM in hosts (name → host) in
// the compose YAML y, keeping everything else as exported (a node tree, so key
// order and quoting survive). A VM y does not name is left alone.
func repinVMs(y string, hosts map[string]string) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(y), &root); err != nil {
		return "", fmt.Errorf("parse exported stack: %w", err)
	}
	if len(root.Content) == 0 {
		return "", fmt.Errorf("exported stack is empty")
	}
	vms := mapValue(root.Content[0], "vms")
	if vms == nil {
		return "", fmt.Errorf("exported stack has no vms")
	}
	for name, h := range hosts {
		vm := mapValue(vms, name)
		if vm == nil || vm.Kind != yaml.MappingNode {
			continue
		}
		pl := mapValue(vm, "placement")
		if pl == nil {
			pl = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			vm.Content = append(vm.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "placement"}, pl)
		}
		if hn := mapValue(pl, "host"); hn != nil {
			hn.Value = h
		} else {
			pl.Content = append(pl.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "host"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: h})
		}
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// mapValue returns the value node under key in mapping node m, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
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
