package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/tests/e2e/e2ehelp"
)

// The noisy-neighbour controls against a real hypervisor. tests/fleet injects
// internal/libvirtfake, which only models the XML edit; whether libvirt accepts
// the cputune global quota, the scheduler write reaches the cgroup of a running
// guest, the weight lands in cpu.weight, the iotune reaches qemu and the
// <bandwidth> shapes the tap and survives a migration is only knowable here.
// Every assertion reads libvirt (virsh), the cgroup or tc ON THE NODE, never
// litevirt's report of what it did.
//
// The VM is a COMPOSE VM with a network: a NIC rate is a per-NIC spec entry,
// and the product refuses (by design) to rate a NIC that was hot-plugged after
// create, because it has no spec entry to hold the rate. `lv run` has no
// network flag, so `attach-nic` onto it cannot be rate-limited.
//
// Runs on a cluster node (virsh is local); skips elsewhere.

// sshTarget is what to hand ssh to reach a cluster host from this node. Cluster
// host names do not resolve in DNS on the nodes, so it is the host's address
// (E2E_SSH_<name> overrides it).
func sshTarget(host string) string { return e2ehelp.SSHTarget(host, os.Getenv, hostIPs) }

// nodeOut runs a shell script on a cluster host (locally for the host the suite
// runs on) and returns its combined output.
func nodeOut(host, script string) (string, error) {
	var cmd *exec.Cmd
	if host == localHost && localHost != "" {
		cmd = exec.Command("sh", "-c", script)
	} else {
		cmd = exec.Command("timeout", "60", "ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no", sshTarget(host), script)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// readLimits reads domain's limits on host in one round trip.
func readLimits(t *testing.T, host, domain string) e2ehelp.Limits {
	t.Helper()
	glob := strings.ReplaceAll(domain, "-", "*")
	script := fmt.Sprintf(`D=%[1]s
V="virsh -c qemu:///system"
mac=$($V domiflist $D | awk 'NR>2 && NF>=5 {print $5; exit}')
tap=$($V domiflist $D | awk 'NR>2 && NF>=5 {print $1; exit}')
echo '##sched'; $V schedinfo $D
echo '##schedcfg'; $V schedinfo $D --config
echo '##iflive'; $V domiftune $D $mac
echo '##ifcfg'; $V domiftune $D $mac --config
echo '##iotune'; $V blkdeviotune $D vda
echo '##tap'; echo "$tap"
echo '##tc'; [ -n "$tap" ] && tc class show dev $tap
echo '##cfgxml'; $V dumpxml --inactive $D
echo '##v2'; test -e /sys/fs/cgroup/cgroup.controllers && echo yes || echo no
echo '##cgroup'
for s in /sys/fs/cgroup/machine.slice/machine-qemu*%[2]s*.scope /sys/fs/cgroup/cpu,cpuacct/machine.slice/machine-qemu*%[2]s*.scope; do
  [ -d "$s" ] || continue
  for f in cpu.weight cpu.max libvirt/cpu.max cpu.shares cpu.cfs_quota_us cpu.cfs_period_us libvirt/cpu.cfs_quota_us libvirt/cpu.cfs_period_us; do
    [ -r "$s/$f" ] && echo "$f=$(cat $s/$f)"
  done
  break
done
true
`, domain, glob)
	out, err := nodeOut(host, script)
	if err != nil {
		t.Fatalf("reading libvirt/cgroup/tc for %s on %s: %v\n%s", domain, host, err, out)
	}
	return e2ehelp.ParseLimits(host, out)
}

// report fails the test once per problem.
func report(t *testing.T, when string, problems []string) {
	t.Helper()
	for _, p := range problems {
		t.Errorf("%s: %s", when, p)
	}
}

// limitsNetwork creates a bridge network for a limits test and registers its
// cleanup, which removes the network and then checks that `lv network rm`
// removed the Linux bridge it provisioned from every host.
func limitsNetwork(t *testing.T, subnet string) string {
	t.Helper()
	netName := uniqueName("ln")
	cleanup(t, func() {
		lvErr(t, "network", "rm", netName, "--force")
		assertTestBridgeGone(t, netName)
	})
	lv(t, "network", "create", netName, "--type", "bridge", "--subnet", subnet, "--dhcp")
	return netName
}

// assertTestBridgeGone checks, on every cluster host, that the Linux bridge
// the test's own bridge network (created without --interface) provisioned is
// gone once the network is removed: litevirt created it, so `lv network rm`
// removes it on every node within a reconcile pass or two (lab finding P-5).
//
// It used to delete the bridge itself, which hid exactly that leak. It now
// fails the test on a bridge still present after the wait, and only then
// deletes it, so one leak does not spill into the next run. The name is
// derived from a uniqueName, so no bridge the test did not create can match.
func assertTestBridgeGone(t *testing.T, netName string) {
	t.Helper()
	br := network.FlatBridgeName(netName)
	if !strings.HasPrefix(netName, "e2e-") || br == "" {
		t.Logf("refusing to check bridge %q of network %q: not a test-created name", br, netName)
		return
	}
	failed := waitOnHosts(hostNames, bridgeAbsent(br), netRmPass)
	if len(failed) == 0 {
		return
	}
	t.Errorf("`lv network rm %s` left bridge %s on %d host(s) after %s: %v", netName, br, len(failed), netRmPass, failed)
	for h := range failed {
		if out, err := nodeOut(h, "if ip link show "+br+" >/dev/null 2>&1; then ip link del "+br+"; fi"); err != nil {
			t.Logf("cleanup: removing leaked bridge %s on %s: %v\n%s", br, h, err, out)
		}
	}
}

// limitsComposeFile renders the stack: a VM with a CPU cap and weight, a
// throttled root disk and ONE NIC on netName with a rate, all in its spec.
func limitsComposeFile(t *testing.T, stack, vm, host, netName string) string {
	t.Helper()
	y := fmt.Sprintf(`name: %s
networks:
  %s:
    external: true
vms:
  %s:
    image: %s
    cpu: 2
    memory: 1024
    cpu-limit: 1
    cpu-shares: 200
    disks:
      root:
        size: 5G
        iotune:
          read_iops_sec: 300
          write_bytes_sec: 20M
    network:
      - name: %s
        rate: 4
    placement:
      host: %s
`, stack, netName, vm, testImage, netName, host)
	f := fmt.Sprintf("/tmp/e2e-limits-%d-%s.yaml", os.Getpid(), vm)
	if err := os.WriteFile(f, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f) })
	return f
}

// limitsVM creates the compose VM on a local-capacity host and waits for it to
// run, skipping when the cluster refuses limits because the release token has
// not latched (a node is still on an older build): a rollout state, not a defect.
func limitsVM(t *testing.T, name, subnet string) (host string) {
	t.Helper()
	if !virshAvailable() {
		t.Skip("needs virsh on a cluster node")
	}
	requireImage(t)
	host = hostWithCapacity(t, 2, 1024)
	if host != localHost {
		t.Skipf("no local capacity (placed on %s); virsh assertions need the local host", host)
	}
	netName := limitsNetwork(t, subnet)
	stack := uniqueName("lstk")
	cleanup(t, func() { lvErr(t, "compose", "down", "--name", stack, "-y") })
	out, err := lvErr(t, "compose", "up", "-f", limitsComposeFile(t, stack, name, host, netName), "-y")
	if err != nil {
		if strings.Contains(out+err.Error(), "cluster upgrade") {
			t.Skipf("the release token has not latched (roll every node to this build first): %v", err)
		}
		t.Fatalf("compose up with limits: %v\n%s", err, out)
	}
	waitVM(t, name, "RUNNING", 3*time.Minute)
	return host
}

func TestVM_NoisyNeighbourLimits_AppliedLiveAndPersisted(t *testing.T) {
	name := uniqueName("limits")
	host := limitsVM(t, name, "172.34.1.0/24")

	// At create: a 1-core cap is 100000us of CPU per 100000us period for the
	// WHOLE guest, weight 200, the disk throttled, the NIC at 4 MB/s.
	s := readLimits(t, host, name)
	report(t, "at create", s.CPUProblems(200, 100000))
	report(t, "at create", s.DiskProblems("300", "20971520"))
	report(t, "at create", s.NICProblems("4000", "32Mbit"))

	// Change CPU and NIC on the RUNNING guest: no stop, same qemu process.
	pid := qemuPID(name)
	lv(t, "update", name, "--cpu-limit", "1.5", "--cpu-shares", "400", "--nic-rate", "0=2")
	if got := qemuPID(name); pid == "" || got != pid {
		t.Errorf("qemu pid %q -> %q: a limit change restarted the guest", pid, got)
	}
	s = readLimits(t, host, name)
	report(t, "live update", s.CPUProblems(400, 150000))
	report(t, "live update", s.DiskProblems("300", "20971520")) // untouched
	report(t, "live update", s.NICProblems("2000", "16Mbit"))
	if out := lv(t, "inspect", name); !strings.Contains(out, "cpuLimit") || !strings.Contains(out, "rateMbSec") {
		t.Errorf("lv inspect does not show the limits:\n%s", out)
	}

	// Removal.
	lv(t, "update", name, "--cpu-limit", "0", "--cpu-shares", "0", "--nic-rate", "0=0")
	report(t, "after removal", readLimits(t, host, name).RemovedProblems("16Mbit"))
}

// A live migration carries the definition, so the destination's guest must run
// under the same cap, weight, disk throttle and rate. Needs a second ACTIVE host
// reachable by ssh from here; skips only when there is none. Once there is one, a
// failure to migrate or to read the destination is a failure, not a skip.
func TestVM_NoisyNeighbourLimits_SurviveMigration(t *testing.T) {
	if !virshAvailable() {
		t.Skip("needs virsh on a cluster node")
	}
	// The destination must be ACTIVE, not this host, and have room for the
	// guest (2 vCPU, 1024 MiB, plus qemu overhead): a host without it refuses
	// the migration on capacity, which says nothing about the limits.
	const needMiB = 1024 + 256
	var target string
	sawOther := false
	for _, line := range strings.Split(lv(t, "host", "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.Contains(line, "ACTIVE") || f[0] == localHost {
			continue
		}
		if witnessHosts(t)[f[0]] {
			continue // a witness runs no guests, whatever `host ls` shows for it
		}
		sawOther = true
		if free(t, f[3]) < 2 || free(t, f[4]) < needMiB {
			continue
		}
		target = f[0]
		break
	}
	if target == "" {
		if sawOther {
			t.Skipf("no other active host has 2 free vCPUs and %d MiB free memory for the guest", needMiB)
		}
		t.Skip("needs a second active host")
	}
	name := uniqueName("limmig")
	host := limitsVM(t, name, "172.34.2.0/24")
	lv(t, "update", name, "--cpu-limit", "1.5", "--cpu-shares", "400", "--nic-rate", "0=2")

	// The VM has a host-local disk, which `lv migrate` refuses to move without
	// --with-storage.
	if out, err := lvErr(t, "migrate", name, target, "--with-storage"); err != nil {
		if strings.Contains(out, "qemu overhead") {
			t.Skipf("%s has no room for the guest: %s", target, out)
		}
		t.Fatalf("migration to %s failed: %v\n%s", target, err, out)
	}
	waitVM(t, name, "RUNNING", 3*time.Minute)

	// The destination definition carries the TARGET's scale for the weight.
	s := readLimits(t, target, name)
	report(t, "after migration", s.CPUProblems(400, 150000))
	report(t, "after migration", s.DiskProblems("300", "20971520"))
	report(t, "after migration", s.NICProblems("2000", "16Mbit"))

	// The source domain is gone: a leftover would still be throttling a ghost.
	if out, err := nodeOut(host, "virsh -c qemu:///system domstate "+name); err == nil {
		t.Errorf("the source still defines the domain after the move: %s", out)
	}
}

// witnessHosts is the set of witness hosts, read from this node's state
// database. Without sqlite3 it is empty: nothing is excluded, as before.
func witnessHosts(t *testing.T) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		return set
	}
	out, err := exec.Command(sqlite, "-readonly", "/var/lib/litevirt/state.db",
		"SELECT name FROM hosts WHERE deleted_at IS NULL AND role = 'witness'").Output()
	if err != nil {
		t.Logf("cannot read the witnesses (%v); none is excluded from the migration target", err)
		return set
	}
	for _, n := range strings.Fields(string(out)) {
		set[n] = true
	}
	return set
}
