package e2ehelp

import (
	"strings"
	"testing"
)

// The scripts' output as seen on lab 1: node-3 (cgroup v2) and node-2 (v1).
const v2Out = `##sched
Scheduler      : posix
cpu_shares     : 400
vcpu_period    : 100000
vcpu_quota     : 17592186044415
emulator_period: 100000
emulator_quota : 17592186044415
global_period  : 100000
global_quota   : 150000
iothread_period: 100000
iothread_quota : 17592186044415

##schedcfg
Scheduler      : posix
cpu_shares     : 400
global_period  : 100000
global_quota   : 150000

##iflive
inbound.average: 2000
inbound.peak   : 0
outbound.average: 2000
outbound.peak  : 0

##ifcfg
inbound.average: 2000
outbound.average: 2000

##iotune
write_bytes_sec: 20971520
read_iops_sec  : 300
group_name     : /machine/peripheral/virtio-disk0/virtio-backend

##tap
lvt525400cad72c
##tc
class htb 1:1 root leaf 2: prio 0 rate 16Mbit ceil 16Mbit burst 1600b cburst 1600b 
##cfgxml
      <bandwidth>
        <inbound average='2000'/>
        <outbound average='2000'/>
      </bandwidth>
##v2
yes
##cgroup
cpu.weight=400
cpu.max=max 100000
libvirt/cpu.max=150000 100000
`

const v1Out = `##sched
cpu_shares     : 4096
global_period  : 100000
global_quota   : 150000
##schedcfg
cpu_shares     : 4096
global_period  : 100000
global_quota   : 150000
##iflive
inbound.average: 2000
outbound.average: 2000
##ifcfg
inbound.average: 2000
outbound.average: 2000
##iotune
write_bytes_sec: 20971520
read_iops_sec  : 300
##tap
lvt525400cad72c
##tc
class htb 1:1 root leaf 2: prio 0 rate 16Mbit ceil 16Mbit burst 1600b cburst 1600b 
##cfgxml
        <inbound average='2000'/>
##v2
no
##cgroup
cpu.shares=4096
cpu.cfs_quota_us=-1
cpu.cfs_period_us=100000
libvirt/cpu.shares=1024
libvirt/cpu.cfs_quota_us=150000
libvirt/cpu.cfs_period_us=100000
`

func TestHostShares(t *testing.T) {
	for _, c := range []struct {
		v2   bool
		w, s int
	}{{true, 200, 200}, {false, 200, 2048}, {false, 400, 4096}, {false, 100, 1024}, {false, 1, 10}, {false, 0, 2}} {
		if got := HostShares(c.v2, c.w); got != c.s {
			t.Errorf("HostShares(%v, %d) = %d, want %d", c.v2, c.w, got, c.s)
		}
	}
}

func TestLimits_RealOutputPasses(t *testing.T) {
	v2 := ParseLimits("node-3", v2Out)
	v1 := ParseLimits("node-2", v1Out)
	if !v2.V2 || v1.V2 || v2.Tap != "lvt525400cad72c" {
		t.Fatalf("parse: v2=%v v1=%v tap=%q", v2.V2, v1.V2, v2.Tap)
	}
	for name, l := range map[string]Limits{"v2": v2, "v1": v1} {
		for _, p := range [][]string{l.CPUProblems(400, 150000), l.DiskProblems("300", "20971520"), l.NICProblems("2000", "16Mbit")} {
			if len(p) != 0 {
				t.Errorf("%s: unexpected problems on the output a correct host gives: %v", name, p)
			}
		}
	}
}

// Each case breaks ONE property and must be reported, on both cgroup versions.
func TestLimits_EachBrokenPropertyIsReported(t *testing.T) {
	cases := []struct {
		name     string
		from, to string
		check    func(Limits) []string
	}{
		{"v2 weight not in cpu.weight", "cpu.weight=400", "cpu.weight=100", func(l Limits) []string { return l.CPUProblems(400, 150000) }},
		{"v2 quota not in the cgroup", "libvirt/cpu.max=150000 100000", "libvirt/cpu.max=max 100000", func(l Limits) []string { return l.CPUProblems(400, 150000) }},
		{"v2 wrong quota in the cgroup", "libvirt/cpu.max=150000 100000", "libvirt/cpu.max=100000 100000", func(l Limits) []string { return l.CPUProblems(400, 150000) }},
		{"live global_quota", "global_quota   : 150000\niothread_period", "global_quota   : 100000\niothread_period", func(l Limits) []string { return l.CPUProblems(400, 150000) }},
		{"persistent shares", "##schedcfg\nScheduler      : posix\ncpu_shares     : 400", "##schedcfg\nScheduler      : posix\ncpu_shares     : 1024", func(l Limits) []string { return l.CPUProblems(400, 150000) }},
		{"live period", "global_period  : 100000\nglobal_quota   : 150000\niothread", "global_period  : 50000\nglobal_quota   : 150000\niothread", func(l Limits) []string { return l.CPUProblems(400, 150000) }},
		{"disk iops", "read_iops_sec  : 300", "read_iops_sec  : 0", func(l Limits) []string { return l.DiskProblems("300", "20971520") }},
		{"disk bytes", "write_bytes_sec: 20971520", "write_bytes_sec: 0", func(l Limits) []string { return l.DiskProblems("300", "20971520") }},
		{"live NIC rate", "##iflive\ninbound.average: 2000", "##iflive\ninbound.average: 0", func(l Limits) []string { return l.NICProblems("2000", "16Mbit") }},
		{"persistent NIC rate", "##ifcfg\ninbound.average: 2000\noutbound.average: 2000", "##ifcfg\ninbound.average: 2000\noutbound.average: 0", func(l Limits) []string { return l.NICProblems("2000", "16Mbit") }},
		{"config xml", "<inbound average='2000'/>", "<inbound average='1'/>", func(l Limits) []string { return l.NICProblems("2000", "16Mbit") }},
		{"tc rate", "rate 16Mbit", "rate 32Mbit", func(l Limits) []string { return l.NICProblems("2000", "16Mbit") }},
		{"no tc class", "class htb 1:1 root leaf 2: prio 0 rate 16Mbit ceil 16Mbit burst 1600b cburst 1600b \n", "", func(l Limits) []string { return l.NICProblems("2000", "16Mbit") }},
		{"no tap", "lvt525400cad72c\n##tc", "\n##tc", func(l Limits) []string { return l.NICProblems("2000", "16Mbit") }},
	}
	for _, c := range cases {
		if !strings.Contains(v2Out, c.from) {
			t.Fatalf("%s: test data lacks %q", c.name, c.from)
		}
		if p := c.check(ParseLimits("n", strings.Replace(v2Out, c.from, c.to, 1))); len(p) == 0 {
			t.Errorf("%s: v2: broken property not reported", c.name)
		}
	}
	for _, c := range []struct{ name, from, to string }{
		{"v1 shares not in cpu.shares", "cpu.shares=4096", "cpu.shares=1024"},
		{"v1 quota only on the scope's unlimited level", "libvirt/cpu.cfs_quota_us=150000", "libvirt/cpu.cfs_quota_us=-1"},
		{"v1 wrong period", "libvirt/cpu.cfs_period_us=100000", "libvirt/cpu.cfs_period_us=50000"},
	} {
		if !strings.Contains(v1Out, c.from) {
			t.Fatalf("%s: test data lacks %q", c.name, c.from)
		}
		if p := ParseLimits("n", strings.Replace(v1Out, c.from, c.to, 1)).CPUProblems(400, 150000); len(p) == 0 {
			t.Errorf("%s: not reported", c.name)
		}
	}
}

func TestLimits_Removed(t *testing.T) {
	gone := strings.NewReplacer(
		"global_quota   : 150000", "global_quota   : -1",
		"cpu_shares     : 400", "cpu_shares     : 100",
		"cpu.weight=400", "cpu.weight=100",
		"libvirt/cpu.max=150000 100000", "libvirt/cpu.max=max 100000",
		"inbound.average: 2000", "inbound.average: 0",
		"outbound.average: 2000", "outbound.average: 0",
		"class htb 1:1 root leaf 2: prio 0 rate 16Mbit ceil 16Mbit burst 1600b cburst 1600b \n", "",
	).Replace(v2Out)
	if p := ParseLimits("n", gone).RemovedProblems("16Mbit"); len(p) != 0 {
		t.Fatalf("a fully cleared domain reported %v", p)
	}
	for _, c := range []struct{ name, from, to string }{
		{"live quota left", "global_quota   : -1\niothread_period", "global_quota   : 150000\niothread_period"},
		{"weight left", "cpu_shares     : 100\n", "cpu_shares     : 400\n"},
		{"cgroup weight left", "cpu.weight=100", "cpu.weight=400"},
		{"cgroup quota left", "libvirt/cpu.max=max 100000", "libvirt/cpu.max=150000 100000"},
	} {
		if !strings.Contains(gone, c.from) {
			t.Fatalf("%s: test data lacks %q", c.name, c.from)
		}
		if p := ParseLimits("n", strings.Replace(gone, c.from, c.to, 1)).RemovedProblems("16Mbit"); len(p) == 0 {
			t.Errorf("%s: not reported", c.name)
		}
	}
}

// Newer libvirt reports a cleared CPU cap as its unlimited sentinel, not -1.
func TestLimits_RemovedAcceptsLibvirtUnlimitedSentinel(t *testing.T) {
	gone := strings.NewReplacer(
		"global_quota   : 150000", "global_quota   : 17592186044415",
		"cpu_shares     : 400", "cpu_shares     : 100",
		"cpu.weight=400", "cpu.weight=100",
		"libvirt/cpu.max=150000 100000", "libvirt/cpu.max=max 100000",
		"inbound.average: 2000", "inbound.average: 0",
		"outbound.average: 2000", "outbound.average: 0",
		"class htb 1:1 root leaf 2: prio 0 rate 16Mbit ceil 16Mbit burst 1600b cburst 1600b \n", "",
	).Replace(v2Out)
	if p := ParseLimits("n", gone).RemovedProblems("16Mbit"); len(p) != 0 {
		t.Fatalf("the unlimited sentinel was reported as a live cap: %v", p)
	}
	// A real quota is still a problem.
	still := strings.Replace(gone, "global_quota   : 17592186044415", "global_quota   : 150000", 1)
	if p := ParseLimits("n", still).RemovedProblems("16Mbit"); len(p) == 0 {
		t.Fatal("a live 150000 quota was not reported")
	}
}

// libvirt's behaviour on the tap after a clear was never observed. The cap is
// gone when EITHER domiftune reads 0 OR no class at the old rate remains; only
// both still showing the old limit is a failure.
func TestLimits_RemovedNICCap(t *testing.T) {
	gone := strings.NewReplacer(
		"global_quota   : 150000", "global_quota   : -1",
		"cpu_shares     : 400", "cpu_shares     : 100",
		"cpu.weight=400", "cpu.weight=100",
		"libvirt/cpu.max=150000 100000", "libvirt/cpu.max=max 100000",
	).Replace(v2Out) // CPU cleared; NIC still at 2000 and 16Mbit
	zeroed := strings.NewReplacer("inbound.average: 2000", "inbound.average: 0", "outbound.average: 2000", "outbound.average: 0").Replace(gone)
	noClass := strings.Replace(gone, "class htb 1:1 root leaf 2: prio 0 rate 16Mbit ceil 16Mbit burst 1600b cburst 1600b \n", "", 1)
	otherClass := strings.Replace(gone, "rate 16Mbit", "rate 1000Mbit", 1)

	if p := ParseLimits("n", gone).RemovedProblems("16Mbit"); len(p) == 0 {
		t.Error("a clear that was never applied (domiftune 2000 and the 16Mbit class) must be reported")
	}
	for name, out := range map[string]string{
		"domiftune zero, old class left (libvirt kept a root class)": zeroed,
		"class gone, domiftune stale":                                noClass,
		"class at a different rate":                                  otherClass,
	} {
		if p := ParseLimits("n", out).RemovedProblems("16Mbit"); len(p) != 0 {
			t.Errorf("%s: the old limit is not enforced, got %v", name, p)
		}
	}
}
