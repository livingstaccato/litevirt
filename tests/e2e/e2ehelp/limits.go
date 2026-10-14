package e2ehelp

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Limits is everything the hypervisor, the cgroup and tc say about one domain
// on one host, parsed from the script tests/e2e's readLimits runs there.
type Limits struct {
	Host   string
	V2     bool
	Sched  map[string]string // virsh schedinfo, live
	SchedC map[string]string // virsh schedinfo --config
	IfLive map[string]string // virsh domiftune, live
	IfCfg  map[string]string // virsh domiftune --config
	IOTune map[string]string // virsh blkdeviotune vda
	TC     []string          // htb class rates on the domain's tap
	Tap    string
	Cgroup map[string]string // control files relative to the domain's cgroup scope
	CfgXML string            // virsh dumpxml --inactive
}

// ParseLimits parses the marker-separated output of the readLimits script.
func ParseLimits(host, out string) Limits {
	sec := Sections(out)
	l := Limits{
		Host:   host,
		V2:     strings.TrimSpace(sec["v2"]) == "yes",
		Sched:  KV(sec["sched"]),
		SchedC: KV(sec["schedcfg"]),
		IfLive: KV(sec["iflive"]),
		IfCfg:  KV(sec["ifcfg"]),
		IOTune: KV(sec["iotune"]),
		TC:     HTBRates(sec["tc"]),
		Tap:    strings.TrimSpace(sec["tap"]),
		Cgroup: map[string]string{},
		CfgXML: sec["cfgxml"],
	}
	for _, line := range strings.Split(sec["cgroup"], "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			l.Cgroup[k] = strings.TrimSpace(v)
		}
	}
	return l
}

// HostShares is the <shares> a weight renders as on a host of that cgroup
// version: unchanged on v2, scaled by 1024/100 (floor 2) on v1.
func HostShares(v2 bool, weight int) int {
	if v2 {
		return weight
	}
	v := int(math.Round(float64(weight) * 1024 / 100))
	if v < 2 {
		v = 2
	}
	return v
}

func (l Limits) weightKey() string {
	if l.V2 {
		return "cpu.weight"
	}
	return "cpu.shares"
}

// CPUProblems lists where the weight or the whole-domain cap (quotaUS per
// 100000us period) is not what libvirt (live and persistent) and the guest's
// cgroup should show.
func (l Limits) CPUProblems(weight int, quotaUS int64) []string {
	var p []string
	shares := strconv.Itoa(HostShares(l.V2, weight))
	for name, got := range map[string]map[string]string{"live": l.Sched, "config": l.SchedC} {
		if got["cpu_shares"] != shares || got["global_period"] != "100000" || got["global_quota"] != strconv.FormatInt(quotaUS, 10) {
			p = append(p, fmt.Sprintf("virsh schedinfo (%s) on %s = cpu_shares %q global_period %q global_quota %q, want %s 100000 %d",
				name, l.Host, got["cpu_shares"], got["global_period"], got["global_quota"], shares, quotaUS))
		}
	}
	// cgroup v2 takes the weight unconverted in cpu.weight; v1 reads cpu.shares
	// (the weight scaled by 1024/100).
	if got := l.Cgroup[l.weightKey()]; got != shares {
		p = append(p, fmt.Sprintf("cgroup %s on %s = %q, want %s (cgroup files: %v)", l.weightKey(), l.Host, got, shares, l.Cgroup))
	}
	q, per, ok := CPUQuota(l.Cgroup)
	switch {
	case !ok:
		p = append(p, fmt.Sprintf("no cgroup level on %s carries a CPU quota, want %d: the cap is not enforced (cgroup files: %v)", l.Host, quotaUS, l.Cgroup))
	case q != quotaUS || per != 100000:
		p = append(p, fmt.Sprintf("cgroup CPU quota on %s = %d per %d, want %d per 100000", l.Host, q, per, quotaUS))
	}
	return p
}

// DiskProblems lists where the vda throttle libvirt hands qemu differs.
func (l Limits) DiskProblems(readIops, writeBytes string) []string {
	if l.IOTune["read_iops_sec"] != readIops || l.IOTune["write_bytes_sec"] != writeBytes {
		return []string{fmt.Sprintf("virsh blkdeviotune vda on %s = read_iops_sec %q write_bytes_sec %q, want %s %s (all: %v)",
			l.Host, l.IOTune["read_iops_sec"], l.IOTune["write_bytes_sec"], readIops, writeBytes, l.IOTune)}
	}
	return nil
}

// NICProblems lists where the NIC cap differs: in libvirt live and persistent,
// and as the htb class on the tap. kb is libvirt's unit (1000 bytes/s), mbit
// the tc rate (4 MB/s is 4000 and 32Mbit). An empty mbit means the cap must be
// gone: no class on the tap at all.
func (l Limits) NICProblems(kb, mbit string) []string {
	var p []string
	for name, got := range map[string]map[string]string{"live": l.IfLive, "config": l.IfCfg} {
		if got["inbound.average"] != kb || got["outbound.average"] != kb {
			p = append(p, fmt.Sprintf("virsh domiftune (%s) on %s = in %q out %q, want %s/%s",
				name, l.Host, got["inbound.average"], got["outbound.average"], kb, kb))
		}
	}
	if !strings.Contains(l.CfgXML, "<inbound average='"+kb+"'") {
		p = append(p, fmt.Sprintf("the persistent definition on %s lacks <inbound average='%s'>", l.Host, kb))
	}
	if mbit == "" {
		if len(l.TC) != 0 {
			p = append(p, fmt.Sprintf("tap %s on %s still has htb classes %v", l.Tap, l.Host, l.TC))
		}
		return p
	}
	if l.Tap == "" {
		return append(p, fmt.Sprintf("no tap device found for the domain on %s", l.Host))
	}
	for _, r := range l.TC {
		if r == mbit {
			return p
		}
	}
	return append(p, fmt.Sprintf("tc class show dev %s on %s has htb rates %v, want %s: the tap is not shaped", l.Tap, l.Host, l.TC, mbit))
}

// libvirtUnlimitedQuota is what newer libvirt reports for global_quota once a
// CPU cap is cleared: its "unlimited" sentinel (2^44-1 us), where older builds
// report -1 or 0. All three mean no cap is in force.
const libvirtUnlimitedQuota = "17592186044415"

// RemovedProblems lists where a cleared cap, weight and NIC rate are still in
// effect. Clearing the weight writes the host's DEFAULT (100) back, never a
// leftover or a hard-coded number.
//
// The NIC cap counts as cleared when EITHER libvirt reports 0/unset inbound and
// outbound OR tc shows no htb class at oldMbit (the rate of the cap that was
// removed). What libvirt leaves on the tap after a clear (no qdisc, or a root
// htb with a default class) is its own behaviour and was never observed, so
// only a cap that is still enforced is a problem: libvirt still reporting a
// rate AND the old class still shaping the tap.
func (l Limits) RemovedProblems(oldMbit string) []string {
	var p []string
	if q := l.Sched["global_quota"]; q != "-1" && q != "0" && q != libvirtUnlimitedQuota {
		p = append(p, fmt.Sprintf("cap not removed: global_quota = %q", q))
	}
	want := strconv.Itoa(HostShares(l.V2, 100))
	if l.Sched["cpu_shares"] != want {
		p = append(p, fmt.Sprintf("clearing cpu-shares left cpu_shares = %q, want this host's default %s", l.Sched["cpu_shares"], want))
	}
	if got := l.Cgroup[l.weightKey()]; got != want {
		p = append(p, fmt.Sprintf("clearing cpu-shares left cgroup %s = %q, want %s", l.weightKey(), got, want))
	}
	if _, _, ok := CPUQuota(l.Cgroup); ok {
		p = append(p, fmt.Sprintf("the cgroup still carries a CPU quota: %v", l.Cgroup))
	}
	in, out := l.IfLive["inbound.average"], l.IfLive["outbound.average"]
	reportedGone := (in == "0" || in == "") && (out == "0" || out == "")
	classLeft := false
	for _, r := range l.TC {
		classLeft = classLeft || r == oldMbit
	}
	if !reportedGone && classLeft {
		p = append(p, fmt.Sprintf("NIC cap still enforced: domiftune in %q out %q and tap %s still has an htb class at %s", in, out, l.Tap, oldMbit))
	}
	return p
}
