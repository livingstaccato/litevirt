package libvirt

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// The noisy-neighbour controls: a per-VM CPU cap and weight, and a per-NIC
// bandwidth cap. All three are libvirt tunables that can be changed on a
// running domain, so none of them needs a restart.

const (
	// CPUPeriodUS is the CFS enforcement period litevirt uses (100 ms, the
	// kernel default). The cap is expressed against it.
	CPUPeriodUS = 100000
	// minCPUQuotaUS is libvirt's floor for a quota (1000 microseconds).
	minCPUQuotaUS = 1000

	// CPUWeightMin / CPUWeightMax bound cpu-shares: Proxmox's cpuunits, which is
	// the cgroup v2 cpu.weight. libvirt writes <shares> straight into cpu.weight
	// on a unified-hierarchy host, and the kernel refuses anything outside this
	// range when the domain starts or is tuned.
	CPUWeightMin = 1
	CPUWeightMax = 10000

	// MinCPULimit is the smallest cap libvirt's quota floor allows.
	MinCPULimit = 0.01
)

// cgroupControllersFile exists only on a cgroup v2 (unified) host. A variable
// so a test can point it elsewhere.
var cgroupControllersFile = "/sys/fs/cgroup/cgroup.controllers"

// DefaultCPUWeight is the weight of an unconfigured VM in the USER'S scale
// (Proxmox cpuunits, cgroup v2 cpu.weight): 100, on every host. It is what
// clearing cpu-shares writes back; HostCPUShares turns it into the number this
// host's cgroup version expects.
func DefaultCPUWeight() int { return 100 }

// cgroupV2 reports whether this host runs the unified cgroup hierarchy.
func cgroupV2() bool {
	_, err := os.Stat(cgroupControllersFile)
	return err == nil
}

// scaleWeightV1 maps a v2-scale weight onto cgroup v1's cpu.shares, whose
// default is 1024 where v2's cpu.weight default is 100: weight * 1024/100,
// never below v1's floor of 2.
func scaleWeightV1(weight float64) int {
	v := int(math.Round(weight * 1024 / 100))
	if v < 2 {
		v = 2
	}
	return v
}

// HostCPUShares converts the user's weight (what the spec stores, 1..10000,
// 0 = unset) into the value libvirt's <shares> must carry on THIS host:
// unchanged on cgroup v2, scaled by 1024/100 on cgroup v1. It is applied where
// the host's XML or scheduler parameters are written, never to the stored
// spec, so a cluster mixing v1 and v2 hosts renders each host's own value.
func HostCPUShares(weight int) int { return HostCPUSharesFor(weight, cgroupV2()) }

// HostCPUSharesFor is HostCPUShares for a host whose cgroup version is known:
// a migration renders the destination's definition for the TARGET's scale.
func HostCPUSharesFor(weight int, v2 bool) int {
	if weight <= 0 {
		return 0
	}
	if v2 {
		return weight
	}
	return scaleWeightV1(float64(weight))
}

// CgroupMode names this host's cgroup hierarchy, "v2" or "v1", for a peer that
// must render a definition for it.
func CgroupMode() string {
	if cgroupV2() {
		return "v2"
	}
	return "v1"
}

var reSharesElem = regexp.MustCompile(`<shares>[0-9]+</shares>`)

// RetargetCPUShares returns domainXML with its <shares> set to the host value
// of weight on a host of the given cgroup version, every other node untouched.
// A definition without <shares> is returned unchanged.
func RetargetCPUShares(domainXML string, weight int, v2 bool) string {
	if weight <= 0 {
		return domainXML
	}
	return reSharesElem.ReplaceAllString(domainXML, fmt.Sprintf("<shares>%d</shares>", HostCPUSharesFor(weight, v2)))
}

// MigrationShareXML builds the destination and persistent definitions of a
// migration of a VM whose cpu-shares weight is set: the same definitions with
// <shares> on the target's scale. ok is false when nothing needs rewriting:
// no weight, a target whose cgroup version is unknown (an older build), or the
// same version as the source (srcV2), where the number is already right.
func MigrationShareXML(live, persist string, weight int, targetMode string, srcV2 bool) (dest, persistOut string, ok bool) {
	if weight <= 0 || (targetMode != "v1" && targetMode != "v2") || (targetMode == "v2") == srcV2 {
		return "", "", false
	}
	v2 := targetMode == "v2"
	return RetargetCPUShares(live, weight, v2), RetargetCPUShares(persist, weight, v2), true
}

// GlobalQuota converts a total-cores cap into libvirt's global period and
// quota, which cap the WHOLE domain (its cgroup's cpu.max) the way Proxmox's
// cpulimit does: a guest running one busy thread can use a full core of a
// 2.5-core cap. The per-vCPU <quota> is deliberately not used — it would hold a
// single-threaded guest to limit/vcpus. The quota may exceed one period: that is
// a cap above one core.
func GlobalQuota(limit float64) (period uint64, quota int64) {
	q := int64(math.Round(limit * CPUPeriodUS))
	if q < minCPUQuotaUS {
		q = minCPUQuotaUS
	}
	return CPUPeriodUS, q
}

// ValidateCPULimit reports whether limit is a usable cap for a guest with vcpus
// vCPUs: 0 (unlimited) or within [MinCPULimit, vcpus].
func ValidateCPULimit(limit float64, vcpus int) error {
	if limit == 0 {
		return nil
	}
	if math.IsNaN(limit) || math.IsInf(limit, 0) || limit < 0 {
		return fmt.Errorf("cpu limit %v must be 0 (unlimited) or a positive number of cores", limit)
	}
	if vcpus < 1 {
		vcpus = 1
	}
	if limit > float64(vcpus) {
		return fmt.Errorf("cpu limit %v exceeds the VM's %d vCPUs — it could never be reached; use 0 for unlimited or a value up to %d", limit, vcpus, vcpus)
	}
	if limit < MinCPULimit {
		return fmt.Errorf("cpu limit %v is below the smallest cap libvirt allows (%.2f cores)", limit, MinCPULimit)
	}
	return nil
}

// ValidateCPUShares reports whether shares is 0 (default) or a cgroup v2
// cpu.weight, 1..10000.
func ValidateCPUShares(shares int) error {
	if shares == 0 {
		return nil
	}
	if shares < CPUWeightMin || shares > CPUWeightMax {
		return fmt.Errorf("cpu shares %d is outside %d..%d (the cgroup weight; 0 restores the default)", shares, CPUWeightMin, CPUWeightMax)
	}
	return nil
}

// ValidateNICRate reports whether rate (MB/s) is 0 (unlimited) or a positive,
// finite rate that rounds to at least 1 KB/s.
func ValidateNICRate(rate float64) error {
	if rate == 0 {
		return nil
	}
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 {
		return fmt.Errorf("nic rate %v must be 0 (unlimited) or a positive MB/s", rate)
	}
	if rateKBps(rate) < 1 || rate > 1e6 {
		return fmt.Errorf("nic rate %v MB/s is outside the supported range (0.001 .. 1000000)", rate)
	}
	return nil
}

// rateKBps converts MB/s (Proxmox's unit: 10^6 bytes) to libvirt's average,
// which is kilobytes/s: libvirt hands it to tc as "<n>kbps", and iproute2
// reads that as 1000 bytes per second, so the factor is 1000, not 1024.
func rateKBps(rateMBps float64) uint64 {
	return uint64(math.Round(rateMBps * 1000))
}

type ifaceBandwidth struct {
	Inbound  *ifaceRate `xml:"inbound,omitempty"`
	Outbound *ifaceRate `xml:"outbound,omitempty"`
}

type ifaceRate struct {
	Average uint64 `xml:"average,attr"`
}

// bandwidthElement renders a symmetric cap, or nil for 0 (unlimited).
func bandwidthElement(rateMBps float64) *ifaceBandwidth {
	if rateMBps <= 0 {
		return nil
	}
	k := rateKBps(rateMBps)
	return &ifaceBandwidth{Inbound: &ifaceRate{Average: k}, Outbound: &ifaceRate{Average: k}}
}

var (
	reCPUTuneLimitElems = regexp.MustCompile(`[ \t]*<(shares|period|quota|global_period|global_quota)\b[^>]*>[^<]*</(shares|period|quota|global_period|global_quota)>\n?`)
	reCPUTuneBlock      = regexp.MustCompile(`(?s)[ \t]*<cputune>.*?</cputune>\n?`)
)

// PatchInactiveCPUTune returns domainXML with the weight and the whole-domain
// cap of <cputune> set from shares/limit, every other node (vcpupin included)
// preserved. shares is the user's weight; the host's value is rendered. A zero limit and zero shares remove them (a stale per-vCPU
// period/quota goes too). It exists so a stopped VM's limits change is an
// in-place edit that keeps libvirt-assigned device addresses.
func PatchInactiveCPUTune(domainXML string, limit float64, shares int) (string, error) {
	var add strings.Builder
	if shares > 0 {
		fmt.Fprintf(&add, "    <shares>%d</shares>\n", HostCPUShares(shares))
	}
	if limit > 0 {
		period, quota := GlobalQuota(limit)
		fmt.Fprintf(&add, "    <global_period>%d</global_period>\n    <global_quota>%d</global_quota>\n", period, quota)
	}
	loc := reCPUTuneBlock.FindStringIndex(domainXML)
	if loc == nil {
		if add.Len() == 0 {
			return domainXML, nil
		}
		at := reVCPUClose.FindStringIndex(domainXML)
		if at == nil {
			return "", fmt.Errorf("PatchInactiveCPUTune: no <cputune> and no </vcpu> to insert after")
		}
		return domainXML[:at[1]] + "\n  <cputune>\n" + add.String() + "  </cputune>" + domainXML[at[1]:], nil
	}
	block := domainXML[loc[0]:loc[1]]
	stripped := reCPUTuneLimitElems.ReplaceAllString(block, "")
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.Replace(stripped, "<cputune>", "", 1)), "</cputune>"))
	if inner == "" && add.Len() == 0 {
		return domainXML[:loc[0]] + domainXML[loc[1]:], nil
	}
	idx := strings.LastIndex(stripped, "</cputune>")
	if idx < 0 {
		return "", fmt.Errorf("PatchInactiveCPUTune: malformed <cputune>")
	}
	rebuilt := stripped[:idx] + add.String() + "  " + stripped[idx:]
	return domainXML[:loc[0]] + rebuilt + domainXML[loc[1]:], nil
}

// SetCPUTune applies a CPU cap and weight to a domain: the persistent config
// first (so a refused write surfaces before any live change), then the running
// domain. limit 0 removes the cap; shares 0 leaves the weight untouched. The
// cap is the whole domain's (global_period/global_quota), so nothing about it
// depends on the vCPU count.
func (c *Client) SetCPUTune(name string, limit float64, shares int) error {
	if err := ValidateCPUShares(shares); err != nil {
		return err
	}
	if limit < 0 || math.IsNaN(limit) || math.IsInf(limit, 0) {
		return fmt.Errorf("cpu limit %v must be 0 (unlimited) or a positive number of cores", limit)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	var params []golibvirt.TypedParam
	if limit > 0 {
		period, quota := GlobalQuota(limit)
		params = append(params,
			golibvirt.TypedParam{Field: "global_period", Value: *golibvirt.NewTypedParamValueUllong(period)},
			golibvirt.TypedParam{Field: "global_quota", Value: *golibvirt.NewTypedParamValueLlong(quota)})
	} else {
		// Unlimited: a negative quota is libvirt's "no limit".
		params = append(params,
			golibvirt.TypedParam{Field: "global_period", Value: *golibvirt.NewTypedParamValueUllong(CPUPeriodUS)},
			golibvirt.TypedParam{Field: "global_quota", Value: *golibvirt.NewTypedParamValueLlong(-1)})
	}
	if shares > 0 {
		params = append(params, golibvirt.TypedParam{Field: "cpu_shares", Value: *golibvirt.NewTypedParamValueUllong(uint64(HostCPUShares(shares)))})
	}
	if err := c.virt.DomainSetSchedulerParametersFlags(dom, params, uint32(golibvirt.DomainAffectConfig)); err != nil {
		return fmt.Errorf("set cpu tune %s (config): %w", name, err)
	}
	if c.domainRunning(dom) {
		if err := c.virt.DomainSetSchedulerParametersFlags(dom, params, uint32(golibvirt.DomainAffectLive)); err != nil {
			return fmt.Errorf("set cpu tune %s (live): %w", name, err)
		}
	}
	return nil
}

// SetNICRate sets (rateMBps > 0) or clears (0) the bandwidth cap of the NIC with
// the given MAC, persistent config first and then the running domain.
func (c *Client) SetNICRate(name, mac string, rateMBps float64) error {
	if err := ValidateNICRate(rateMBps); err != nil {
		return err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	k := rateKBps(rateMBps) // 0 clears the limit
	mk := func(f string) golibvirt.TypedParam {
		return golibvirt.TypedParam{Field: f, Value: *golibvirt.NewTypedParamValueUint(uint32(k))}
	}
	params := []golibvirt.TypedParam{mk("inbound.average"), mk("outbound.average")}
	if err := c.virt.DomainSetInterfaceParameters(dom, mac, params, uint32(golibvirt.DomainAffectConfig)); err != nil {
		return fmt.Errorf("set nic rate %s/%s (config): %w", name, mac, err)
	}
	if c.domainRunning(dom) {
		if err := c.virt.DomainSetInterfaceParameters(dom, mac, params, uint32(golibvirt.DomainAffectLive)); err != nil {
			return fmt.Errorf("set nic rate %s/%s (live): %w", name, mac, err)
		}
	}
	return nil
}

var reBandwidthBlock = regexp.MustCompile(`(?s)[ \t]*<bandwidth\b.*?</bandwidth>\n?|[ \t]*<bandwidth\s*/>\n?`)

// PatchInterfaceBandwidth returns domainXML with the <bandwidth> of the
// interface carrying mac set to a symmetric rateMBps cap (0 removes it), every
// other node preserved. ok=false when no interface has that MAC. A cap on the
// interface's own <bandwidth> is the only thing touched, so a peak/burst an
// operator added by hand outside litevirt is replaced, not merged.
func PatchInterfaceBandwidth(domainXML, mac string, rateMBps float64) (string, bool) {
	want := strings.ToLower(strings.TrimSpace(mac))
	for _, e := range interfaceElemRE.FindAllString(domainXML, -1) {
		m := macAddrRE.FindStringSubmatch(e)
		if m == nil || strings.ToLower(m[1]) != want {
			continue
		}
		ne := reBandwidthBlock.ReplaceAllString(e, "")
		if rateMBps > 0 {
			k := rateKBps(rateMBps)
			if i := strings.LastIndex(ne, "</interface>"); i >= 0 {
				ls := strings.LastIndex(ne[:i], "\n") + 1 // start of the closing tag's line
				ind := ne[ls:i]
				bw := fmt.Sprintf("%s  <bandwidth>\n%s    <inbound average='%d'/>\n%s    <outbound average='%d'/>\n%s  </bandwidth>\n",
					ind, ind, k, ind, k, ind)
				ne = ne[:ls] + bw + ne[ls:]
			}
		}
		return strings.Replace(domainXML, e, ne, 1), true
	}
	return domainXML, false
}
