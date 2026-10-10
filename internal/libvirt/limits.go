package libvirt

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// The noisy-neighbour controls: a per-VM CPU cap and weight, and a per-NIC
// bandwidth cap. All three are libvirt tunables that can be changed on a
// running domain, so none of them needs a restart.

const (
	// CPUPeriodUS is the CFS enforcement period litevirt uses (100 ms, the
	// kernel default). Quota is expressed against it.
	CPUPeriodUS = 100000
	// minCPUQuotaUS is libvirt's floor for a vCPU quota (1000 microseconds).
	minCPUQuotaUS = 1000

	// CPUSharesMin / CPUSharesMax bound libvirt's <shares>.
	CPUSharesMin = 2
	CPUSharesMax = 262144

	// MinCPULimit is the smallest cap that survives division across vCPUs
	// without dropping under libvirt's quota floor. It is checked per VM by
	// ValidateCPULimit, which knows the vCPU count.
	MinCPULimit = 0.01
)

// CPUTuneQuota converts a total-cores cap into libvirt's period and PER-VCPU
// quota. libvirt's <quota> applies to each vCPU thread, while the cap an
// operator states (Proxmox cpulimit) is for the whole VM, so a 4-vCPU guest
// capped at 2 cores gets a quota of half a period per vCPU. A limit at or
// above the vCPU count caps nothing and renders as a full period per vCPU.
func CPUTuneQuota(limit float64, vcpus int) (period uint64, quota int64) {
	if vcpus < 1 {
		vcpus = 1
	}
	q := int64(math.Round(limit / float64(vcpus) * CPUPeriodUS))
	if q < minCPUQuotaUS {
		q = minCPUQuotaUS
	}
	if q > CPUPeriodUS {
		q = CPUPeriodUS
	}
	return CPUPeriodUS, q
}

// ValidateCPULimit reports whether limit is a usable cap for a guest with vcpus
// vCPUs: 0 (unlimited) or within [MinCPULimit-per-vCPU floor, vcpus].
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
	if limit/float64(vcpus)*CPUPeriodUS < minCPUQuotaUS {
		return fmt.Errorf("cpu limit %v is too small for %d vCPUs (the smallest allowed is %.2f cores per vCPU)", limit, vcpus, float64(minCPUQuotaUS)/CPUPeriodUS)
	}
	return nil
}

// ValidateCPUShares reports whether shares is 0 (default) or within libvirt's range.
func ValidateCPUShares(shares int) error {
	if shares == 0 {
		return nil
	}
	if shares < CPUSharesMin || shares > CPUSharesMax {
		return fmt.Errorf("cpu shares %d is outside %d..%d (0 restores the default)", shares, CPUSharesMin, CPUSharesMax)
	}
	return nil
}

// ValidateNICRate reports whether rate (MB/s) is 0 (unlimited) or a positive,
// finite rate that rounds to at least 1 KiB/s.
func ValidateNICRate(rate float64) error {
	if rate == 0 {
		return nil
	}
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 {
		return fmt.Errorf("nic rate %v must be 0 (unlimited) or a positive MB/s", rate)
	}
	if rateKiBps(rate) < 1 || rate > 1e6 {
		return fmt.Errorf("nic rate %v MB/s is outside the supported range (0.001 .. 1000000)", rate)
	}
	return nil
}

// rateKiBps converts MB/s (Proxmox's unit: 10^6 bytes) to libvirt's KiB/s.
func rateKiBps(rateMBps float64) uint64 {
	return uint64(math.Round(rateMBps * 1e6 / 1024))
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
	k := rateKiBps(rateMBps)
	return &ifaceBandwidth{Inbound: &ifaceRate{Average: k}, Outbound: &ifaceRate{Average: k}}
}

var (
	reCPUTuneLimitElems = regexp.MustCompile(`[ \t]*<(shares|period|quota)\b[^>]*>[^<]*</(shares|period|quota)>\n?`)
	reCPUTuneBlock      = regexp.MustCompile(`(?s)[ \t]*<cputune>.*?</cputune>\n?`)
)

// PatchInactiveCPUTune returns domainXML with the <shares>/<period>/<quota>
// children of <cputune> set from limit/shares/vcpus, every other node (vcpupin
// included) preserved. A zero limit and zero shares remove them. It keeps the
// in-place CPU resize of a stopped VM honest: the quota is per vCPU, so a vCPU
// count change must move it, and the patch exists precisely so a regeneration
// does not reshuffle libvirt-assigned device addresses.
func PatchInactiveCPUTune(domainXML string, limit float64, shares, vcpus int) (string, error) {
	var add strings.Builder
	if shares > 0 {
		fmt.Fprintf(&add, "    <shares>%d</shares>\n", shares)
	}
	if limit > 0 {
		period, quota := CPUTuneQuota(limit, vcpus)
		fmt.Fprintf(&add, "    <period>%d</period>\n    <quota>%d</quota>\n", period, quota)
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
// domain. limit 0 removes the cap; shares 0 leaves the weight untouched.
// vcpus is the domain's CURRENT vCPU count, which the per-vCPU quota is
// derived from — call again after a vCPU hot-add.
func (c *Client) SetCPUTune(name string, limit float64, shares, vcpus int) error {
	if err := ValidateCPULimit(limit, vcpus); err != nil {
		return err
	}
	if err := ValidateCPUShares(shares); err != nil {
		return err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	var params []golibvirt.TypedParam
	if limit > 0 {
		period, quota := CPUTuneQuota(limit, vcpus)
		params = append(params,
			golibvirt.TypedParam{Field: "vcpu_period", Value: *golibvirt.NewTypedParamValueUllong(period)},
			golibvirt.TypedParam{Field: "vcpu_quota", Value: *golibvirt.NewTypedParamValueLlong(quota)})
	} else {
		// Unlimited: a negative quota is libvirt's "no limit".
		params = append(params,
			golibvirt.TypedParam{Field: "vcpu_period", Value: *golibvirt.NewTypedParamValueUllong(CPUPeriodUS)},
			golibvirt.TypedParam{Field: "vcpu_quota", Value: *golibvirt.NewTypedParamValueLlong(-1)})
	}
	if shares > 0 {
		params = append(params, golibvirt.TypedParam{Field: "cpu_shares", Value: *golibvirt.NewTypedParamValueUllong(uint64(shares))})
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
	k := rateKiBps(rateMBps) // 0 clears the limit
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
			k := rateKiBps(rateMBps)
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
