package libvirt

import (
	"encoding/xml"
	"fmt"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// CPUCompare is the verdict of comparing a guest CPU requirement against a
// host. It mirrors virConnectCompareHypervisorCPU, minus the error code (returned as a
// Go error instead).
type CPUCompare int

const (
	// CPUCompareIncompatible: the host cannot run a guest needing this CPU.
	CPUCompareIncompatible CPUCompare = 0
	// CPUCompareIdentical: the host CPU matches the requirement exactly.
	CPUCompareIdentical CPUCompare = 1
	// CPUCompareSuperset: the host is richer than required — the guest runs.
	CPUCompareSuperset CPUCompare = 2
)

func (c CPUCompare) String() string {
	switch c {
	case CPUCompareIncompatible:
		return "incompatible"
	case CPUCompareIdentical:
		return "identical"
	case CPUCompareSuperset:
		return "superset"
	default:
		return fmt.Sprintf("unknown(%d)", int(c))
	}
}

// Runnable reports whether a guest requiring the compared CPU can run here.
func (c CPUCompare) Runnable() bool {
	return c == CPUCompareIdentical || c == CPUCompareSuperset
}

// CompareCPU asks the LOCAL hypervisor whether it can satisfy the guest CPU
// described by cpuXML (a standalone <cpu>…</cpu> element) on the given machine
// type ("" = libvirt's default). This is the destination side of a migration
// CPU preflight.
//
// It uses virConnectCompareHypervisorCPU, not the legacy virConnectCompareCPU.
// The legacy call compares against the host's raw capabilities CPU, which omits
// features QEMU gives guests regardless (spec-ctrl, arch-capabilities on AMD),
// so it calls a running host-model guest incompatible with the very host it
// runs on. The hypervisor call compares against what this host's default
// emulator (KVM) can actually provide for that machine type — the hypervisor a
// migrated guest lands on. Emulator, arch and virttype are left to libvirt.
func (c *Client) CompareCPU(cpuXML, machine string) (CPUCompare, error) {
	return compareCPU(c.virt, cpuXML, machine)
}

// HostModelCPUFeatures returns the features this host's hypervisor lists for
// mode='host-model' in its domain capabilities, for the given machine type
// ("" = libvirt's default), mapped to whether the host-model PROVIDES each one
// (a feature it lists only as disabled maps to false). See CreditCPURequirement.
func (c *Client) HostModelCPUFeatures(machine string) (map[string]bool, error) {
	return hostModelCPUFeatures(c.virt, machine)
}

// cpuCompareAPI is the slice of go-libvirt the CPU compare uses. The legacy
// call is named too, though nothing here calls it, so a test fake can answer
// the two differently and prove which one a verdict came from.
type cpuCompareAPI interface {
	ConnectCompareCPU(XML string, Flags golibvirt.ConnectCompareCPUFlags) (int32, error)
	ConnectCompareHypervisorCPU(Emulator, Arch, Machine, Virttype golibvirt.OptString, XMLCPU string, Flags uint32) (int32, error)
	ConnectGetDomainCapabilities(Emulatorbin, Arch, Machine, Virttype golibvirt.OptString, Flags golibvirt.ConnectGetDomainCapabilitiesFlags) (string, error)
}

// optString is libvirt's optional string: absent for "", so libvirt applies
// its default.
func optString(v string) golibvirt.OptString {
	if v == "" {
		return nil
	}
	return golibvirt.OptString{v}
}

func compareCPU(api cpuCompareAPI, cpuXML, machine string) (CPUCompare, error) {
	if strings.TrimSpace(cpuXML) == "" {
		return CPUCompareIncompatible, fmt.Errorf("compare cpu: empty cpu xml")
	}
	res, err := api.ConnectCompareHypervisorCPU(nil, nil, optString(machine), nil, cpuXML, 0)
	if err != nil {
		return CPUCompareIncompatible, fmt.Errorf("compare cpu: %w", err)
	}
	if golibvirt.CPUCompareResult(res) == golibvirt.CPUCompareError {
		return CPUCompareIncompatible, fmt.Errorf("compare cpu: hypervisor returned an error result")
	}
	return CPUCompare(res), nil
}

func hostModelCPUFeatures(api cpuCompareAPI, machine string) (map[string]bool, error) {
	caps, err := api.ConnectGetDomainCapabilities(nil, nil, optString(machine), nil, 0)
	if err != nil {
		return nil, fmt.Errorf("domain capabilities: %w", err)
	}
	return hostModelFeaturesFromDomCaps(caps)
}

// hostModelFeaturesFromDomCaps reads <domainCapabilities><cpu><mode
// name='host-model'> feature list. A host-model that is absent or unsupported
// is an error: with nothing to credit, the caller keeps the requirement as is.
func hostModelFeaturesFromDomCaps(caps string) (map[string]bool, error) {
	var doc struct {
		XMLName xml.Name `xml:"domainCapabilities"`
		CPU     struct {
			Modes []struct {
				Name      string `xml:"name,attr"`
				Supported string `xml:"supported,attr"`
				Model     string `xml:"model"`
				Features  []struct {
					Policy string `xml:"policy,attr"`
					Name   string `xml:"name,attr"`
				} `xml:"feature"`
			} `xml:"mode"`
		} `xml:"cpu"`
	}
	if err := xml.Unmarshal([]byte(caps), &doc); err != nil {
		return nil, fmt.Errorf("parse domain capabilities: %w", err)
	}
	for _, m := range doc.CPU.Modes {
		if m.Name != CPUModeHostModel {
			continue
		}
		if m.Supported != "yes" || strings.TrimSpace(m.Model) == "" {
			return nil, fmt.Errorf("domain capabilities: host-model is not supported here")
		}
		out := make(map[string]bool, len(m.Features))
		for _, f := range m.Features {
			out[f.Name] = f.Policy != "disable" && f.Policy != "forbid"
		}
		return out, nil
	}
	return nil, fmt.Errorf("domain capabilities carry no host-model cpu mode")
}

// CreditCPURequirement returns a running host-model guest's live <cpu> with
// every <feature policy='require'> removed that the SOURCE's own host-model
// (hostModel, from HostModelCPUFeatures) does not provide, plus the names it
// removed. Everything else passes through byte for byte.
//
// libvirt expands a running host-model guest with features its hypervisor
// compare does not credit the host with — on the lab's EPYC-Milan, topoext: the
// live CPU requires it, domcapabilities' host-model does not list it, and
// virConnectCompareHypervisorCPU rejects the guest on its own host. A verbatim
// requirement therefore cannot tell a good destination from a bad one there.
// Stripping only what the source does not credit keeps every feature the
// comparison can actually judge.
//
// It strips; it never adds. A guest that booted on an older host carries a
// narrower expansion than this host's host-model, and comparing the host-model
// wholesale would refuse moving it back to a host like the one it booted on.
func CreditCPURequirement(cpuXML string, hostModel map[string]bool) (string, []string) {
	dec := xml.NewDecoder(strings.NewReader(cpuXML))
	type span struct{ start, end int64 }
	var cuts []span
	var dropped []string
	var prevEnd int64 // offset just past the previous token
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch se := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && se.Name.Local == "feature" {
				var policy, name string
				for _, a := range se.Attr {
					switch a.Name.Local {
					case "policy":
						policy = a.Value
					case "name":
						name = a.Value
					}
				}
				start := prevEnd
				if serr := dec.Skip(); serr != nil {
					return cpuXML, nil
				}
				depth--
				if policy == "require" && name != "" && !hostModel[name] {
					cuts = append(cuts, span{start, dec.InputOffset()})
					dropped = append(dropped, name)
				}
			}
		case xml.EndElement:
			depth--
		}
		prevEnd = dec.InputOffset()
	}
	if len(cuts) == 0 {
		return cpuXML, nil
	}
	var b strings.Builder
	var at int64
	for _, c := range cuts {
		// prevEnd for a feature is just past the whitespace before it, which the
		// decoder returned as CharData; take that indentation out with it.
		start := c.start
		for start > at && strings.ContainsRune(" \t\r\n", rune(cpuXML[start-1])) {
			start--
		}
		b.WriteString(cpuXML[at:start])
		at = c.end
	}
	b.WriteString(cpuXML[at:])
	return b.String(), dropped
}

// DomainMachineType returns the machine attribute of a domain XML's
// <os><type> ("" when it has none) — the machine type a migrated guest keeps.
func DomainMachineType(domainXML string) string {
	osEl, ok := extractRootChild(domainXML, "os")
	if !ok {
		return ""
	}
	var probe struct {
		Type struct {
			Machine string `xml:"machine,attr"`
		} `xml:"type"`
	}
	if err := xml.Unmarshal([]byte(osEl), &probe); err != nil {
		return ""
	}
	return probe.Type.Machine
}

// HostCPUXML returns this host's own CPU as a comparable <cpu> element, read
// from the hypervisor capabilities. It is what a host-passthrough guest
// effectively requires, so it is the requirement a migration of such a guest
// must compare against the destination.
func (c *Client) HostCPUXML() (string, error) {
	caps, err := c.virt.ConnectGetCapabilities()
	if err != nil {
		return "", fmt.Errorf("host capabilities: %w", err)
	}
	cpu, err := hostCPUFromCapabilities(caps)
	if err != nil {
		return "", err
	}
	return cpu, nil
}

// extractRootChild returns the named element VERBATIM when it appears as a
// DIRECT child of doc's root element, plus whether it was found.
//
// The depth scoping is the point: a plain document-wide search for "cpu" in a
// domain XML could match something nested under <metadata> or a future schema
// addition, and patching the wrong element would rewrite the guest's CPU from a
// node that has nothing to do with it.
func extractRootChild(doc, name string) (string, bool) {
	dec := xml.NewDecoder(strings.NewReader(doc))
	var startOff int64
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch se := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && se.Name.Local == name {
				if serr := dec.Skip(); serr != nil {
					return "", false
				}
				return strings.TrimSpace(doc[startOff:dec.InputOffset()]), true
			}
			if depth >= 2 {
				// Not the element we want: skip its whole subtree so nothing
				// inside it can be mistaken for a root child.
				if serr := dec.Skip(); serr != nil {
					return "", false
				}
				depth--
			}
		case xml.EndElement:
			depth--
		}
		startOff = dec.InputOffset()
	}
}

// extractElement returns the named element from doc VERBATIM — attributes,
// children and all — plus whether it was found.
//
// Verbatim matters: libvirt's CPU compare parses a <cpu> element in one of two
// native forms, the host form from capabilities (which carries <arch> and no
// mode/match) or the guest form from a domain (which carries mode/match and no
// <arch>). Rebuilding the element by hand produces a hybrid that is neither, so
// the bytes are passed through untouched.
//
// Byte offsets are exact because the decoder accounts for every byte: the
// offset after the previous token is the offset at which this token begins.
func extractElement(doc, name string) (string, bool) {
	dec := xml.NewDecoder(strings.NewReader(doc))
	var startOff int64
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == name {
			if err := dec.Skip(); err != nil {
				return "", false
			}
			return strings.TrimSpace(doc[startOff:dec.InputOffset()]), true
		}
		startOff = dec.InputOffset()
	}
}

// hostCPUFromCapabilities lifts <capabilities><host><cpu> out verbatim, as the
// host-form <cpu> element libvirt's CPU compare accepts — the requirement a
// host-passthrough guest carries.
func hostCPUFromCapabilities(caps string) (string, error) {
	// Scope to <host> first: <guest> blocks further down also contain CPU
	// material, and the host's own CPU is the one a passthrough guest requires.
	host, ok := extractElement(caps, "host")
	if !ok {
		return "", fmt.Errorf("host capabilities carry no <host> element")
	}
	cpu, ok := extractElement(host, "cpu")
	if !ok {
		return "", fmt.Errorf("host capabilities carry no <host><cpu> element")
	}
	return cpu, nil
}

// DomainCPURequirement extracts, from a domain XML, the guest CPU requirement
// to compare against a migration destination — and reports whether one could be
// derived at all.
//
// For a RUNNING domain libvirt has already expanded mode='host-model' into a
// concrete model plus feature list in the live XML, so the live element IS the
// exact requirement and is returned verbatim. A domain with no <cpu> element
// (the qemu64 case) or an unexpanded mode='host-passthrough' yields ok=false:
// neither names a model, so neither is a comparable requirement, and the caller
// resolves passthrough via the source's HostCPUXML instead.
func DomainCPURequirement(domainXML string) (cpuXML string, ok bool) {
	cpu, found := extractElement(domainXML, "cpu")
	if !found {
		return "", false
	}
	var probe struct {
		Model string `xml:"model"`
	}
	if err := xml.Unmarshal([]byte(cpu), &probe); err != nil {
		return "", false
	}
	if strings.TrimSpace(probe.Model) == "" {
		return "", false
	}
	return cpu, true
}

// DomainCPUMode returns the mode attribute of a domain XML's <cpu> element
// ("" when it has none).
func DomainCPUMode(domainXML string) string {
	cpu, ok := extractElement(domainXML, "cpu")
	if !ok {
		return ""
	}
	var probe struct {
		Mode string `xml:"mode,attr"`
	}
	if err := xml.Unmarshal([]byte(cpu), &probe); err != nil {
		return ""
	}
	return probe.Mode
}
