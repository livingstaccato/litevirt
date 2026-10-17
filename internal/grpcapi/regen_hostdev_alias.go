package grpcapi

import (
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pci"
)

// ownedHostdevConfigs is the hostdevs of a regenerate: every address the VM
// owns, each with the user alias the current definition gives it. Ownership
// carries no alias, and a device attached through the journal is matched by
// its alias afterwards (the reconcile patcher, a detach).
func ownedHostdevConfigs(owned []string, priorXML string) []lv.HostdevConfig {
	aliases := map[string]string{}
	if priorXML != "" {
		if m, err := lv.HostdevPCIAliases(priorXML); err == nil {
			for addr, alias := range m {
				if bdf, ok := pci.CanonicalBDF(addr); ok {
					aliases[bdf] = alias
				}
			}
		}
	}
	var out []lv.HostdevConfig
	for _, addr := range owned {
		alias := ""
		if bdf, ok := pci.CanonicalBDF(addr); ok {
			alias = aliases[bdf]
		}
		out = append(out, lv.HostdevConfig{Address: addr, Alias: alias})
	}
	return out
}
