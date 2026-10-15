package compose

import (
	"fmt"

	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// validateFirewall checks every firewall rule and ip set against the grammar
// the renderer can write into an nft script (rulefield): a value outside it
// either stops every host's firewall from applying or adds nft syntax of its
// own to every host's ruleset. The daemon's writers refuse the same values;
// this names the field in the file.
func (v *validator) validateFirewall(f *File) {
	rules := func(path string, rs []FirewallRuleDef) {
		for i, r := range rs {
			if err := rulefield.Rule(r.Direction, r.Proto, r.Port, r.CIDR, r.Action, r.Comment); err != nil {
				v.ps.add(fmt.Sprintf("%s[%d]", path, i), err.Error(), "")
			}
		}
	}
	for _, name := range sortedKeys(f.SecurityGroups) {
		rules("security-groups."+name+".rules", f.SecurityGroups[name].Rules)
	}
	for _, name := range sortedKeys(f.IPSets) {
		if err := rulefield.IPSet(name, f.IPSets[name].CIDRs); err != nil {
			v.ps.add("ipsets."+name, err.Error(), "")
		}
	}
	if fd := f.FirewallDefaults; fd != nil {
		rules("firewall.cluster-rules", fd.ClusterRules)
	}
}
