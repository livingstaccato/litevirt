package compose

import (
	"fmt"
	"sort"

	"github.com/litevirt/litevirt/internal/firewall/macro"
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
			if r.Macro != "" {
				if err := checkMacroRule(r); err != nil {
					v.ps.add(fmt.Sprintf("%s[%d]", path, i), err.Error(), "")
				}
				continue
			}
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

// checkMacroRule is the refuse-form then grammar check of a rule naming a
// macro: it may not also set proto or port, and every row it expands to must
// pass the write grammar (macro.Expand), with the rule's own comment.
func checkMacroRule(r FirewallRuleDef) error {
	if r.Proto != "" || r.Port != "" {
		return fmt.Errorf("macro %q cannot be combined with proto or port", r.Macro)
	}
	if _, err := macro.Expand(r.Macro, r.Direction, r.CIDR, r.Action); err != nil {
		return err
	}
	return rulefield.Rule(r.Direction, "", "", "", "", r.Comment)
}

// ExpandMacros replaces every rule that names a macro with the ordinary rows
// it stands for, in catalog order. Every row of the rule at index i, macro or
// not, gets priority (i+1)*10, as a rule written by hand does. A cluster-tier
// row with no comment of its own is labelled "macro <NAME>"; security-group
// rows have no comment column. A file with no macro is left untouched, and a
// file already expanded is too, so it is safe to call again. A rule the
// catalog does not resolve is an error: it is never left to be written as a
// rule with no proto or port, which would allow everything.
func ExpandMacros(f *File) error {
	names := make([]string, 0, len(f.SecurityGroups))
	for name := range f.SecurityGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sg := f.SecurityGroups[name]
		rules, err := expandMacroRules(sg.Rules, false)
		if err != nil {
			return fmt.Errorf("security-groups.%s.rules: %w", name, err)
		}
		sg.Rules = rules
		f.SecurityGroups[name] = sg
	}
	if fd := f.FirewallDefaults; fd != nil {
		rules, err := expandMacroRules(fd.ClusterRules, true)
		if err != nil {
			return fmt.Errorf("firewall.cluster-rules: %w", err)
		}
		fd.ClusterRules = rules
	}
	return nil
}

func expandMacroRules(in []FirewallRuleDef, label bool) ([]FirewallRuleDef, error) {
	has := false
	for _, r := range in {
		if r.Macro != "" {
			has = true
			break
		}
	}
	if !has {
		return in, nil
	}
	out := make([]FirewallRuleDef, 0, len(in))
	for i, r := range in {
		prio := (i + 1) * 10
		if r.Macro == "" {
			if r.Priority == 0 {
				r.Priority = prio
			}
			out = append(out, r)
			continue
		}
		if err := checkMacroRule(r); err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		m, _ := macro.LookupMacro(r.Macro)
		rows, err := macro.Expand(r.Macro, r.Direction, r.CIDR, r.Action)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		for _, x := range rows {
			d := FirewallRuleDef{
				Direction: x.Direction, Proto: x.Proto, Port: x.Port, CIDR: x.CIDR,
				Action: x.Action, Comment: r.Comment, Priority: prio,
			}
			if label && d.Comment == "" {
				d.Comment = "macro " + m.Name
			}
			out = append(out, d)
		}
	}
	return out, nil
}
