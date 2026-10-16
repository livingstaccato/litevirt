package firewall

import "github.com/litevirt/litevirt/internal/firewall/macro"

// The catalog lives in the macro package, which imports nothing of the
// daemon, so internal/compose can expand macros without an import cycle.

// MacroRow is one tcp or udp destination-port row of a macro.
type MacroRow = macro.MacroRow

// Macro is a named set of rows that share every other field of a rule.
type Macro = macro.Macro

// ExpandedRule is one ordinary rule a macro expands to.
type ExpandedRule = macro.ExpandedRule

// Macros returns a copy of the catalog, in catalog order.
func Macros() []Macro { return macro.Macros() }

// LookupMacro finds a macro by name, ignoring case, and returns it under its
// canonical spelling.
func LookupMacro(name string) (Macro, bool) { return macro.LookupMacro(name) }

// Expand turns a macro into ordinary rules; see macro.Expand.
func Expand(name, direction, cidr, action string) ([]ExpandedRule, error) {
	return macro.Expand(name, direction, cidr, action)
}
