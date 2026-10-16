package automation

import (
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type engineError struct{ code string }

func (e engineError) Error() string { return "automation: " + e.code }
func (e engineError) Code() string  { return e.code }
func fail(code string) error        { return engineError{code} }

type assignment = contract.Assignment

func validateCommand(c Command) error { return contract.ValidateSupportedCommand(c) }

// reduce preserves the internal callback API while delegating all semantics.
func reduce(p corrosion.AutomationProjection, d Decision) (corrosion.AutomationReduction, error) {
	return contract.Reduce(p, d)
}
