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

func validateCommand(c Command) error {
	if err := contract.ValidateSupportedCommand(c); err != nil {
		return err
	}
	// Structural support is not admission authority. Task5 migration permits,
	// enrolled authentication and runtime/custody providers are not wired yet.
	if c.Kind != "initialize_cluster" && c.Kind != "read_barrier" {
		return fail(CodeUnavailable)
	}
	return nil
}

// reduce preserves the internal callback API while delegating all semantics.
func reduce(p corrosion.AutomationProjection, d Decision) (corrosion.AutomationReduction, error) {
	return contract.Reduce(p, d)
}
