package corrosion

import (
	"fmt"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// These are limits on automation protocol participation, not a truncation of
// the certified electorate. Quorums always count the entire adopted set.
// Seven complete responding accepts fit with a maximum 2 MiB value
// under the 3 MiB record bound, even with worst-case JSON string escaping.
const MaxAutomationVoters = 7
const MaxAutomationSignerBytes = 8 << 10

func automationElectorateBudget(members []VoterMember) error {
	if len(members) == 0 || len(members) > MaxAutomationVoters {
		return fmt.Errorf("automation electorate exceeds transport budget")
	}
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		if m.Name == "" || m.Incarnation == "" || len(m.Name) > contract.MaxStringBytes || len(m.Incarnation) > contract.MaxStringBytes || !utf8.ValidString(m.Name) || !utf8.ValidString(m.Incarnation) || seen[m.Name] {
			return fmt.Errorf("automation member exceeds transport budget")
		}
		seen[m.Name] = true
	}
	return nil
}

// AutomationTransportEligible checks the actual served signer representation.
// It grants no authority or durable readiness. Each Accept repeats it so renewal cannot
// turn a previously eligible signer into an oversized emitted certificate.
func (s *ClaimSigner) AutomationTransportEligible() bool {
	return s != nil && s.key != nil && s.name != "" && len(s.name) <= contract.MaxStringBytes && utf8.ValidString(s.name) && len(s.certPEM) > 0 && len(s.certPEM) <= MaxAutomationSignerBytes && s.key.Curve != nil && s.key.Curve.Params().BitSize <= 521
}
