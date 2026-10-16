package grpcapi

import (
	"encoding/json"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// specForNICAttach is the desired spec a NIC attach under mac begins its
// operation with: specJSON with any entry carrying the MAC (a detached NIC's)
// rewritten to the attached model (compose.RewriteSpecNICForAttach).
// Unchanged, or unreadable, it is returned as it was, byte for byte.
func specForNICAttach(specJSON, mac, model string) string {
	if specJSON == "" {
		return specJSON
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(specJSON), spec); err != nil {
		return specJSON
	}
	if !compose.RewriteSpecNICForAttach(spec, mac, model) {
		return specJSON
	}
	out, err := json.Marshal(spec)
	if err != nil {
		return specJSON
	}
	return string(out)
}
