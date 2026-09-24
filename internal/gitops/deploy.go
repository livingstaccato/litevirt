package gitops

import (
	"errors"
	"fmt"
	"io"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// DeployStream is the receive side of a DeployStack call.
type DeployStream interface {
	Recv() (*pb.DeployProgress, error)
}

// DrainDeploy reads a DeployStack stream TO ITS END and returns an error that
// names every failed action, or nil when the deploy applied cleanly.
//
// It must not return early. A deploy reports each failed action as an "error"
// progress message and carries on to the next — but only while its client is
// listening: a client that stops reading and closes its connection cancels the
// server's stream context, the deploy's next send fails, and every action
// planned after the failure is abandoned, stack record included. Returning at
// the first error message therefore turned one failed VM into a half-applied
// stack (pinned by TestFleet_ComposeAbandonedDeployStreamCancelsTheRestOfTheDeploy).
func DrainDeploy(stream DeployStream) error {
	var failures []string
	for {
		p, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// The deploy itself failed (e.g. a fail-fast rolling update), or
			// the stream broke. Keep the per-action failures seen so far.
			if len(failures) > 0 {
				return fmt.Errorf("deploy: %s; then the stream ended: %w", strings.Join(failures, "; "), err)
			}
			return fmt.Errorf("stream: %w", err)
		}
		if p.Error != "" {
			name := p.VmName
			if name == "" {
				name = p.Phase
			}
			failures = append(failures, name+": "+p.Error)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("deploy: %d failure(s): %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}
