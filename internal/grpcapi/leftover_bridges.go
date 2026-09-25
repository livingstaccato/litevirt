package grpcapi

import (
	"context"
	"log/slog"
	"strings"

	"github.com/litevirt/litevirt/internal/network"
)

// A NIC whose network had no record fell back to a flat bridge named after
// the network, which CreateVM created on the VM's host. For a stack NIC on an
// undeclared network that name was "<stack>_<name>". Once no NIC uses such a
// bridge it carries nothing, so it is removed here, on the host that has it.
//
// A bridge is removed only when ALL of these hold:
//   - its name is "<stack>_<rest>" for a stack litevirt knows (live or deleted),
//   - it is the network name some litevirt NIC row used, and no live NIC row
//     anywhere uses it now,
//   - no network record has that name, and no network's bridge has it,
//   - on this host it is a bridge with no ports and no IPv4 address
//     (NetworkProvisioner.RemoveUnusedBridge checks that).
//
// litevirt keeps no marker saying it created a bridge, so this pattern is the
// proof. An operator's own bridge would need an operator to have pointed a
// litevirt NIC at it by that stack-scoped name AND to have nothing on it.

// removeLeftoverStackBridges scans for flat stack bridges no NIC uses and
// removes the ones this host has.
func (s *Server) removeLeftoverStackBridges(ctx context.Context, _ *netReconcileState) {
	names, err := s.unusedStackFlatBridgeNames(ctx, "")
	if err != nil {
		slog.Warn("network reconcile: list leftover stack bridges", "error", err)
		return
	}
	for _, name := range names {
		s.removeBridgeIfUnusedHere(name)
	}
}

// removeStackBridgeIfUnused is the same check for one name, used right after
// a NIC moves off it.
func (s *Server) removeStackBridgeIfUnused(ctx context.Context, name string) {
	names, err := s.unusedStackFlatBridgeNames(ctx, name)
	if err != nil {
		slog.Warn("leftover stack bridge check failed", "bridge", name, "error", err)
		return
	}
	for _, n := range names {
		s.removeBridgeIfUnusedHere(n)
	}
}

func (s *Server) removeBridgeIfUnusedHere(name string) {
	removed, err := s.networkProvisioner().RemoveUnusedBridge(name)
	switch {
	case err != nil:
		slog.Warn("remove leftover stack bridge failed", "bridge", name, "error", err)
	case removed:
		slog.Info("removed a leftover flat stack bridge no NIC uses", "bridge", name)
	}
}

// unusedStackFlatBridgeNames returns the names meeting the database half of
// the rule above. only != "" restricts the answer to that one name.
func (s *Server) unusedStackFlatBridgeNames(ctx context.Context, only string) ([]string, error) {
	refRows, err := s.db.Query(ctx,
		`SELECT network_name, MAX(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) AS live
		 FROM (SELECT network_name, deleted_at FROM vm_interfaces
		       UNION ALL SELECT network_name, deleted_at FROM vm_nics)
		 GROUP BY network_name`)
	if err != nil {
		return nil, err
	}
	// A stack's name is known from its record or from any VM that belongs to it
	// (a deploy writes the stack record only once it has finished).
	stackRows, err := s.db.Query(ctx,
		`SELECT name FROM stacks UNION SELECT DISTINCT stack_name AS name FROM vms WHERE stack_name != ''`)
	if err != nil {
		return nil, err
	}
	netRows, err := s.db.Query(ctx, `SELECT name, type, config FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	taken := map[string]bool{}
	for _, r := range netRows {
		name := r.String("name")
		taken[name] = true
		if def, err := networkRowDef(networkRow{name: name, typ: r.String("type"), config: r.String("config")}); err == nil {
			taken[network.BridgeName(name, def)] = true
		}
	}
	var stacks []string
	for _, r := range stackRows {
		if n := r.String("name"); n != "" {
			stacks = append(stacks, n)
		}
	}
	isStackScoped := func(name string) bool {
		for _, st := range stacks {
			if strings.HasPrefix(name, st+"_") && len(name) > len(st)+1 {
				return true
			}
		}
		return false
	}
	live := map[string]bool{}
	var candidates []string
	for _, r := range refRows {
		name := r.String("network_name")
		live[name] = r.Int("live") != 0
		if only == "" {
			candidates = append(candidates, name)
		}
	}
	if only != "" {
		// The caller just moved a NIC off this name, which may have been its
		// last row of any kind.
		candidates = []string{only}
	}
	var out []string
	for _, name := range candidates {
		if live[name] || taken[name] || !isStackScoped(name) {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}
