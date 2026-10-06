package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// auditAdmissionPosition is the audit chain position AdmitHost hands a machine
// admitted under name — the last seq the name wrote here and that row's hash —
// or a refusal when this node cannot vouch for it.
//
// The position is the whole of what stops a host rebuilt under an old name from
// forking its chain: the new machine holds its audit rows until that row has
// reached it, and a position of 0 tells it there is nothing to wait for. So a
// node that may simply not have the name's history yet must refuse, not answer
// 0. Three ways that happens, each refused Unavailable:
//
//   - this node is itself holding its own audit rows: it is a rebuilt host
//     whose history has not arrived, so the cluster's history of other names
//     has not either;
//   - its replica has not completed an exchange with a peer. Being alone is not
//     enough on its own: a rebuilt host at first boot sees only its own host
//     row. Only a node that FOUNDED the cluster and is alone in it (no join
//     peers configured, no gossip member, no other live host) answers from its
//     own replica — there is nobody else whose replica could be newer;
//   - the name's tail here is below a retirement the cluster CA recorded for one
//     of its keys (`lv host rm` writes it at the tail it removed the host at):
//     this replica is behind the one that removed it.
func (s *Server) auditAdmissionPosition(ctx context.Context, name string) (int64, string, error) {
	if s.db.AuditChainHeld(ctx, s.hostName) {
		return 0, "", status.Errorf(codes.Unavailable,
			"%s cannot admit %s: it is itself holding its own audit rows until its history arrives from its "+
				"peers, so its copy of %s's audit history may be incomplete. Run `lv host add` against a "+
				"node that is not (`lv health` shows audit_chain_held)", s.hostName, name, name)
	}
	if ok, why := s.db.ReplicaCaughtUp(); !ok {
		alone, err := s.clusterOfOne(ctx)
		if err != nil {
			return 0, "", status.Errorf(codes.Unavailable, "read this node's peers: %v", err)
		}
		if !alone || s.joinedCluster {
			return 0, "", status.Errorf(codes.Unavailable,
				"%s cannot admit %s: its replica has not caught up with the cluster (%s), so it cannot "+
					"vouch for %s's audit history. Retry in a minute, or run `lv host add` against another "+
					"node", s.hostName, name, why, name)
		}
	}
	seq, hash, err := corrosion.AuditChainTail(ctx, s.db, name)
	if err != nil {
		return 0, "", status.Errorf(codes.Unavailable, "read %s's audit chain position: %v", name, err)
	}
	keyring := s.db.AuditKeyringOf()
	if v, verr := corrosion.LoadAuditVerifier(s.pkiDir); verr == nil {
		keyring = v
	}
	floor, err := corrosion.CARetirementFloor(ctx, s.db, keyring, name)
	if err != nil {
		return 0, "", status.Errorf(codes.Unavailable, "read %s's audit key retirements: %v", name, err)
	}
	if seq < floor {
		return 0, "", status.Errorf(codes.Unavailable,
			"%s cannot admit %s: the cluster CA retired %s's key at audit seq %d, but this node's copy of "+
				"its audit chain ends at %d — this replica is behind the one that removed it. Retry once "+
				"replication has caught up, or run `lv host add` against another node", s.hostName, name, name, floor, seq)
	}
	return seq, hash, nil
}

// SetJoinedCluster records whether this node was set up to join an existing
// cluster (join_peers configured). A node that joined never vouches for an
// audit chain position on the strength of being alone (auditAdmissionPosition).
func (s *Server) SetJoinedCluster(joined bool) { s.joinedCluster = joined }
