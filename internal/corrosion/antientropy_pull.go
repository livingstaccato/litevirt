package corrosion

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// pullAndMerge pulls tables from a peer, narrowed by scope, and merges them:
// over the paged stream (table_rows.go) when the peer serves it, else over the
// blob dump. sensReq selects the sensitive lane (nil: public). It returns the
// pulled rows of every table this node tracks a tie in, for the settled-tie
// proof, and keeps a failed PULL apart from a failed MERGE, which the caller
// reports differently.
//
// The stand-down (legacyRepair) goes straight to the blob dump.
func (ae *AntiEntropy) pullAndMerge(ctx context.Context, client pb.LiteVirtClient, tables []string, scope *pullScope, sensReq *pb.SensitiveStateRequest, rs *remintScope) (kept *syncPayload, pullErr, mergeErr error) {
	sensitive := sensReq != nil
	// A used release-feature record must be in, and any quarantine it trips up,
	// before a feature table is merged (I2). The paged stream merges vms and
	// containers ahead of cluster_policies, and a stream that breaks midway
	// keeps what it merged, so cluster_policies is pulled ALONE first, whole.
	// Done on the receiver: reordering the sender's ranks would make every
	// paged pull from this build fail an older receiver's page-order check.
	// The sensitive lane carries feature data too (a secret a feature stores),
	// and has no cluster_policies of its own: pull the public one first (N6).
	if (sensitive || len(tables) > 1) && (sensitive || slices.Contains(tables, "cluster_policies")) {
		if _, perr, merr := ae.pullAndMerge(ctx, client, []string{"cluster_policies"}, nil, nil, rs); perr != nil || merr != nil {
			return nil, perr, merr
		}
	}
	allowed := replicatedTableSet
	if sensitive {
		allowed = sensitiveTableSet
	}
	if !ae.legacyRepair {
		keep := map[string]bool{}
		tracked := ae.client.UnresolvedTieTables()
		for _, t := range tables {
			if tracked[t] > 0 {
				keep[t] = true
			}
		}
		var stream grpc.ServerStreamingClient[pb.TableRowsPage]
		var err error
		if sensitive {
			stream, err = client.StreamSensitiveTableRows(ctx, sensReq)
		} else {
			req := &pb.TableDumpRequest{Tables: tables}
			if b := scope.wire(); b != nil {
				req.Buckets, req.BucketScheme = b, BucketScheme
			}
			stream, err = client.StreamTableRows(ctx, req)
		}
		switch {
		case err == nil:
			first, older := true, false
			recv := func() (*pb.TableRowsPage, error) {
				p, rerr := stream.Recv()
				if first {
					first = false
					// An older build answers Unimplemented, usually on the
					// first Recv: nothing has been merged yet.
					if status.Code(rerr) == codes.Unimplemented {
						older = true
						return nil, io.EOF
					}
				}
				return p, rerr
			}
			kept, rows, perr, merr := ae.client.mergeTableRowsStreamScoped(recv, allowed, keep, rs)
			if !older {
				ae.client.observePulledRows(rows, tables, scope, sensitive)
				return kept, perr, merr
			}
		case status.Code(err) != codes.Unimplemented:
			return nil, err, nil
		}
	}

	// The blob dump: an older peer, or the stand-down.
	var data []byte
	var err error
	if sensitive {
		data, err = fetchSensitiveStateDump(ctx, client, sensReq)
	} else {
		data, err = fetchTableDumpScoped(ctx, client, tables, scope)
	}
	if err != nil {
		return nil, err, nil
	}
	payload, merr := ae.client.mergeRepairPullScoped(data, tables, scope, sensitive, rs)
	return payload, nil, merr
}

// observePulledRows counts a pull's rows by scope: "bucket" for a table the
// pull narrowed (a co-bucketed parent included), "table" for one sent whole.
func (c *Client) observePulledRows(rows map[string]int, pull []string, scope *pullScope, sensitive bool) {
	var buckets map[string][]int
	if scope != nil {
		buckets = scope.buckets
	}
	var narrowedTo dumpScope
	if sensitive {
		_, narrowedTo = resolveSensitiveDumpScope(pull, buckets)
	} else if _, sc, err := resolveTableDumpScope(pull, buckets); err == nil {
		narrowedTo = sc
	}
	for t, n := range rows {
		label := "table"
		if narrowedTo[t] != nil {
			label = "bucket"
		}
		c.observePullRows(label, n)
	}
}

// pullTableFrom pulls table from peer and merges it.
func (ae *AntiEntropy) pullTableFrom(ctx context.Context, peer, table string) error {
	client, conn, err := ae.peerClient(ctx, peer)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, perr, merr := ae.pullAndMerge(ctx, client, []string{table}, nil, nil, nil)
	return errors.Join(perr, merr)
}

// ErrNoPeerConfirmed is PullTableNow's answer when no peer completed the pull.
var ErrNoPeerConfirmed = errors.New("no peer completed the pull")

// PullTableNow pulls one replicated table from a member and merges it, ahead
// of a decision read from that table: the currency pull `lv host rm` and `lv
// host add` make before deciding a host's incarnation (host_incarnation.go).
//
// exclude (the host the decision is about) is never a candidate: its own
// replica confirms nothing. Voters are tried first. A member is skipped when a
// pass would skip it (isolated, or unable to keep a release feature in use).
// When no candidate remains and no other voter was skipped — a cluster this
// node is alone in, or one whose only other member is the excluded host — it
// returns ("", skipped, nil): there is nobody to confirm with, and the
// caller's voter-majority gate has already decided whether this node may act.
// When a voter was skipped (isolated, or unable to keep a release feature in
// use) it refuses, naming them. It is not debounced, and is
// bounded by ctx, which it shares out among the candidates.
func (ae *AntiEntropy) PullTableNow(ctx context.Context, table, exclude string) (peer string, skipped []string, err error) {
	if !replicatedTableSet[table] {
		return "", nil, fmt.Errorf("%s is not a replicated table", table)
	}
	// This node in release probation takes no state from any peer: say so,
	// rather than name every peer as the one that cannot keep a feature.
	if err := ae.client.ReleaseProbationRefusal(); err != nil {
		return "", nil, fmt.Errorf("%w: this node is in release probation: %v", ErrNoPeerConfirmed, err)
	}
	voters, verr := VoterSet(ctx, ae.client)
	if verr != nil {
		// Without the voter set a skipped voter cannot be told from a
		// skipped non-voter: fail closed.
		return "", nil, fmt.Errorf("%w: read the voter set: %v", ErrNoPeerConfirmed, verr)
	}
	var first, rest, skippedVoters []string
	skip := func(name, why string) {
		skipped = append(skipped, name+" ("+why+")")
		if voters[name] {
			skippedVoters = append(skippedVoters, name+" ("+why+")")
		}
	}
	for _, m := range ae.client.Members() {
		switch {
		case m.Name == "" || m.Name == exclude:
			continue
		case func() bool { e, _, ierr := HostIsolation(ctx, ae.client, m.Name); return ierr == nil && e > 0 }():
			skip(m.Name, "isolated")
		case ae.client.ReplicationSourceAllowed(ctx, m.Name) != nil:
			skip(m.Name, "cannot keep a release feature in use")
		case voters[m.Name]:
			first = append(first, m.Name)
		default:
			rest = append(rest, m.Name)
		}
	}
	candidates := append(first, rest...)
	if len(candidates) == 0 {
		// Nobody to confirm with. That is a decision this node may make
		// alone only when no other voter exists to confirm it: a voter that
		// was skipped is one the operator should know about first.
		if len(skippedVoters) > 0 {
			return "", skipped, fmt.Errorf("%w: every other voter was skipped: %s", ErrNoPeerConfirmed,
				strings.Join(skippedVoters, ", "))
		}
		return "", skipped, nil
	}
	pull := ae.tablePull
	if pull == nil {
		pull = ae.pullTableFrom
	}
	var errs []string
	for i, name := range candidates {
		if ctx.Err() != nil {
			break
		}
		// Each candidate gets its share of what is left of ctx's budget, so
		// one that does not answer cannot spend the time of those behind it.
		budget := antiEntropyPeerTimeout
		if dl, ok := ctx.Deadline(); ok {
			if share := time.Until(dl) / time.Duration(len(candidates)-i); share < budget {
				budget = share
			}
		}
		pctx, cancel := context.WithTimeout(ctx, budget)
		err := pull(pctx, name, table)
		cancel()
		if err == nil {
			return name, skipped, nil
		}
		errs = append(errs, name+": "+err.Error())
	}
	if len(errs) == 0 && ctx.Err() != nil {
		errs = append(errs, ctx.Err().Error())
	}
	return "", skipped, fmt.Errorf("%w: %s", ErrNoPeerConfirmed, strings.Join(errs, "; "))
}
