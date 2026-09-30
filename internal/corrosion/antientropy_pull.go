package corrosion

import (
	"context"
	"io"

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
func (ae *AntiEntropy) pullAndMerge(ctx context.Context, client pb.LiteVirtClient, tables []string, scope *pullScope, sensReq *pb.SensitiveStateRequest) (kept *syncPayload, pullErr, mergeErr error) {
	sensitive := sensReq != nil
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
			kept, rows, perr, merr := ae.client.mergeTableRowsStream(recv, allowed, keep)
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
	payload, merr := ae.client.mergeRepairPull(data, tables, scope, sensitive)
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
