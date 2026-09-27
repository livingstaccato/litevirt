package grpcapi

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func tableDumpBlob(stream *fakeDumpStream) []byte {
	var blob []byte
	for _, c := range stream.chunks {
		blob = append(blob, c.GetData()...)
	}
	return blob
}

func tableDumpTables(t *testing.T, blob []byte) []string {
	t.Helper()
	var payload struct {
		Tables []struct {
			Name string `json:"name"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(gunzipDump(t, blob), &payload); err != nil {
		t.Fatalf("unmarshal dump: %v", err)
	}
	var out []string
	for _, tb := range payload.Tables {
		out = append(out, tb.Name)
	}
	return out
}

// StreamTableDump is the full dump restricted to named tables, so it carries
// the same secret columns and is peer-only in exactly the same way.
func TestStreamTableDump_PeerOnly(t *testing.T) {
	s := testServer(t)
	seedDumpSecrets(t, s)
	req := &pb.TableDumpRequest{Tables: []string{"hosts", "users", "tokens"}}

	for name, ctx := range map[string]context.Context{
		"operator bearer": userCtx("op", "operator"),
		"admin bearer":    adminCtx(),
		"client cert":     lvCLICertCtx("lv-cli"),
	} {
		stream := &fakeDumpStream{ctx: ctx}
		if err := s.StreamTableDump(req, stream); status.Code(err) != codes.PermissionDenied {
			t.Errorf("StreamTableDump %s: code = %v, want PermissionDenied (err=%v)", name, status.Code(err), err)
		}
		if len(stream.chunks) != 0 {
			t.Errorf("StreamTableDump %s: sent %d chunks before refusing", name, len(stream.chunks))
		}
	}

	stream := &fakeDumpStream{ctx: peerCtxFor(t, s, "peer-1")}
	if err := s.StreamTableDump(req, stream); err != nil {
		t.Fatalf("StreamTableDump peer: %v", err)
	}
	assertDumpCarriesSecrets(t, "StreamTableDump", tableDumpBlob(stream))
}

// A peer gets the tables it named and nothing else.
func TestStreamTableDump_CarriesOnlyTheNamedTables(t *testing.T) {
	s := testServer(t)
	seedDumpSecrets(t, s)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.db.Execute(context.Background(),
		`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		 VALUES ('s1', 'h', 'services: {}', 'active', ?, ?)`, now, now); err != nil {
		t.Fatalf("seed stack: %v", err)
	}

	stream := &fakeDumpStream{ctx: peerCtxFor(t, s, "peer-1")}
	if err := s.StreamTableDump(&pb.TableDumpRequest{Tables: []string{"stacks"}}, stream); err != nil {
		t.Fatalf("StreamTableDump: %v", err)
	}
	if got := tableDumpTables(t, tableDumpBlob(stream)); !slices.Equal(got, []string{"stacks"}) {
		t.Fatalf("StreamTableDump([stacks]) carried %v, want exactly [stacks]", got)
	}
}

// The sensitive lane stays its own: naming one of its tables is refused, not
// served — this RPC checks the peer certificate, not the sender CN the
// sensitive dump pins. An empty list is refused rather than read as
// "everything".
func TestStreamTableDump_RefusesSensitiveAndEmpty(t *testing.T) {
	s := testServer(t)
	peer := peerCtxFor(t, s, "peer-1")
	for name, req := range map[string]*pb.TableDumpRequest{
		"sensitive": {Tables: []string{"stacks", "registry_credentials"}},
		"proofs":    {Tables: []string{"runtime_action_proofs"}},
		"empty":     {},
		"unknown":   {Tables: []string{"no_such_table"}},
	} {
		stream := &fakeDumpStream{ctx: peer}
		if err := s.StreamTableDump(req, stream); status.Code(err) != codes.InvalidArgument {
			t.Errorf("StreamTableDump %s: code = %v, want InvalidArgument (err=%v)", name, status.Code(err), err)
		}
		if len(stream.chunks) != 0 {
			t.Errorf("StreamTableDump %s: sent %d chunks before refusing", name, len(stream.chunks))
		}
	}
}
