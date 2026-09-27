package corrosion

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// fakeTableDumpClient adds StreamTableDump to fakeDumpClient.
type fakeTableDumpClient struct {
	fakeDumpClient
	tableChunks    []*pb.StateDumpChunk
	tableRecvErr   error
	tableStreamErr error
	tableCalls     int
	tableReq       []string
}

func (f *fakeTableDumpClient) StreamTableDump(_ context.Context, in *pb.TableDumpRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.StateDumpChunk], error) {
	f.tableCalls++
	f.tableReq = append([]string(nil), in.GetTables()...)
	if f.tableStreamErr != nil {
		return nil, f.tableStreamErr
	}
	return &fakeDumpRecvStream{chunks: f.tableChunks, recvErr: f.tableRecvErr}, nil
}

// A mismatch pulls the mismatched tables only, over StreamTableDump, and never
// touches the full dump.
func TestFetchTableDump_PullsOnlyTheNamedTables(t *testing.T) {
	c := &fakeTableDumpClient{
		fakeDumpClient: fakeDumpClient{chunks: []*pb.StateDumpChunk{chunk("full", true)}},
		tableChunks:    []*pb.StateDumpChunk{chunk("sta", false), chunk("cks", true)},
	}
	got, err := fetchTableDump(context.Background(), c, []string{"stacks"})
	if err != nil {
		t.Fatalf("fetchTableDump: %v", err)
	}
	if string(got) != "stacks" {
		t.Fatalf("got %q, want the table dump %q", got, "stacks")
	}
	if c.tableCalls != 1 || len(c.tableReq) != 1 || c.tableReq[0] != "stacks" {
		t.Errorf("StreamTableDump calls=%d req=%v, want 1 call for [stacks]", c.tableCalls, c.tableReq)
	}
	if c.streamCalls != 0 || c.getCalls != 0 {
		t.Errorf("full dump pulled (stream=%d unary=%d) although the table dump succeeded", c.streamCalls, c.getCalls)
	}
}

// A peer on an older build answers Unimplemented — on the call or on the first
// Recv — and the pull falls back to the full dump, so a mixed-version cluster
// still repairs.
func TestFetchTableDump_FallsBackToTheFullDumpOnUnimplemented(t *testing.T) {
	unimpl := status.Error(codes.Unimplemented, "unknown method StreamTableDump")
	for name, c := range map[string]*fakeTableDumpClient{
		"on call": {fakeDumpClient: fakeDumpClient{chunks: []*pb.StateDumpChunk{chunk("full", true)}}, tableStreamErr: unimpl},
		"on recv": {fakeDumpClient: fakeDumpClient{chunks: []*pb.StateDumpChunk{chunk("full", true)}}, tableRecvErr: unimpl},
	} {
		got, err := fetchTableDump(context.Background(), c, []string{"stacks"})
		if err != nil {
			t.Fatalf("%s: fetchTableDump: %v", name, err)
		}
		if string(got) != "full" || c.tableCalls != 1 || c.streamCalls != 1 {
			t.Errorf("%s: got %q tableCalls=%d streamCalls=%d, want the full dump after one table-dump attempt",
				name, got, c.tableCalls, c.streamCalls)
		}
	}
}

// Any other error is the exchange failing, not an old peer: it propagates, and
// the full dump is NOT pulled behind it.
func TestFetchTableDump_OtherErrorsPropagate(t *testing.T) {
	c := &fakeTableDumpClient{tableRecvErr: status.Error(codes.InvalidArgument, "sensitive table")}
	if _, err := fetchTableDump(context.Background(), c, []string{"stacks"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument propagated", err)
	}
	if c.streamCalls != 0 || c.getCalls != 0 {
		t.Errorf("fell back to the full dump on a non-Unimplemented error (stream=%d unary=%d)", c.streamCalls, c.getCalls)
	}
}
