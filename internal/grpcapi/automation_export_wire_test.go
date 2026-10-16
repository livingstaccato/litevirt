package grpcapi

import (
	"context"
	"math"
	"net"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func exportWirePage() *pb.AutomationSourceExportResponse {
	return &pb.AutomationSourceExportResponse{Version: 1, PublicationId: strings.Repeat("a", 64), Component: 11, Metadata: make([]byte, 131072), Cursor: strings.Repeat("x", 1024), Terminal: true, TerminalRecords: math.MaxInt64, TerminalBytes: math.MaxInt64, TerminalDigest: strings.Repeat("b", 64)}
}
func unknownExportBytes(n int) []byte {
	raw := protowire.AppendTag(nil, 100, protowire.BytesType)
	return protowire.AppendBytes(raw, make([]byte, n-5))
}

// This proves the complete synthetic envelope budget, not membership authority.
// Raw records are protobuf bytes: no base64, compression or receive override.
func TestAutomationExportCompleteWireBudget(t *testing.T) {
	p := exportWirePage()
	p.Records = [][]byte{make([]byte, 3670016)}
	if err := checkAutomationExportWire(p); err != nil {
		t.Fatal("maximum raw frame rejected", err)
	}
	raw, err := proto.Marshal(p)
	if err != nil || len(raw) != proto.Size(p) {
		t.Fatal(err)
	}
	var round pb.AutomationSourceExportResponse
	if err := proto.Unmarshal(raw, &round); err != nil || len(round.Records[0]) != 3670016 {
		t.Fatal("maximum raw record lost", err)
	}
	t.Logf("single maximum raw frame complete protobuf=%d grpc-framed=%d", len(raw), len(raw)+5)
	// With 64 records only one can need a four-byte length varint. All others
	// can need three, giving actual simultaneous record-wrapper maximum257B.
	p.Records = make([][]byte, 64)
	p.Records[0] = make([]byte, 2097152)
	remaining := 3670016 - 2097152
	for i := 1; i < 64; i++ {
		n := remaining / (64 - i)
		p.Records[i] = make([]byte, n)
		remaining -= n
	}
	scalar := &pb.AutomationSourceExportResponse{Version: p.Version, PublicationId: p.PublicationId, Component: p.Component, Terminal: p.Terminal, TerminalRecords: p.TerminalRecords, TerminalBytes: p.TerminalBytes, TerminalDigest: p.TerminalDigest}
	p.ProtoReflect().SetUnknown(unknownExportBytes(65536 - proto.Size(scalar)))
	if err := checkAutomationExportWire(p); err != nil {
		t.Fatal("maximum combined envelope rejected", err)
	}
	raw, err = proto.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 3867912 || len(raw)+5 >= 4194304 {
		t.Fatalf("complete wrapper arithmetic changed: %d", len(raw))
	}
	t.Logf("maximum supported simultaneous fields protobuf=%d grpc-framed=%d", len(raw), len(raw)+5)
	for _, kind := range []string{"record-byte", "record-count", "metadata", "cursor", "unknown-overhead"} {
		t.Run(kind, func(t *testing.T) {
			bad := proto.Clone(p).(*pb.AutomationSourceExportResponse)
			switch kind {
			case "record-byte":
				bad.Records[0] = append(bad.Records[0], 0)
			case "record-count":
				bad.Records = append(bad.Records, []byte{})
			case "metadata":
				bad.Metadata = append(bad.Metadata, 0)
			case "cursor":
				bad.Cursor += "x"
			case "unknown-overhead":
				bad.ProtoReflect().SetUnknown(unknownExportBytes(65537 - proto.Size(scalar)))
			}
			if checkAutomationExportWire(bad) == nil {
				t.Fatal("over-bound complete export accepted")
			}
		})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	pb.RegisterLiteVirtServer(server, &exportWireServer{page: p})
	go server.Serve(listener)
	defer server.Stop()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := pb.NewLiteVirtClient(conn).ExportAutomationSource(context.Background(), &pb.AutomationSourceExportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	received, err := stream.Recv()
	if err != nil || !proto.Equal(p, received) {
		t.Fatal("default4MiB client did not receive complete envelope", err)
	}
}

type exportWireServer struct {
	pb.UnimplementedLiteVirtServer
	page *pb.AutomationSourceExportResponse
}

func (s *exportWireServer) ExportAutomationSource(_ *pb.AutomationSourceExportRequest, stream grpc.ServerStreamingServer[pb.AutomationSourceExportResponse]) error {
	return stream.Send(s.page)
}

func TestAutomationExportMethodPolicies(t *testing.T) {
	const method = "/litevirt.v1.LiteVirt/ExportAutomationSource"
	if skipAuth[method] || enrollmentOnlyMethods[method] || staleReplicaGated[method] {
		t.Fatal("peer export lost narrow repair classification")
	}
	ctx := context.WithValue(context.Background(), ctxKeyEnrollOnly, true)
	if status.Code(gateEnrollmentOnly(ctx, method)) != codes.PermissionDenied {
		t.Fatal("enrollment-only credential gained export authority")
	}
	if !auditHoldReadOnly(method) {
		t.Fatal("immutable peer export blocked behind audit hold")
	}
}
