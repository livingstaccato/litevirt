package grpcapi

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"math"
	"net"
	"os"
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

// The stream double represents only the transport boundary. It never supplies a
// peer identity, auth context or source owner; the real handler must refuse it.
type exportAdmissionStream struct {
	grpc.ServerStream
	ctx   context.Context
	sends int
}

func (s *exportAdmissionStream) Context() context.Context                      { return s.ctx }
func (s *exportAdmissionStream) Send(*pb.AutomationSourceExportResponse) error { s.sends++; return nil }
func TestAutomationExportHandlerAdmissionAndRelease(t *testing.T) {
	s := testServerR2(t)
	stream := &exportAdmissionStream{ctx: context.Background()}
	if got := status.Code(s.ExportAutomationSource(nil, stream)); got != codes.Unavailable {
		t.Fatalf("missing admission: %v", got)
	}
	s.automationExportSem = make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		if got := status.Code(s.ExportAutomationSource(nil, stream)); got != codes.PermissionDenied {
			t.Fatalf("unauthenticated export: %v", got)
		}
		if len(s.automationExportSem) != 0 {
			t.Fatal("refused export retained its semaphore slot")
		}
	}
	if s.automationSource != nil || stream.sends != 0 {
		t.Fatal("unauthenticated export reached source preparation or Send")
	}
	s.automationExportSem <- struct{}{}
	s.automationExportSem <- struct{}{}
	if got := status.Code(s.ExportAutomationSource(nil, stream)); got != codes.ResourceExhausted {
		t.Fatalf("full admission: %v", got)
	}
	if len(s.automationExportSem) != 2 || stream.sends != 0 {
		t.Fatal("capacity refusal changed admitted work or sent a page")
	}
}

// The canonical custom audit entry is backed by the current handler's direct
// peer check, bounded owner call under its stream context, deferred admission
// release, final identity check and returned transport error. This guard does
// not pretend the unauthenticated admission test executes a successful export.
func automationExportAuditProblems(raw []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), "automation_export.go", raw, parser.SkipObjectResolution)
	if err != nil {
		return []string{"parse export handler: " + err.Error()}
	}
	var handler *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "ExportAutomationSource" {
			handler = fd
		}
	}
	if handler == nil || handler.Body == nil {
		return []string{"missing actual export handler"}
	}
	text := func(n ast.Node) string {
		var b bytes.Buffer
		_ = printer.Fprint(&b, token.NewFileSet(), n)
		return b.String()
	}
	calls := map[string]token.Pos{}
	acquired, released := false, false
	ast.Inspect(handler.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			calls[text(call)] = call.Pos()
		}
		if send, ok := n.(*ast.SendStmt); ok && text(send.Chan) == "s.automationExportSem" {
			acquired = true
		}
		if d, ok := n.(*ast.DeferStmt); ok {
			ast.Inspect(d, func(n ast.Node) bool {
				if receive, ok := n.(*ast.UnaryExpr); ok && receive.Op == token.ARROW && text(receive.X) == "s.automationExportSem" {
					released = true
				}
				return true
			})
		}
		return true
	})
	var problems []string
	if !acquired || !released {
		problems = append(problems, "export lost owned deferred admission release")
	}
	for _, call := range []string{"stream.Context()", "s.requireAutomationExportPeer(ctx)", "checkedAutomationExportRequest(r)", "owner.ExportAutomationSource(ctx, request)"} {
		if calls[call] == token.NoPos {
			problems = append(problems, "export lost audited call: "+call)
		}
	}
	last, ok := handler.Body.List[len(handler.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(last.Results) != 1 || text(last.Results[0]) != "stream.Send(response)" {
		problems = append(problems, "export no longer returns its actual Send error")
	}
	identity, send := calls["s.connIdentityGate(ctx)"], calls["stream.Send(response)"]
	if identity == token.NoPos || send == token.NoPos || identity >= send {
		problems = append(problems, "export lost final identity check before Send")
	}
	return problems
}
func TestAutomationExportCustomAuditBoundary(t *testing.T) {
	original, err := os.ReadFile("automation_export.go")
	if err != nil {
		t.Fatal(err)
	}
	if got := automationExportAuditProblems(original); len(got) != 0 {
		t.Fatal(got)
	}
	for _, tc := range []struct{ name, before, after, want string }{
		{"direct-peer", "s.requireAutomationExportPeer(ctx)", "s.requirePeerCert(ctx)", "lost audited call: s.requireAutomationExportPeer(ctx)"},
		{"context", "owner.ExportAutomationSource(ctx, request)", "owner.ExportAutomationSource(context.Background(), request)", "lost audited call: owner.ExportAutomationSource(ctx, request)"},
		{"release", "defer func() { <-s.automationExportSem }()", "func() { <-s.automationExportSem }()", "lost owned deferred admission release"},
		{"send-error", "return stream.Send(response)", "_ = stream.Send(response); return nil", "no longer returns its actual Send error"},
		{"final-identity", "if err := s.connIdentityGate(ctx); err != nil", "if err := s.requirePeerCert(ctx); err != nil", "lost final identity check before Send"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := string(original)
			// connIdentityGate also occurs in the authentication helper. Mutate the
			// actual handler, retaining the earlier authenticated-connection check.
			start := strings.Index(raw, "func (s *Server) ExportAutomationSource(")
			if start < 0 {
				t.Fatal("actual export handler disappeared")
			}
			relative := strings.Index(raw[start:], tc.before)
			if relative < 0 {
				t.Fatal("mutation missed actual export handler")
			}
			at := start + relative
			changed := []byte(raw[:at] + tc.after + raw[at+len(tc.before):])
			got := strings.Join(automationExportAuditProblems(changed), "\n")
			if strings.Contains(got, "parse ") || !strings.Contains(got, tc.want) {
				t.Fatalf("wrong audit refusal: %s, want %q", got, tc.want)
			}
		})
	}
}
