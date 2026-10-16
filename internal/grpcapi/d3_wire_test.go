package grpcapi

import (
	"context"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"testing"
)

func TestProto_D3ReservationLBWireUnion(t *testing.T) {
	for _, c := range []struct {
		msg    proto.Message
		name   protoreflect.Name
		number protoreflect.FieldNumber
	}{
		{&pb.ApplyLBRequest{}, "health", 10},
		{&pb.ApplyLBRequest{}, "sticky_sessions", 11},
		{&pb.CreateLBRequest{}, "snat", 8},
		{&pb.UpdateLBRequest{}, "snat", 10},
		{&pb.Host{}, "reservations", 29},
		{&pb.Host{}, "reserved_cpu", 30},
		{&pb.Host{}, "reserved_mem_mib", 31},
		{&pb.Host{}, "reservations_error", 32},
		{&pb.Host{}, "reservations_partial", 33},
		{&pb.HostReservation{}, "operation_id", 1},
		{&pb.HostReservation{}, "method", 2},
		{&pb.HostReservation{}, "kind", 3},
		{&pb.HostReservation{}, "vm", 4},
		{&pb.HostReservation{}, "project", 5},
		{&pb.HostReservation{}, "vcpu", 6},
		{&pb.HostReservation{}, "memory_mib", 7},
		{&pb.HostReservation{}, "created_at", 8},
		{&pb.HostReservation{}, "age_seconds", 9},
		{&pb.HostReservation{}, "state", 10},
		{&pb.HostReservation{}, "detail", 11},
		{&pb.HostReservation{}, "header_owner_epoch", 12},
		{&pb.HostReservation{}, "admitted", 13},
		{&pb.HostReservation{}, "provisional", 14},
		{&pb.HostReservation{}, "release_blocked", 15},
		{&pb.LoadBalancer{}, "snat", 10},
		{&pb.ReleaseHostReservationRequest{}, "operation_id", 1},
		{&pb.ReleaseHostReservationRequest{}, "force", 2},
		{&pb.ReleaseHostReservationResponse{}, "released", 1},
		{&pb.ReleaseHostReservationResponse{}, "host", 2},
		{&pb.ReleaseHostReservationResponse{}, "vm", 3},
		{&pb.ReleaseHostReservationResponse{}, "vcpu", 4},
		{&pb.ReleaseHostReservationResponse{}, "memory_mib", 5},
		{&pb.ReleaseHostReservationResponse{}, "detail", 6},
	} {
		f := c.msg.ProtoReflect().Descriptor().Fields().ByName(c.name)
		if f == nil || f.Number() != c.number {
			t.Errorf("%T.%s descriptor %v, want number %d", c.msg, c.name, f, c.number)
		}
	}
	for _, value := range []*bool{nil, proto.Bool(false), proto.Bool(true)} {
		for _, m := range []proto.Message{&pb.UpdateLBRequest{Snat: value}, &pb.LoadBalancer{Snat: value}, &pb.ApplyLBRequest{Snat: value}} {
			b, e := proto.Marshal(m)
			if e != nil {
				t.Fatal(e)
			}
			out := m.ProtoReflect().Type().New().Interface()
			if e := proto.Unmarshal(b, out); e != nil {
				t.Fatal(e)
			}
			f := out.ProtoReflect().Descriptor().Fields().ByName("snat")
			if out.ProtoReflect().Has(f) != (value != nil) {
				t.Fatalf("%T optional presence lost", m)
			}
			if value != nil && out.ProtoReflect().Get(f).Bool() != *value {
				t.Fatalf("%T optional value lost", m)
			}
		}
	}
	service := pb.File_litevirt_v1_service_proto.Services().ByName("LiteVirt")
	method := service.Methods().ByName("ReleaseHostReservation")
	if method == nil || method.Input().FullName() != "litevirt.v1.ReleaseHostReservationRequest" || method.Output().FullName() != "litevirt.v1.ReleaseHostReservationResponse" {
		t.Fatal("release RPC signature lost")
	}
}
func TestProto_D3MethodPolicies(t *testing.T) {
	for _, name := range []string{"ReleaseHostReservation", "ApplyLB", "CreateLoadBalancer", "UpdateLoadBalancer"} {
		method := "/litevirt.v1.LiteVirt/" + name
		if skipAuth[method] || enrollmentOnlyMethods[method] || auditHoldReadOnly(method) {
			t.Errorf("%s gained an authentication/enrollment/audit-read exemption", name)
		}
		ctx := context.WithValue(context.Background(), ctxKeyEnrollOnly, true)
		if status.Code(gateEnrollmentOnly(ctx, method)) != codes.PermissionDenied {
			t.Errorf("%s permits enrollment-only credential", name)
		}
	}
	s := testServer(t)
	if _, err := s.ApplyLB(adminCtx(), &pb.ApplyLBRequest{LbName: "test"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ordinary admin gained peer ApplyLB: %v", err)
	}
}
