package grpcapi

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The four security branches each added proto fields, reserved numbers and
// RPCs; integrated, every one keeps its own number, and none takes another's.
// A later change that renumbers or reuses one of them fails here first.
func TestProtoNumbers_TheIntegratedBranchesDoNotCollide(t *testing.T) {
	fields := []struct {
		msg  protoreflect.ProtoMessage
		num  protoreflect.FieldNumber
		name protoreflect.Name
	}{
		{&pb.VMSpec{}, 43, "iso_scope"},
		{&pb.EnsureDisksRequest{}, 4, "installer_iso_listed"},
		{&pb.EnsureDisksRequest{}, 5, "installer_iso_paths"},
		{&pb.EnsureDisksRequest{}, 6, "installer_iso_runtime"},
		{&pb.EnsureDisksRequest{}, 7, "installer_iso_sha256"},
		{&pb.EnsureDisksResponse{}, 3, "installer_iso_warning"},
		{&pb.EnsureDisksResponse{}, 4, "installer_iso_resolved"},
		{&pb.PushReplicaIncrementRequest{}, 8, "replica"},
		{&pb.PushReplicaIncrementResponse{}, 3, "replica_recorded"},
		{&pb.StoragePoolContent{}, 6, "replica_vm"},
		{&pb.StoragePoolContent{}, 7, "replica_disk"},
		{&pb.StoragePoolContent{}, 8, "replica_taken"},
	}
	for _, f := range fields {
		md := f.msg.ProtoReflect().Descriptor()
		fd := md.Fields().ByNumber(f.num)
		if fd == nil || fd.Name() != f.name {
			t.Errorf("%s field %d is %v, want %s", md.FullName(), f.num, fd, f.name)
		}
	}
	reserved := []struct {
		msg protoreflect.ProtoMessage
		num protoreflect.FieldNumber
	}{
		{&pb.VMSpec{}, 44},
		{&pb.UploadStoragePoolContentRequest{}, 5},
	}
	for _, r := range reserved {
		md := r.msg.ProtoReflect().Descriptor()
		if !md.ReservedRanges().Has(r.num) || md.Fields().ByNumber(r.num) != nil {
			t.Errorf("%s field %d is not reserved", md.FullName(), r.num)
		}
	}
	svc := pb.File_litevirt_v1_service_proto.Services().ByName("LiteVirt")
	if svc == nil {
		t.Fatal("no LiteVirt service")
	}
	for _, rpc := range []protoreflect.Name{
		// disk-files-project-isolation
		"PushReplica", "ListReplicas", "PruneReplicas", "PruneImages",
		// import-host-path-reads
		"ImportLeftoverStatus",
		// vm-host-path-reads-confined
		"ListISOs", "PullISO", "GetISOLibraryMode", "SetISOLibraryMode", "FetchISOLibraryFile",
	} {
		if svc.Methods().ByName(rpc) == nil {
			t.Errorf("RPC %s is missing", rpc)
		}
	}
}
