package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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
		// a re-create's judgement on the host placement chose
		"PreflightRecreateVM",
	} {
		if svc.Methods().ByName(rpc) == nil {
			t.Errorf("RPC %s is missing", rpc)
		}
	}
}

// The ops bundle's fields, messages and RPCs (HA disarm, NIC MTU, replication
// rate) keep the numbers they were given.
func TestProtoNumbers_OpsBundle(t *testing.T) {
	fields := []struct {
		msg  protoreflect.ProtoMessage
		num  protoreflect.FieldNumber
		name protoreflect.Name
	}{
		{&pb.NetworkAttachment{}, 18, "mtu"},
		{&pb.NICMTUUpdate{}, 1, "ordinal"},
		{&pb.NICMTUUpdate{}, 2, "mtu"},
		{&pb.UpdateVMRequest{}, 27, "nic_mtu"},
		{&pb.ReadyResponse{}, 5, "ha_disarmed"},
		{&pb.ReadyResponse{}, 6, "ha_policy_at"},
		{&pb.ReadyResponse{}, 7, "ha_known"},
		{&pb.ReplicationSchedule{}, 14, "bwlimit_bytes_per_sec"},
		{&pb.CreateReplicationScheduleRequest{}, 12, "bwlimit_bytes_per_sec"},
		{&pb.EnsureDisksRequest{}, 9, "nic_mtu"},
		{&pb.NICMTUExpectation{}, 1, "network"},
		{&pb.NICMTUExpectation{}, 2, "mtu"},
		{&pb.NICMTUExpectation{}, 3, "ordinal"},
		{&pb.EnsureDisksResponse{}, 8, "nic_mtu_problem"},
		{&pb.EnsureDisksRequest{}, 10, "want_network_devices"},
		{&pb.EnsureDisksResponse{}, 9, "network_devices"},
		{&pb.SetHAPolicyRequest{}, 1, "state"},
		{&pb.SetHAPolicyRequest{}, 2, "reason"},
		{&pb.SetHAPolicyRequest{}, 3, "fence_down_hosts"},
		{&pb.HAPolicyStatus{}, 1, "state"},
		{&pb.HAPolicyStatus{}, 2, "set_by"},
		{&pb.HAPolicyStatus{}, 3, "at"},
		{&pb.HAPolicyStatus{}, 4, "reason"},
		{&pb.HAPolicyStatus{}, 5, "voters"},
		{&pb.HAPolicyStatus{}, 6, "would_be_fenced"},
		{&pb.HAPolicyStatus{}, 7, "first_use_paid"},
		{&pb.HAPolicyStatus{}, 8, "regions"},
		{&pb.HAVoterAnswer{}, 1, "host"},
		{&pb.HAVoterAnswer{}, 2, "ha_known"},
		{&pb.HAVoterAnswer{}, 3, "ha_disarmed"},
		{&pb.HAVoterAnswer{}, 4, "ha_policy_at"},
		{&pb.HAVoterAnswer{}, 5, "confirmed"},
		{&pb.HAVoterAnswer{}, 6, "status"},
		{&pb.HARegionConfirmation{}, 1, "region"},
		{&pb.HARegionConfirmation{}, 2, "confirmed"},
	}
	for _, f := range fields {
		md := f.msg.ProtoReflect().Descriptor()
		fd := md.Fields().ByNumber(f.num)
		if fd == nil || fd.Name() != f.name {
			t.Errorf("%s field %d is %v, want %s", md.FullName(), f.num, fd, f.name)
		}
	}
	if fd := (&pb.CreateReplicationScheduleRequest{}).ProtoReflect().Descriptor().Fields().ByNumber(12); fd == nil || !fd.HasPresence() {
		t.Error("CreateReplicationScheduleRequest.bwlimit_bytes_per_sec must be optional: unset keeps the stored limit, 0 clears it")
	}
	if fd := (&pb.NetworkAttachment{}).ProtoReflect().Descriptor().Fields().ByNumber(11); fd != nil {
		t.Errorf("NetworkAttachment field 11 is %s; it stays unused", fd.Name())
	}
	svc := pb.File_litevirt_v1_service_proto.Services().ByName("LiteVirt")
	for _, rpc := range []protoreflect.Name{"GetHAPolicy", "SetHAPolicy"} {
		if svc.Methods().ByName(rpc) == nil {
			t.Errorf("RPC %s is missing", rpc)
		}
	}
}

// The ops bundle's new fields survive a protojson round trip, and the optional
// bandwidth limit tells unset apart from 0.
func TestProto_OpsBundleFieldsRoundTrip(t *testing.T) {
	roundTrip := func(t *testing.T, in, out proto.Message) string {
		t.Helper()
		b, err := protojson.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %T: %v", in, err)
		}
		if err := protojson.Unmarshal(b, out); err != nil {
			t.Fatalf("unmarshal %T: %v", out, err)
		}
		if !proto.Equal(in, out) {
			t.Errorf("%T round trip: got %v, want %v", in, out, in)
		}
		return string(b)
	}

	nic := &pb.NetworkAttachment{Name: "lan", Mtu: 9000}
	var nicOut pb.NetworkAttachment
	roundTrip(t, nic, &nicOut)
	if nicOut.GetMtu() != 9000 {
		t.Errorf("NetworkAttachment.mtu = %d, want 9000", nicOut.GetMtu())
	}

	ready := &pb.ReadyResponse{HostName: "n1", Ready: true, HaDisarmed: true, HaPolicyAt: "2026-10-15T05:10:00Z", HaKnown: true}
	var readyOut pb.ReadyResponse
	roundTrip(t, ready, &readyOut)
	if !readyOut.GetHaDisarmed() || readyOut.GetHaPolicyAt() != "2026-10-15T05:10:00Z" || !readyOut.GetHaKnown() {
		t.Errorf("ReadyResponse HA fields = %v/%q/%v, want true/%q/true",
			readyOut.GetHaDisarmed(), readyOut.GetHaPolicyAt(), readyOut.GetHaKnown(), ready.GetHaPolicyAt())
	}

	var unsetOut pb.CreateReplicationScheduleRequest
	roundTrip(t, &pb.CreateReplicationScheduleRequest{VmName: "web"}, &unsetOut)
	if unsetOut.BwlimitBytesPerSec != nil {
		t.Errorf("unset bwlimit_bytes_per_sec came back as %d, want unset", unsetOut.GetBwlimitBytesPerSec())
	}
	zero := int64(0)
	var zeroOut pb.CreateReplicationScheduleRequest
	roundTrip(t, &pb.CreateReplicationScheduleRequest{VmName: "web", BwlimitBytesPerSec: &zero}, &zeroOut)
	if zeroOut.BwlimitBytesPerSec == nil || zeroOut.GetBwlimitBytesPerSec() != 0 {
		t.Error("bwlimit_bytes_per_sec set to 0 came back unset, want an explicit 0")
	}
	var schedOut pb.ReplicationSchedule
	roundTrip(t, &pb.ReplicationSchedule{VmName: "web", BwlimitBytesPerSec: 50 << 20}, &schedOut)
	if schedOut.GetBwlimitBytesPerSec() != 50<<20 {
		t.Errorf("ReplicationSchedule.bwlimit_bytes_per_sec = %d, want %d", schedOut.GetBwlimitBytesPerSec(), 50<<20)
	}

	ens := &pb.EnsureDisksRequest{VmName: "web", NicMtu: []*pb.NICMTUExpectation{{Network: "jumbo", Mtu: 9000, Ordinal: 1}}}
	var ensOut pb.EnsureDisksRequest
	js := roundTrip(t, ens, &ensOut)
	if got := ensOut.GetNicMtu(); len(got) != 1 || got[0].GetNetwork() != "jumbo" || got[0].GetMtu() != 9000 || got[0].GetOrdinal() != 1 {
		t.Errorf("EnsureDisksRequest.nic_mtu = %v, want one {jumbo 9000 1}", got)
	}
	if !strings.Contains(js, `"nicMtu"`) {
		t.Errorf("EnsureDisksRequest JSON %s has no nicMtu", js)
	}
}

// The firewall extras' fields, messages and RPCs (SYN-flood protection,
// logging, tag groups) keep the numbers they were given. The numbers were
// checked free against the integration head and every fork branch.
func TestProtoNumbers_FirewallExtras(t *testing.T) {
	fields := []struct {
		msg  protoreflect.ProtoMessage
		num  protoreflect.FieldNumber
		name protoreflect.Name
	}{
		{&pb.FirewallRule{}, 11, "log"},
		{&pb.SecurityGroupRule{}, 9, "log"},
		{&pb.VMSpec{}, 47, "firewall_id"},

		{&pb.FirewallSynfloodPolicy{}, 1, "scope"},
		{&pb.FirewallSynfloodPolicy{}, 2, "mode"},
		{&pb.FirewallSynfloodPolicy{}, 3, "rate"},
		{&pb.FirewallSynfloodPolicy{}, 4, "burst"},
		{&pb.FirewallSynfloodPolicy{}, 5, "set_by"},
		{&pb.FirewallSynfloodPolicy{}, 6, "updated_at"},
		{&pb.FirewallSynfloodPolicy{}, 7, "inherited"},

		{&pb.FirewallLogPolicy{}, 1, "scope"},
		{&pb.FirewallLogPolicy{}, 2, "default_policy"},
		{&pb.FirewallLogPolicy{}, 3, "rate"},
		{&pb.FirewallLogPolicy{}, 4, "burst"},
		{&pb.FirewallLogPolicy{}, 5, "set_by"},
		{&pb.FirewallLogPolicy{}, 6, "updated_at"},
		{&pb.FirewallLogPolicy{}, 7, "inherited"},

		{&pb.FirewallLogEntry{}, 1, "host"},
		{&pb.FirewallLogEntry{}, 2, "seq"},
		{&pb.FirewallLogEntry{}, 3, "time"},
		{&pb.FirewallLogEntry{}, 4, "workload"},
		{&pb.FirewallLogEntry{}, 5, "mac"},
		{&pb.FirewallLogEntry{}, 6, "device"},
		{&pb.FirewallLogEntry{}, 7, "side"},
		{&pb.FirewallLogEntry{}, 8, "rule_id"},
		{&pb.FirewallLogEntry{}, 9, "tier"},
		{&pb.FirewallLogEntry{}, 10, "verdict"},
		{&pb.FirewallLogEntry{}, 11, "family"},
		{&pb.FirewallLogEntry{}, 12, "proto"},
		{&pb.FirewallLogEntry{}, 13, "src"},
		{&pb.FirewallLogEntry{}, 14, "sport"},
		{&pb.FirewallLogEntry{}, 15, "dst"},
		{&pb.FirewallLogEntry{}, 16, "dport"},
		{&pb.FirewallLogEntry{}, 17, "length"},
		{&pb.FirewallLogEntry{}, 18, "tcp_flags"},

		{&pb.FirewallTagGroup{}, 1, "name"},
		{&pb.FirewallTagGroup{}, 2, "match"},
		{&pb.FirewallTagGroup{}, 3, "networks"},
		{&pb.FirewallTagGroup{}, 4, "security_groups"},
		{&pb.FirewallTagGroup{}, 5, "set_by"},
		{&pb.FirewallTagGroup{}, 6, "updated_at"},
		{&pb.FirewallTagGroup{}, 7, "members"},

		{&pb.FirewallTagMember{}, 1, "kind"},
		{&pb.FirewallTagMember{}, 2, "workload"},
		{&pb.FirewallTagMember{}, 3, "host"},
		{&pb.FirewallTagMember{}, 4, "addresses"},
		{&pb.FirewallTagMember{}, 5, "address_note"},

		{&pb.FirewallTags{}, 1, "kind"},
		{&pb.FirewallTags{}, 2, "workload"},
		{&pb.FirewallTags{}, 3, "host"},
		{&pb.FirewallTags{}, 4, "fw_id"},
		{&pb.FirewallTags{}, 5, "tags"},
		{&pb.FirewallTags{}, 6, "set_by"},
		{&pb.FirewallTags{}, 7, "updated_at"},
		{&pb.FirewallTags{}, 8, "orphan"},
		{&pb.FirewallTags{}, 9, "replaced_fw_id"},
		{&pb.FirewallTags{}, 10, "dropped_tags"},
		{&pb.FirewallTags{}, 11, "unreadable"},

		{&pb.SetFirewallTagsRequest{}, 1, "kind"},
		{&pb.SetFirewallTagsRequest{}, 2, "workload"},
		{&pb.SetFirewallTagsRequest{}, 3, "host"},
		{&pb.SetFirewallTagsRequest{}, 4, "set"},
		{&pb.SetFirewallTagsRequest{}, 5, "remove"},
	}
	for _, f := range fields {
		md := f.msg.ProtoReflect().Descriptor()
		fd := md.Fields().ByNumber(f.num)
		if fd == nil || fd.Name() != f.name {
			t.Errorf("%s field %d is %v, want %s", md.FullName(), f.num, fd, f.name)
		}
	}
	svc := pb.File_litevirt_v1_service_proto.Services().ByName("LiteVirt")
	for _, rpc := range firewallExtrasRPCs() {
		if svc.Methods().ByName(protoreflect.Name(rpc)) == nil {
			t.Errorf("RPC %s is missing", rpc)
		}
	}
}

// The scoped operation abort and the Ping bit that gates it keep their numbers;
// abort_scoped follows delete_force, the last PingResponse feature bit.
func TestProtoNumbers_ScopedOperationAbort(t *testing.T) {
	fields := []struct {
		msg  protoreflect.ProtoMessage
		num  protoreflect.FieldNumber
		name protoreflect.Name
	}{
		{&pb.AbortVMOperationRequest{}, 3, "operation_id"},
		{&pb.PingResponse{}, 12, "delete_force"},
		{&pb.PingResponse{}, 13, "abort_scoped"},
	}
	for _, f := range fields {
		md := f.msg.ProtoReflect().Descriptor()
		fd := md.Fields().ByNumber(f.num)
		if fd == nil || fd.Name() != f.name {
			t.Errorf("%s field %d is %v, want %s", md.FullName(), f.num, fd, f.name)
		}
	}
}
