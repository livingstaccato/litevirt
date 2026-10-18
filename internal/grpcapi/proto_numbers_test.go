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
		{&pb.UpdateVMRequest{}, 43, "nic_by_list_position"},
		{&pb.PingResponse{}, 14, "nic_list_position"},
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

// The live firmware migration RPCs' fields, messages and enums keep the
// numbers they were given. The numbers were checked free against the
// integration head and every open fork branch that adds proto.
func TestProtoNumbers_LiveFirmware(t *testing.T) {
	fields := []struct {
		msg  protoreflect.ProtoMessage
		num  protoreflect.FieldNumber
		name protoreflect.Name
	}{
		{&pb.FirmwareRuntime{}, 1, "libvirt"},
		{&pb.FirmwareRuntime{}, 2, "qemu"},
		{&pb.FirmwareRuntime{}, 3, "swtpm"},
		{&pb.FirmwareRuntime{}, 4, "libtpms"},
		{&pb.FirmwareRuntime{}, 5, "ovmf_fingerprint"},
		{&pb.FirmwareRuntime{}, 6, "live_firmware_enabled"},

		{&pb.FirmwareApplicability{}, 1, "tpm"},
		{&pb.FirmwareApplicability{}, 2, "uefi"},

		{&pb.TargetDomain{}, 1, "present"},
		{&pb.TargetDomain{}, 2, "state"},
		{&pb.TargetDomain{}, 3, "reason"},
		{&pb.TargetDomain{}, 4, "uuid"},

		{&pb.PrepareLiveFirmwareTargetRequest{}, 1, "vm_name"},
		{&pb.PrepareLiveFirmwareTargetRequest{}, 2, "uuid"},
		{&pb.PrepareLiveFirmwareTargetRequest{}, 3, "created_at"},
		{&pb.PrepareLiveFirmwareTargetRequest{}, 4, "attempt_id"},
		{&pb.PrepareLiveFirmwareTargetRequest{}, 5, "protocol_version"},
		{&pb.PrepareLiveFirmwareTargetRequest{}, 6, "src_runtime"},
		{&pb.PrepareLiveFirmwareTargetRequest{}, 7, "src_applicability"},
		{&pb.PrepareLiveFirmwareTargetRequest{}, 8, "source_domain_active"},
		{&pb.PrepareLiveFirmwareTargetRequest{}, 9, "nvram"},
		{&pb.PrepareLiveFirmwareTargetResponse{}, 1, "dst_runtime"},
		{&pb.PrepareLiveFirmwareTargetResponse{}, 2, "dst_applicability"},
		{&pb.PrepareLiveFirmwareTargetResponse{}, 3, "swtpm_absent"},
		{&pb.PrepareLiveFirmwareTargetResponse{}, 4, "target_domain"},

		{&pb.VerifyLiveFirmwareTargetRequest{}, 1, "vm_name"},
		{&pb.VerifyLiveFirmwareTargetRequest{}, 2, "uuid"},
		{&pb.VerifyLiveFirmwareTargetRequest{}, 3, "attempt_id"},
		{&pb.VerifyLiveFirmwareTargetRequest{}, 4, "src_permall_sha256"},
		{&pb.VerifyLiveFirmwareTargetResponse{}, 1, "verdict"},
		{&pb.VerifyLiveFirmwareTargetResponse{}, 2, "dst_permall_sha256"},
		{&pb.VerifyLiveFirmwareTargetResponse{}, 3, "target_domain"},
		{&pb.VerifyLiveFirmwareTargetResponse{}, 4, "detail"},

		{&pb.ReleaseLiveFirmwareTargetRequest{}, 1, "vm_name"},
		{&pb.ReleaseLiveFirmwareTargetRequest{}, 2, "uuid"},
		{&pb.ReleaseLiveFirmwareTargetRequest{}, 3, "attempt_id"},
		{&pb.ReleaseLiveFirmwareTargetRequest{}, 4, "src_nvram_sha256"},
		{&pb.ReleaseLiveFirmwareTargetRequest{}, 5, "nvram_final"},
		{&pb.ReleaseLiveFirmwareTargetRequest{}, 6, "created_at"},
		{&pb.ReleaseLiveFirmwareTargetResponse{}, 1, "nvram_sha256"},
		{&pb.ReleaseLiveFirmwareTargetResponse{}, 2, "nvram_confirmed"},
		{&pb.ReleaseLiveFirmwareTargetResponse{}, 3, "target_domain"},
		{&pb.ReleaseLiveFirmwareTargetResponse{}, 4, "verdict"},
		{&pb.ReleaseLiveFirmwareTargetResponse{}, 5, "detail"},

		{&pb.AbortLiveFirmwareTargetRequest{}, 1, "vm_name"},
		{&pb.AbortLiveFirmwareTargetRequest{}, 2, "uuid"},
		{&pb.AbortLiveFirmwareTargetRequest{}, 3, "created_at"},
		{&pb.AbortLiveFirmwareTargetRequest{}, 4, "attempt_id"},
		{&pb.AbortLiveFirmwareTargetRequest{}, 5, "mode"},
		{&pb.AbortLiveFirmwareTargetRequest{}, 6, "source_domain_active"},
		{&pb.AbortLiveFirmwareTargetRequest{}, 7, "created_stubs"},
		{&pb.AbortLiveFirmwareTargetResponse{}, 1, "target_domain"},
		{&pb.AbortLiveFirmwareTargetResponse{}, 2, "hold_state"},
		{&pb.AbortLiveFirmwareTargetResponse{}, 3, "refused"},
		{&pb.AbortLiveFirmwareTargetResponse{}, 4, "detail"},
	}
	for _, f := range fields {
		md := f.msg.ProtoReflect().Descriptor()
		fd := md.Fields().ByNumber(f.num)
		if fd == nil || fd.Name() != f.name {
			t.Errorf("%s field %d is %v, want %s", md.FullName(), f.num, fd, f.name)
		}
	}
	enums := []struct {
		ed   protoreflect.EnumDescriptor
		num  protoreflect.EnumNumber
		name protoreflect.Name
	}{
		{pb.FirmwareVerdict(0).Descriptor(), 0, "FIRMWARE_VERDICT_UNSPECIFIED"},
		{pb.FirmwareVerdict(0).Descriptor(), 1, "FIRMWARE_VERDICT_BAD_REQUEST"},
		{pb.FirmwareVerdict(0).Descriptor(), 2, "FIRMWARE_VERDICT_NOT_HELD"},
		{pb.FirmwareVerdict(0).Descriptor(), 3, "FIRMWARE_VERDICT_NOT_RUNNING"},
		{pb.FirmwareVerdict(0).Descriptor(), 4, "FIRMWARE_VERDICT_TARGET_RAN"},
		{pb.FirmwareVerdict(0).Descriptor(), 5, "FIRMWARE_VERDICT_MATCH"},
		{pb.FirmwareVerdict(0).Descriptor(), 6, "FIRMWARE_VERDICT_MISMATCH"},
		{pb.FirmwareAbortMode(0).Descriptor(), 0, "FIRMWARE_ABORT_MODE_UNSPECIFIED"},
		{pb.FirmwareAbortMode(0).Descriptor(), 1, "FIRMWARE_ABORT_MODE_PRE_CUTOVER"},
		{pb.FirmwareAbortMode(0).Descriptor(), 2, "FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED"},
	}
	for _, e := range enums {
		vd := e.ed.Values().ByNumber(e.num)
		if vd == nil || vd.Name() != e.name {
			t.Errorf("%s value %d is %v, want %s", e.ed.FullName(), e.num, vd, e.name)
		}
	}
	for _, ed := range []protoreflect.EnumDescriptor{pb.FirmwareVerdict(0).Descriptor(), pb.FirmwareAbortMode(0).Descriptor()} {
		n := 0
		for _, e := range enums {
			if e.ed == ed {
				n++
			}
		}
		if ed.Values().Len() != n {
			t.Errorf("%s has %d values, the table pins %d", ed.FullName(), ed.Values().Len(), n)
		}
	}
	svc := pb.File_litevirt_v1_service_proto.Services().ByName("LiteVirt")
	for _, rpc := range []protoreflect.Name{
		"PrepareLiveFirmwareTarget", "VerifyLiveFirmwareTarget",
		"ReleaseLiveFirmwareTarget", "AbortLiveFirmwareTarget",
		// lv doctor firmware-move (D2-18): the operator's RPC and the target's part.
		"FirmwareMoveDoctor", "FirmwareMoveDoctorTarget",
	} {
		m := svc.Methods().ByName(rpc)
		if m == nil {
			t.Errorf("RPC %s is missing", rpc)
			continue
		}
		if m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("RPC %s streams; it is unary", rpc)
		}
		if got, want := m.Input().Name(), rpc+"Request"; got != want {
			t.Errorf("RPC %s takes %s, want %s", rpc, got, want)
		}
		if got, want := m.Output().Name(), rpc+"Response"; got != want {
			t.Errorf("RPC %s returns %s, want %s", rpc, got, want)
		}
	}
}

// Every live firmware migration message survives a binary and a protojson
// round trip with every field set, and each of the four responses carries the
// target's domain (spec §14, I-7).
func TestProto_LiveFirmwareRoundTrip(t *testing.T) {
	rt := &pb.FirmwareRuntime{
		Libvirt: "10.0.0", Qemu: "8.2.2", Swtpm: "0.9.0", Libtpms: "0.9.3",
		OvmfFingerprint: "sha256:ab12", LiveFirmwareEnabled: true,
	}
	app := &pb.FirmwareApplicability{Tpm: true, Uefi: true}
	dom := &pb.TargetDomain{Present: true, State: "paused", Reason: "migration", Uuid: "6f1c2b3a-0000-4000-8000-000000000001"}
	msgs := []proto.Message{
		&pb.PrepareLiveFirmwareTargetRequest{
			VmName: "web", Uuid: dom.Uuid, CreatedAt: "2026-10-15T10:00:00Z", AttemptId: "att-1",
			ProtocolVersion: 1, SrcRuntime: rt, SrcApplicability: app, SourceDomainActive: true,
			Nvram: []byte{0x00, 0xff, 0x10},
		},
		&pb.PrepareLiveFirmwareTargetResponse{DstRuntime: rt, DstApplicability: app, SwtpmAbsent: true, TargetDomain: dom},
		&pb.VerifyLiveFirmwareTargetRequest{VmName: "web", Uuid: dom.Uuid, AttemptId: "att-1", SrcPermallSha256: "aa"},
		&pb.VerifyLiveFirmwareTargetResponse{
			Verdict: pb.FirmwareVerdict_FIRMWARE_VERDICT_MISMATCH, DstPermallSha256: "bb", TargetDomain: dom, Detail: "permall differs",
		},
		&pb.ReleaseLiveFirmwareTargetRequest{
			VmName: "web", Uuid: dom.Uuid, AttemptId: "att-1", SrcNvramSha256: "cc",
			NvramFinal: []byte{0x01, 0x02}, CreatedAt: "2026-10-15T10:00:00Z",
		},
		&pb.ReleaseLiveFirmwareTargetResponse{
			NvramSha256: "cc", NvramConfirmed: true, TargetDomain: dom,
			Verdict: pb.FirmwareVerdict_FIRMWARE_VERDICT_TARGET_RAN, Detail: "running",
		},
		&pb.AbortLiveFirmwareTargetRequest{
			VmName: "web", Uuid: dom.Uuid, CreatedAt: "2026-10-15T10:00:00Z", AttemptId: "att-1",
			Mode: pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_DISCARD_UNVERIFIED, SourceDomainActive: true,
			CreatedStubs: []string{"/var/lib/litevirt/disks/web-0.qcow2"},
		},
		&pb.AbortLiveFirmwareTargetResponse{TargetDomain: dom, HoldState: "prepared", Refused: true, Detail: "domain defined"},
	}
	for _, in := range msgs {
		// Every field is set, so a field the generator dropped or a setter
		// that wrote the wrong field shows as an unpopulated one here.
		md := in.ProtoReflect().Descriptor()
		for i := 0; i < md.Fields().Len(); i++ {
			if fd := md.Fields().Get(i); !in.ProtoReflect().Has(fd) {
				t.Errorf("%s.%s is not set in the fixture", md.Name(), fd.Name())
			}
		}
		b, err := proto.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %s: %v", md.Name(), err)
		}
		bin := in.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(b, bin); err != nil {
			t.Fatalf("unmarshal %s: %v", md.Name(), err)
		}
		if !proto.Equal(in, bin) {
			t.Errorf("%s binary round trip: got %v, want %v", md.Name(), bin, in)
		}
		js, err := protojson.Marshal(in)
		if err != nil {
			t.Fatalf("protojson marshal %s: %v", md.Name(), err)
		}
		jo := in.ProtoReflect().New().Interface()
		if err := protojson.Unmarshal(js, jo); err != nil {
			t.Fatalf("protojson unmarshal %s: %v", md.Name(), err)
		}
		if !proto.Equal(in, jo) {
			t.Errorf("%s protojson round trip: got %v, want %v", md.Name(), jo, in)
		}
		if strings.HasSuffix(string(md.Name()), "Response") {
			fd := md.Fields().ByName("target_domain")
			if fd == nil || fd.Message() == nil || fd.Message().Name() != "TargetDomain" {
				t.Errorf("%s does not carry a TargetDomain", md.Name())
			}
		}
	}

	// The zero verdict and abort mode are UNSPECIFIED: an empty response (an
	// older peer, a dropped field) never reads as MATCH or as a mode.
	if v := (&pb.VerifyLiveFirmwareTargetResponse{}).GetVerdict(); v != pb.FirmwareVerdict_FIRMWARE_VERDICT_UNSPECIFIED {
		t.Errorf("zero verdict = %v, want UNSPECIFIED", v)
	}
	if m := (&pb.AbortLiveFirmwareTargetRequest{}).GetMode(); m != pb.FirmwareAbortMode_FIRMWARE_ABORT_MODE_UNSPECIFIED {
		t.Errorf("zero abort mode = %v, want UNSPECIFIED", m)
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
