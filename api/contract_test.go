package api_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

var file = automationv1.File_litevirt_automation_v1_automation_proto

func TestUnaryRPCContract(t *testing.T) {
	names := strings.Fields(`GetAutomationCapabilities EnsureOwner AcquireOwnerSession HandoffOwnerSession ResolveBinding ObserveResource SubmitCreateVM SubmitUpdateVM SubmitDeleteVM GetOperation ListByOwner AdoptResource TransferOwner`)
	svc := file.Services().ByName("Automation")
	if svc == nil || svc.Methods().Len() != len(names) {
		t.Fatal("Automation must expose exactly 13 approved RPCs")
	}
	for _, name := range names {
		m := svc.Methods().ByName(protoreflect.Name(name))
		if m == nil {
			t.Fatalf("missing RPC %s", name)
		}
		if string(m.FullName()) != "litevirt.automation.v1.Automation."+name || string(m.Input().FullName()) != "litevirt.automation.v1."+name+"Request" || string(m.Output().FullName()) != "litevirt.automation.v1."+name+"Response" || m.IsStreamingClient() || m.IsStreamingServer() {
			t.Errorf("invalid RPC shape %s", name)
		}
	}
}

// These literal reviewed allocations independently protect wire identities,
// expectations, and recovery evidence. Compatible additions remain permitted.
func TestReviewedFieldContract(t *testing.T) {
	contracts := map[string]string{
		"ReferenceScope":           "cluster_uid:1:string project_uid:2:string global:3:bool",
		"ScopedName":               "scope:1:ReferenceScope name:2:string",
		"ImageRef":                 "scope:1:ReferenceScope content_digest:2:string immutable_id:3:string display_name:4:string",
		"PoolRef":                  "scope:1:ReferenceScope immutable_id:2:string display_name:3:string",
		"NetworkRef":               "scope:1:ReferenceScope immutable_id:2:string display_name:3:string",
		"ImageInput":               "selector:1:ScopedName pinned:2:ImageRef",
		"PoolInput":                "selector:1:ScopedName pinned:2:PoolRef",
		"NetworkInput":             "selector:1:ScopedName pinned:2:NetworkRef",
		"HostRef":                  "cluster_uid:1:string host_uid:2:string display_name:3:string",
		"HostSelector":             "name:1:string pinned:2:HostRef",
		"VMPlacement":              "host_selector:1:HostSelector required_labels:2:map preferred_labels:3:map affinity:4:ResourceRef[] anti_affinity:5:ResourceRef[] max_per_host:6:uint32 policy:7:PlacementPolicy",
		"VMPlacementConfiguration": "pinned_host:1:HostRef required_labels:2:map preferred_labels:3:map affinity:4:ResourceRef[] anti_affinity:5:ResourceRef[] max_per_host:6:uint32 policy:7:PlacementPolicy",
		"VMDiskDesired":            "key:1:string size_bytes:2:uint64 pool:3:PoolInput image:4:ImageInput bus:5:DiskBus",
		"VMNICDesired":             "key:1:string network:2:NetworkInput model:3:NICModel mac:4:string? ipv4_cidr:5:string? ipv4_gateway:6:string? ipv6_cidr:7:string? ipv6_gateway:8:string?",
		"VMConfiguration":          "name:1:string cpu:2:uint32 memory_mib:3:uint64 labels:4:map placement:5:VMPlacementConfiguration image:6:ImageRef disks:7:VMDiskConfiguration[] nics:8:VMNICConfiguration[] bootstrap:9:BootstrapStatus requested_state:10:VMRequestedState max_cpu:11:uint32 memory_hotplug_max_mib:12:uint64",
		"VMDiskConfiguration":      "key:1:string size_bytes:2:uint64 pool:3:PoolRef image:4:ImageRef bus:5:DiskBus",
		"VMNICConfiguration":       "key:1:string network:2:NetworkRef model:3:NICModel mac:4:string ipv4_cidr:5:string ipv4_gateway:6:string ipv6_cidr:7:string ipv6_gateway:8:string",
		"BootstrapStatus":          "present:1:bool accepted:2:bool cleaned:3:bool receipt_id:4:string",
		"LabelSet":                 "values:1:map",
		"VMNICObservation":         "key:1:string interface_id:2:string network:3:NetworkRef mac:4:string ipv4_addresses:5:string[] ipv6_addresses:6:string[]",
		"VMDiskObservation":        "key:1:string artifact_id:2:string pool:3:PoolRef size_bytes:4:uint64",
		"RetainedArtifactRef":      "artifact_id:1:string pool:2:PoolRef former_resource:3:ResourceRef",
		"FieldViolation":           "field:1:string reason:2:string",
		"RetryAdvice":              "action:1:RetryAction retry_after:2:Duration safe_next_action:3:string",
		"Limits":                   "max_page_size:1:uint32 max_bootstrap_bytes:2:uint64 required_durable_voters:3:uint32 min_cpu:4:uint32 max_cpu:5:uint32 min_memory_mib:6:uint64 max_memory_mib:7:uint64 max_user_data_bytes:8:uint64 max_metadata_bytes:9:uint64 max_network_config_bytes:10:uint64",
		"UpdateSupport":            "field:1:UpdateField permitted_disruptions:2:DisruptionClass[]",

		"ResourceRef":                       "cluster_uid:1:string project_uid:2:string kind:3:string resource_uid:4:string",
		"OwnerRef":                          "project_uid:1:string owner_id:2:string",
		"OwnerSession":                      "owner:1:OwnerRef activation_generation:2:uint64 session_id:3:string",
		"BindingKey":                        "project_uid:1:string owner_id:2:string management_key:3:string",
		"BindingRef":                        "project_uid:1:string owner_id:2:string management_key:3:string creation_generation:4:uint64",
		"OperationRef":                      "operation_id:1:string minimum_sequence:2:uint64",
		"ReadCursor":                        "applied_sequence:1:uint64 resource_revision:2:string operation:3:OperationRef",
		"MutationIdentity":                  "request_id:1:string session:2:OwnerSession",
		"Binding":                           "ref:1:BindingRef presence:2:Presence resource:3:ResourceRef resource_revision:4:string operations:5:OperationRef[] conditions:6:Condition[] cursor:7:ReadCursor",
		"Owner":                             "ref:1:OwnerRef revision:2:string activation_generation:3:uint64",
		"GetAutomationCapabilitiesRequest":  "expected_cluster_uid:1:string?",
		"GetAutomationCapabilitiesResponse": "cluster_uid:1:string contract_version:2:string enforced_features:3:EnforcedFeature[] durability_mode:4:DurabilityMode limits:5:Limits supported_updates:6:UpdateSupport[] cursor:7:ReadCursor",
		"EnsureOwnerRequest":                "owner:1:OwnerRef request_id:2:string",
		"EnsureOwnerResponse":               "owner:1:Owner cursor:2:ReadCursor",
		"AcquireOwnerSessionRequest":        "owner:1:OwnerRef expected_activation_generation:2:uint64 session_id:3:string request_id:4:string",
		"AcquireOwnerSessionResponse":       "session:1:OwnerSession cursor:2:ReadCursor",
		"HandoffOwnerSessionRequest":        "current:1:OwnerSession successor_session_id:2:string request_id:3:string",
		"HandoffOwnerSessionResponse":       "session:1:OwnerSession cursor:2:ReadCursor",
		"ResolveBindingRequest":             "key:1:BindingKey minimum:2:ReadCursor",
		"ResolveBindingResponse":            "binding:1:Binding cursor:2:ReadCursor",
		"ObserveResourceRequest":            "resource:1:ResourceRef minimum:2:ReadCursor",
		"ObserveResourceResponse":           "observation:1:VMObservation cursor:2:ReadCursor",
		"SubmitCreateVMRequest":             "identity:1:MutationIdentity binding:2:BindingKey expected_generation:3:uint64 desired:4:VMDesired",
		"SubmitUpdateVMRequest":             "identity:1:MutationIdentity resource:2:ResourceRef expected_revision:3:string binding:4:BindingRef patch:5:VMPatch permitted_disruption:6:DisruptionClass",
		"SubmitDeleteVMRequest":             "identity:1:MutationIdentity resource:2:ResourceRef expected_revision:3:string binding:4:BindingRef disk_policy:5:DiskPolicy",
		"SubmitCreateVMResponse":            "operation:1:OperationRef resource:2:ResourceRef binding:3:BindingRef cursor:4:ReadCursor",
		"SubmitUpdateVMResponse":            "operation:1:OperationRef resource:2:ResourceRef binding:3:BindingRef cursor:4:ReadCursor",
		"SubmitDeleteVMResponse":            "operation:1:OperationRef resource:2:ResourceRef binding:3:BindingRef cursor:4:ReadCursor",
		"GetOperationRequest":               "operation:1:OperationRef request:2:OperationRequestLookup",
		"OperationRequestLookup":            "binding:1:BindingKey request_id:2:string creation_generation:3:uint64? method:4:string?",
		"GetOperationResponse":              "operation:1:Operation cursor:2:ReadCursor",
		"ListByOwnerRequest":                "owner:1:OwnerRef page_size:2:uint32 page_token:3:string include_retired:4:bool?",
		"ListByOwnerResponse":               "bindings:1:Binding[] operations:2:OperationRef[] next_page_token:3:string cursor:4:ReadCursor",
		"AdoptResourceRequest":              "identity:1:MutationIdentity resource:2:ResourceRef expected_revision:3:string target:4:BindingKey expected_target_generation:5:uint64",
		"TransferOwnerRequest":              "identity:1:MutationIdentity resource:2:ResourceRef expected_revision:3:string source:4:BindingRef target:5:BindingKey expected_target_generation:6:uint64 target_session:7:OwnerSession",
		"AdoptResourceResponse":             "operation:1:OperationRef resource:2:ResourceRef binding:3:BindingRef cursor:4:ReadCursor",
		"TransferOwnerResponse":             "operation:1:OperationRef resource:2:ResourceRef binding:3:BindingRef cursor:4:ReadCursor",
		"VMDesired":                         "name:1:string cpu:2:uint32 memory_mib:3:uint64 labels:4:map placement:5:VMPlacement image:6:ImageInput disks:7:VMDiskDesired[] nics:8:VMNICDesired[] bootstrap:9:BootstrapInput requested_state:10:VMRequestedState max_cpu:11:uint32? memory_hotplug_max_mib:12:uint64?",
		"VMPatch":                           "cpu:1:uint32? memory_mib:2:uint64? labels:3:LabelSet placement:4:VMPlacement",
		"BootstrapInput":                    "user_data:1:bytes? metadata:2:bytes? network_config:3:bytes?",
		"VMObservation":                     "resource:1:ResourceRef desired:2:VMConfiguration revision:3:string owner:4:OwnerRef binding:5:BindingRef runtime:6:VMRuntimeObservation conditions:7:Condition[] cursor:8:ReadCursor presence:9:Presence",
		"VMRuntimeObservation":              "state:1:VMState reporting_host:2:HostRef domain_uuid:3:string incarnation:4:string observed_at:5:Timestamp freshness:6:ObservationFreshness interfaces:7:VMNICObservation[] disks:8:VMDiskObservation[] cpu_actual:9:uint32 memory_actual_mib:10:uint64",
		"Operation":                         "ref:1:OperationRef binding:2:BindingRef resource:3:ResourceRef request_id:4:string kind:5:OperationKind state:6:OperationState resulting_revision:7:string conditions:8:Condition[] error:9:ErrorDetail artifacts:10:ArtifactDisposition[] accepted_at:11:Timestamp updated_at:12:Timestamp completed_at:13:Timestamp progress_compacted:14:bool retry:15:RetryAdvice outcome:16:OperationOutcome",
		"ArtifactDisposition":               "artifact_id:1:string resource:2:ResourceRef kind:3:ArtifactKind disposition:4:ArtifactState hosts:5:HostRef[] retained_ref:6:RetainedArtifactRef cleanup_pending:7:bool reason:8:string",
		"Condition":                         "type:1:string status:2:ConditionStatus reason:3:string message:4:string resource:5:ResourceRef next_action:6:string observed_at:7:Timestamp",
		"ErrorDetail":                       "code:1:ErrorCode message:2:string resource:3:ResourceRef binding:4:BindingRef operation:5:OperationRef retry:6:RetryAdvice field_violations:7:FieldViolation[]",
	}
	for name, fields := range contracts {
		t.Run(name, func(t *testing.T) {
			m := file.Messages().ByName(protoreflect.Name(name))
			if m == nil {
				t.Fatal("missing message")
			}
			for _, spec := range strings.Fields(fields) {
				p := strings.Split(spec, ":")
				f := m.Fields().ByName(protoreflect.Name(p[0]))
				if f == nil {
					t.Errorf("missing %s", p[0])
					continue
				}
				kind := f.Kind().String()
				if f.Message() != nil {
					kind = string(f.Message().Name())
				}
				if f.Enum() != nil {
					kind = string(f.Enum().Name())
				}
				if f.IsMap() {
					kind = "map"
				} else if f.IsList() {
					kind += "[]"
				} else if f.HasOptionalKeyword() {
					kind += "?"
				}
				if p[1] != fmt.Sprint(f.Number()) || p[2] != kind {
					t.Errorf("%s: got %d:%s want %s:%s", p[0], f.Number(), kind, p[1], p[2])
				}
			}
		})
	}
}

func TestRecoveryLookupNeedsNoSavedReceipt(t *testing.T) {
	m := file.Messages().ByName("GetOperationRequest")
	o := m.Oneofs().ByName("lookup")
	if o == nil || o.Fields().Len() != 2 || o.Fields().ByName("operation") == nil || o.Fields().ByName("request") == nil {
		t.Fatal("lookup must choose operation or binding+request")
	}
	in := &automationv1.GetOperationRequest{Lookup: &automationv1.GetOperationRequest_Request{Request: &automationv1.OperationRequestLookup{Binding: &automationv1.BindingKey{ProjectUid: "p", OwnerId: "o", ManagementKey: "k"}, RequestId: "lost-first-reply"}}}
	data, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := new(automationv1.GetOperationRequest)
	if err = proto.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
	if out.GetRequest().GetRequestId() != "lost-first-reply" || out.GetRequest().CreationGeneration != nil || out.GetOperation() != nil {
		t.Fatal("recovery incorrectly needs operation or generation")
	}
}

func TestExplicitEmptyAndAbsentRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
	}{
		{"VMPatch", []string{"cpu", "memory_mib", "labels", "placement"}},
		{"BootstrapInput", []string{"user_data", "metadata", "network_config"}},
		{"ListByOwnerRequest", []string{"include_retired"}},
		{"VMDesired", []string{"max_cpu", "memory_hotplug_max_mib"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := file.Messages().ByName(protoreflect.Name(tc.name))
			in := dynamicpb.NewMessage(m)
			for _, name := range tc.fields {
				f := m.Fields().ByName(protoreflect.Name(name))
				if !f.HasPresence() {
					t.Fatalf("%s loses presence", name)
				}
				in.Set(f, in.NewField(f))
			}
			b, err := proto.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			out := dynamicpb.NewMessage(m)
			if err = proto.Unmarshal(b, out); err != nil {
				t.Fatal(err)
			}
			for _, name := range tc.fields {
				f := m.Fields().ByName(protoreflect.Name(name))
				if !out.Has(f) {
					t.Errorf("explicit empty %s lost", name)
				}
			}
			absent := dynamicpb.NewMessage(m)
			for _, name := range tc.fields {
				if absent.Has(m.Fields().ByName(protoreflect.Name(name))) {
					t.Fatal("absent became present")
				}
			}
		})
	}
}

func TestPublicGraphHasNoInternalOrGenericPayload(t *testing.T) {
	allowed := map[string]bool{"google/protobuf/timestamp.proto": true, "google/protobuf/duration.proto": true}
	var walkFile func(protoreflect.FileDescriptor)
	seen := map[string]bool{}
	walkFile = func(f protoreflect.FileDescriptor) {
		if seen[f.Path()] {
			return
		}
		seen[f.Path()] = true
		if f.Package() != "litevirt.automation.v1" && !allowed[f.Path()] {
			t.Errorf("disallowed import %s", f.Path())
		}
		for i := 0; i < f.Imports().Len(); i++ {
			walkFile(f.Imports().Get(i).FileDescriptor)
		}
	}
	walkFile(file)
	for i := 0; i < file.Enums().Len(); i++ {
		e := file.Enums().Get(i)
		if e.Values().Get(0).Number() != 0 || !strings.HasSuffix(string(e.Values().Get(0).Name()), "_UNSPECIFIED") {
			t.Errorf("enum %s lacks unspecified zero", e.Name())
		}
	}
}

func TestOutputGraphCannotExposeBootstrap(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	var walk func(protoreflect.MessageDescriptor)
	walk = func(m protoreflect.MessageDescriptor) {
		if seen[m.FullName()] {
			return
		}
		seen[m.FullName()] = true
		if strings.Contains("|BootstrapInput|VMDesired|VMDiskDesired|VMNICDesired|ImageInput|PoolInput|NetworkInput|ScopedName|HostSelector|VMPlacement|", "|"+string(m.Name())+"|") {
			t.Errorf("input-only %s reachable from output", m.FullName())
		}
		for i := 0; i < m.Fields().Len(); i++ {
			f := m.Fields().Get(i)
			n := string(f.Name())
			for _, s := range []string{"user_data", "metadata", "network_config", "ciphertext", "secret", "digest", "equality", "private"} {
				if strings.Contains(n, s) && !(m.Name() == "ImageRef" && n == "content_digest") && !(m.Name() == "Limits" && f.Kind() == protoreflect.Uint64Kind && strings.HasPrefix(n, "max_") && strings.HasSuffix(n, "_bytes")) {
					t.Errorf("secret-bearing output field %s", f.FullName())
				}
			}
			if f.Kind() == protoreflect.BytesKind {
				t.Errorf("opaque bytes on output graph: %s", f.FullName())
			}
			if f.Message() != nil {
				walk(f.Message())
			}
		}
	}
	svc := file.Services().ByName("Automation")
	for i := 0; i < svc.Methods().Len(); i++ {
		walk(svc.Methods().Get(i).Output())
	}
}

func TestCompatibilityFixtureIsReadable(t *testing.T) {
	b, err := os.ReadFile("testdata/automation-v1.binpb")
	if err != nil {
		t.Fatal(err)
	}
	set := new(descriptorpb.FileDescriptorSet)
	if err = proto.Unmarshal(b, set); err != nil {
		t.Fatal(err)
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := files.FindFileByPath(file.Path())
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Package() != file.Package() || baseline.Services().ByName("Automation") == nil {
		t.Fatal("invalid compatibility fixture")
	}
}

func TestScopeAndInputSelectionAreExclusive(t *testing.T) {
	for _, tc := range []struct{ message, oneof, first, second string }{
		{"ReferenceScope", "scope", "project_uid", "global"},
		{"ImageInput", "source", "selector", "pinned"},
		{"PoolInput", "source", "selector", "pinned"},
		{"NetworkInput", "source", "selector", "pinned"},
		{"HostSelector", "selection", "name", "pinned"},
	} {
		m := file.Messages().ByName(protoreflect.Name(tc.message))
		o := m.Oneofs().ByName(protoreflect.Name(tc.oneof))
		if o == nil || o.Fields().Len() != 2 || o.Fields().ByName(protoreflect.Name(tc.first)) == nil || o.Fields().ByName(protoreflect.Name(tc.second)) == nil {
			t.Errorf("%s must select exactly one reference form", tc.message)
		}
	}
}

func TestWirePresenceAndPolicies(t *testing.T) {
	for enum, values := range map[string]string{
		"Presence":        "PRESENCE_UNSPECIFIED PRESENCE_PRESENT PRESENCE_ABSENT PRESENCE_RETIRED PRESENCE_UNCERTAIN",
		"DisruptionClass": "DISRUPTION_CLASS_UNSPECIFIED DISRUPTION_CLASS_LIVE DISRUPTION_CLASS_RESTART",
		"DiskPolicy":      "DISK_POLICY_UNSPECIFIED DISK_POLICY_DELETE DISK_POLICY_RETAIN",
	} {
		e := file.Enums().ByName(protoreflect.Name(enum))
		for n, name := range strings.Fields(values) {
			v := e.Values().ByName(protoreflect.Name(name))
			if v == nil || int(v.Number()) != n {
				t.Errorf("%s must retain wire value %d", name, n)
			}
		}
	}
	// Public bytes are restricted to the dedicated input type; no generic command
	// envelope can bypass typed contracts through opaque payloads.
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			m := ms.Get(i)
			for j := 0; j < m.Fields().Len(); j++ {
				f := m.Fields().Get(j)
				if f.Kind() == protoreflect.BytesKind && m.Name() != "BootstrapInput" {
					t.Errorf("unexpected opaque payload %s", f.FullName())
				}
				if f.IsMap() && (f.MapKey().Kind() != protoreflect.StringKind || f.MapValue().Kind() != protoreflect.StringKind) {
					t.Errorf("unexpected untyped map %s", f.FullName())
				}
			}
			walk(m.Messages())
		}
	}
	walk(file.Messages())
}

func TestPublicModuleAndJSONNames(t *testing.T) {
	opts := file.Options().(*descriptorpb.FileOptions)
	if opts.GetGoPackage() != "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1;automationv1" || file.Syntax() != protoreflect.Proto3 {
		t.Fatal("public package identity changed")
	}
	for i := 0; i < file.Messages().Len(); i++ {
		m := file.Messages().Get(i)
		for j := 0; j < m.Fields().Len(); j++ {
			f := m.Fields().Get(j)
			parts := strings.Split(string(f.Name()), "_")
			want := parts[0]
			for _, part := range parts[1:] {
				want += strings.ToUpper(part[:1]) + part[1:]
			}
			if f.JSONName() != want {
				t.Errorf("%s JSON name %s, want %s", f.FullName(), f.JSONName(), want)
			}
		}
	}
}
