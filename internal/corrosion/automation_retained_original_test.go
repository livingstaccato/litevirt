package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestRetainedOriginalAggregatePreimage(t *testing.T) {
	producer, r, q, _, _ := receiverFixture(t)
	a, err := r.Begin(context.Background(), q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := strings.Repeat("a", 64)
	// This tests the consumed format against a real original receiver binding.
	// Synthetic metadata here never represents an audited aggregate or import.
	member := a.request.Sources[0]
	audit := sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(a.id), []byte(member.Name), []byte(d), []byte(d))
	publication, _, err := producer.client.readSourcePublication(context.Background(), 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	roster := []aggregateRosterEntry{{member.Name, member.Incarnation, audit, d, d, publication.manifest.Cut.ID, d}}
	rawRoster, _ := json.Marshal(roster)
	local := sourceDigest([]byte("litevirt/local-audit/v1"), []byte(a.id), []byte(d))
	coverage := sourceDigest([]byte("litevirt/aggregate-coverage/v1"), []byte(d), rawRoster)
	h := retainedAggregateHeader{1, "automation-original-aggregate", retainedLocalLayoutDigest(), a.id, a.request.Job, a.request.Revision,
		a.request.Target, a.facts.Incarnation, 1, sourceDigest(a.binding), 2, d, local, d, d, AutomationPrefix{}, roster, coverage}
	raw, _ := json.Marshal(h)
	decoded, err := decodeRetainedHeader(raw)
	if err != nil {
		t.Fatalf("canonical original header refused: %v", err)
	}
	p, id, err := decoded.originalBinding(a.binding)
	if err != nil {
		t.Fatalf("exact original aggregate preimage refused: %v", err)
	}
	head, _ := json.Marshal(h.Head)
	want := sourceDigest([]byte("litevirt/receiver-aggregate/v1"), []byte(a.id), a.binding, []byte(local), []byte(d), head, []byte(coverage), rawRoster)
	if id != want || p.id != a.id {
		t.Fatal("original C preimage changed")
	}
	for name, mutate := range map[string]func(*retainedAggregateHeader){
		"attempt":          func(v *retainedAggregateHeader) { v.Attempt = d },
		"job":              func(v *retainedAggregateHeader) { v.Job = "other" },
		"revision":         func(v *retainedAggregateHeader) { v.Revision++ },
		"host":             func(v *retainedAggregateHeader) { v.Host = "other" },
		"incarnation":      func(v *retainedAggregateHeader) { v.Incarnation = "other" },
		"binding-digest":   func(v *retainedAggregateHeader) { v.BindingDigest = d },
		"local-id":         func(v *retainedAggregateHeader) { v.LocalID = d },
		"local-dependency": func(v *retainedAggregateHeader) { v.LocalDependency = strings.Repeat("b", 64) },
		"coverage":         func(v *retainedAggregateHeader) { v.Coverage = d },
		"roster-audit": func(v *retainedAggregateHeader) {
			v.Roster = append([]aggregateRosterEntry(nil), v.Roster...)
			v.Roster[0].Audit = d
		},
		"roster-source": func(v *retainedAggregateHeader) {
			v.Roster = append([]aggregateRosterEntry(nil), v.Roster...)
			v.Roster[0].Source = "other"
		},
		"roster-empty": func(v *retainedAggregateHeader) { v.Roster = nil },
	} {
		t.Run(name, func(t *testing.T) {
			v := h
			mutate(&v)
			raw, _ := json.Marshal(v)
			decoded, err := decodeRetainedHeader(raw)
			if err == nil {
				_, _, err = decoded.originalBinding(a.binding)
			}
			if err == nil {
				t.Fatal("spliced original preimage accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*retainedAggregateHeader){
		"layout":         func(v *retainedAggregateHeader) { v.LayoutDigest = d },
		"version":        func(v *retainedAggregateHeader) { v.Version++ },
		"purpose":        func(v *retainedAggregateHeader) { v.Purpose = "other" },
		"binding-object": func(v *retainedAggregateHeader) { v.BindingObject = 0 },
		"local-object":   func(v *retainedAggregateHeader) { v.LocalRowsObject = v.BindingObject },
		"head-empty":     func(v *retainedAggregateHeader) { v.Head.Digest = d },
	} {
		t.Run(name, func(t *testing.T) {
			v := h
			mutate(&v)
			raw, _ := json.Marshal(v)
			if _, err := decodeRetainedHeader(raw); err == nil {
				t.Fatal("unsupported original header accepted")
			}
		})
	}
}

func TestRetainedOriginalWholeElectorate(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 5, Sources: 3})
	before := receiverActive(t, f.local.c)
	for _, n := range []int{3, 2} {
		t.Run(fmt.Sprintf("original-%d-of-five", n), func(t *testing.T) {
			// Consumed original-binding metadata, not a produced import or live attempt.
			// Membership and the complete five-voter denominator are genuinely chosen.
			var binding receiverAttemptBinding
			if err := json.Unmarshal(f.attempt.binding, &binding); err != nil {
				t.Fatal(err)
			}
			binding.Intent.Sources = binding.Intent.Sources[:n]
			raw, _ := json.Marshal(binding)
			id := sourceDigest([]byte("litevirt/receiver-attempt/v1"), raw)
			d := strings.Repeat("a", 64)
			h := retainedAggregateHeader{Version: 1, Purpose: "automation-original-aggregate", LayoutDigest: retainedLocalLayoutDigest(), Attempt: id, Job: binding.Intent.Job, Revision: binding.Intent.Revision, Host: binding.Intent.Target, Incarnation: binding.Facts.Incarnation, BindingObject: 1, BindingDigest: sourceDigest(raw), LocalRowsObject: 2, LocalInventoryDigest: d, LocalDependency: d, LocalCoverage: d}
			h.LocalID = sourceDigest([]byte("litevirt/local-audit/v1"), []byte(id), []byte(d))
			for i, m := range binding.Intent.Sources {
				h.Roster = append(h.Roster, aggregateRosterEntry{m.Name, m.Incarnation, sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(id), []byte(m.Name), []byte(f.requests[i].Publication), []byte(d)), f.requests[i].Publication, d, strings.Repeat("a", 32), d})
			}
			roster, _ := json.Marshal(h.Roster)
			h.Coverage = sourceDigest([]byte("litevirt/aggregate-coverage/v1"), []byte(d), roster)
			header, _ := json.Marshal(h)
			decoded, err := decodeRetainedHeader(header)
			if err != nil {
				t.Fatal("canonical hostile header setup", err)
			}
			_, _, err = decoded.originalBinding(raw)
			if n == 3 && err != nil {
				t.Fatal("complete three-of-five original binding refused", err)
			}
			if n == 2 && err == nil {
				t.Fatal("two-of-five retained original counted as complete majority")
			}
			if receiverActive(t, f.local.c) != before {
				t.Fatal("retained whole-electorate check changed ACTIVE")
			}
		})
	}
}

func TestRetainedOriginal83HeaderLayoutBinding(t *testing.T) {
	producer, r, q, _, _ := receiverFixture(t)
	_ = producer
	a, err := r.Begin(context.Background(), q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A minimal canonical header uses a real original binding; this is not a
	// proof that its synthetic empty aggregate is accepted by full reconstruction.
	d := strings.Repeat("a", 64)
	member := a.request.Sources[0]
	audit := sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(a.id), []byte(member.Name), []byte(d), []byte(d))
	h := retainedAggregateHeader{Version: 1, Purpose: "automation-original-aggregate", LayoutDigest: retainedLocalLayout83Digest(), Attempt: a.id, Job: a.request.Job, Revision: a.request.Revision, Host: a.request.Target, Incarnation: a.facts.Incarnation, BindingObject: 1, BindingDigest: sourceDigest(a.binding), LocalRowsObject: 2, LocalInventoryDigest: d, LocalID: d, LocalDependency: d, LocalCoverage: d, Coverage: d, Roster: []aggregateRosterEntry{{Source: member.Name, Incarnation: member.Incarnation, Audit: audit, Publication: d, Cut: "0123456789abcdef0123456789abcdef", Root: d, Coverage: d}}}
	raw, _ := json.Marshal(h)
	if _, err := decodeRetainedHeader(raw); err != nil {
		t.Fatal("RETAINED83_HEADER_REFUSED", err)
	}
	// Layout binding is checked before consulting scratch/current evidence.
	descriptor := retainedDescriptorInput("local")
	descriptor.OriginalIdentity = h.LocalID
	descriptor.Source = h.Host
	descriptor.Incarnation = h.Incarnation
	err = r.client.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		_, err := auditRetainedLocal(context.Background(), tx, receiverAuditContext{a.id, a.request, a.facts}, h, retainedFrameAddress{}, descriptor, retainedDirectoryReader{}, "unused")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "retained local semantic context differs") {
		t.Fatal("RETAINED83_MIXED_HEADER_OBJECT_ACCEPTED", err)
	}
}

func TestRetainedOriginal83SchemaLayoutMismatch(t *testing.T) {
	for _, tc := range []struct {
		layout string
		schema int64
	}{{retainedLocalLayout83Digest(), 84}, {retainedLocalLayout83Digest(), 85}, {retainedLocalLayout83Digest(), 86}, {retainedLocalLayoutDigest(), 83}} {
		observation := aggregateLocalObservation{retained: true, layoutDigest: tc.layout}
		err := observation.observe(&aggregateLocalAudit{}, 15, 1, Row{Columns: []string{"id", "version"}, Values: []any{int64(1), tc.schema}})
		if err == nil || !strings.Contains(err.Error(), "schema/layout differs") {
			t.Fatal("RETAINED83_SCHEMA_LAYOUT_MISMATCH_ACCEPTED", err)
		}
	}
}

// Old84/85 private33 frames cannot acquire the current37 section offsets.
// Public archived descriptors remain supported; no private compatibility
// adapter is implied by that public provenance.
func TestRetainedOriginal84And85SharedLayout(t *testing.T) {
	for _, version := range []int64{84, 85} {
		t.Run(fmt.Sprintf("schema%d", version), func(t *testing.T) {
			observation := aggregateLocalObservation{retained: true, layoutDigest: retainedLocalLayoutDigest()}
			if err := observation.observe(&aggregateLocalAudit{}, 15, 1, Row{Columns: []string{"id", "version"}, Values: []any{int64(1), version}}); err == nil || !strings.Contains(err.Error(), "schema/layout differs") {
				t.Fatal("old private33 accepted under current37 offsets", version, err)
			}
			if !supportedAutomationCutDescriptor(int(version), 1) {
				t.Fatal("archived public descriptor lost", version)
			}
		})
	}
}

func TestRetainedOriginal85Private33CannotUseExecution37Offsets(t *testing.T) {
	prior := automationExecutionArchived85PrivateLayoutForTest()
	if len(prior) != 33 || len(aggregateLocalTables()) != 38 {
		t.Fatal("private layout inventory changed unexpectedly")
	}
	digest := retainedLocalLayoutDigestFor(prior)
	if digest != "09e38c2616d9155ed46e134be62b051aaef50a549c538b11c644040f4e710fec" || digest == retainedLocalLayoutDigest() {
		t.Fatal("literal old33 layout identity changed")
	}
	admitted, err := retainedLocalTablesForDigest(digest)
	if err != nil || len(admitted) != 33 {
		t.Fatal("literal old33 dispatch refused", err)
	}
	for i, d := range prior {
		if admitted[i] != d {
			t.Fatal("old33 descriptor changed", i)
		}
	}
	for _, version := range []int64{84, 85} {
		observation := aggregateLocalObservation{retained: true, layoutDigest: digest}
		if err := observation.observe(&aggregateLocalAudit{}, 15, 1, Row{Columns: []string{"id", "version"}, Values: []any{int64(1), version}}); err != nil {
			t.Fatal("literal old33 schema refused", version, err)
		}
	}
	observation := aggregateLocalObservation{retained: true, layoutDigest: digest}
	if err := observation.observe(&aggregateLocalAudit{}, 15, 1, Row{Columns: []string{"id", "version"}, Values: []any{int64(1), int64(86)}}); err == nil {
		t.Fatal("old33 accepted current86 meaning")
	}
}

// Frozen literal inventory copied from accepted signed628 genuine85 evidence.
func automationExecutionArchived85PrivateLayoutForTest() []aggregateLocalTable {
	return []aggregateLocalTable{
		{"local_recovery_claims", "target_kind,target_name,owner_epoch,attempt,promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,\n\taccepted_nonce, value_json, value_digest, accept_json, config_generation,updated_at", "target_kind,target_name,owner_epoch,attempt", "ttiiitbitbtttit", false},
		{"local_incarnation_claims", "target_kind,target_name,incarnation,owner_epoch,attempt,promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,\n\taccepted_nonce, value_json, value_digest, accept_json, config_generation,updated_at", "target_kind,target_name,incarnation,owner_epoch,attempt", "tttiiitbitbtttit", false},
		{"local_automation_history", "sequence,digest,value_json,certificate,receipt_json,anchor_sequence", "sequence", "itttti", false},
		{"local_automation_anchors", "sequence,digest,generation,members_hash,certificate", "sequence", "ititt", false},
		{"local_automation_requests", "scope,request_id,identity,receipt_json,operation_id", "scope,request_id", "ttbtt", false},
		{"local_automation_authority", "id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance", "id", "iittttt", false},
		{"local_voter_adoption", "generation,imported_from,adopted_at", "generation", "itt", false},
		{"local_voter_seals", "generation,reason,sealed_at", "generation", "itt", false},
		{"voter_configs", "generation,members_json,members_hash,change,certificate,created_by,created_at,deleted_at,updated_at", "generation", "ittttttTt", false},
		{"local_automation_prefix", "id,cluster_uid,sequence,digest", "id", "itit", false},
		{"local_voter_incarnation", "id,incarnation,created_at", "id", "itt", false},
		{"local_automation_recovery", "id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate", "id", "iititititt", false},
		{"local_automation_staging", "sequence,digest,value_json,certificate", "sequence", "ittt", false},
		{"reseed_in_progress", "id,started_at,source", "id", "itt", false},
		{"reseed_generation", "id,generation", "id", "ii", false},
		{"schema_state", "id,version,updated_at", "id", "iit", false},
		{"local_automation_cuts", "id,generation,incarnation,metadata,root", "id", "titbt", false},
		{"local_automation_cut_records", "cut_id,section,ordinal,record", "cut_id,section,ordinal", "tiib", false},
		{"local_automation_identities", "stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired", "stage,uid", "tttttttii", true},
		{"local_automation_aliases", "stage,cluster_uid,project_scope,kind,alias,uid,generation", "stage,cluster_uid,project_scope,kind,alias", "tttttti", true},
		{"local_automation_owners", "stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation", "stage,cluster_uid,project_uid,owner_id", "ttttttti", true},
		{"local_automation_semantic_heads", "stage,cluster_uid,sequence,digest", "stage", "ttit", true},
		{"local_automation_resources", "stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence", "stage,uid", "tttttttttititti", true},
		{"local_automation_names", "stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id", "stage,cluster_uid,name", "ttttitt", true},
		{"local_automation_bindings", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation,resource_uid,operation_id,revision,retired", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation", "tttttittti", true},
		{"local_automation_admissions", "stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json", "stage,operation_id", "tttttttttttiiit", true},
		{"local_automation_key_epochs", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,equality_epoch,predecessor_activation_sequence,activation_sequence", "stage,cluster_uid,recipient_epoch", "tttittii", true},
		{"local_automation_key_recipients", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence", "stage,cluster_uid,recipient_epoch,host", "tttittitttttttti", true},
		{"local_automation_payload_wrappings", "stage,cluster_uid,operation_id,payload_id,admission_sequence,wrapping_sequence,wrapping_digest,recipient_epoch,membership_generation,config_digest", "stage,cluster_uid,operation_id,wrapping_sequence", "ttttiittit", true},
		{"local_automation_target_operations", "stage,cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json", "stage,cluster_uid,operation_id", "tttttttttittt", true},
		{"local_automation_target_reservations", "stage,cluster_uid,target_key,operation_id,sequence", "stage,cluster_uid,target_key", "tttti", true},
		{"local_automation_lifetimes", "kind,name,witness,origin,retired,valid", "kind,name,witness", "ttttii", false},
		{"local_automation_credential_issuance", "kind,credential_id,username,witness,principal_uid,cluster_uid,valid", "kind,credential_id", "tttttti", false},
	}
}

// Independently frozen current86 inventory: old33 common prefix, four exact
// reviewed execution descriptors, then the original observation suffix.
func automationExecutionCurrent86PrivateLayoutForTest() []aggregateLocalTable {
	return []aggregateLocalTable{
		{"local_recovery_claims", "target_kind,target_name,owner_epoch,attempt,promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,\n\taccepted_nonce, value_json, value_digest, accept_json, config_generation,updated_at", "target_kind,target_name,owner_epoch,attempt", "ttiiitbitbtttit", false},
		{"local_incarnation_claims", "target_kind,target_name,incarnation,owner_epoch,attempt,promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,\n\taccepted_nonce, value_json, value_digest, accept_json, config_generation,updated_at", "target_kind,target_name,incarnation,owner_epoch,attempt", "tttiiitbitbtttit", false},
		{"local_automation_history", "sequence,digest,value_json,certificate,receipt_json,anchor_sequence", "sequence", "itttti", false},
		{"local_automation_anchors", "sequence,digest,generation,members_hash,certificate", "sequence", "ititt", false},
		{"local_automation_requests", "scope,request_id,identity,receipt_json,operation_id", "scope,request_id", "ttbtt", false},
		{"local_automation_authority", "id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance", "id", "iittttt", false},
		{"local_voter_adoption", "generation,imported_from,adopted_at", "generation", "itt", false},
		{"local_voter_seals", "generation,reason,sealed_at", "generation", "itt", false},
		{"voter_configs", "generation,members_json,members_hash,change,certificate,created_by,created_at,deleted_at,updated_at", "generation", "ittttttTt", false},
		{"local_automation_prefix", "id,cluster_uid,sequence,digest", "id", "itit", false},
		{"local_voter_incarnation", "id,incarnation,created_at", "id", "itt", false},
		{"local_automation_recovery", "id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate", "id", "iititititt", false},
		{"local_automation_staging", "sequence,digest,value_json,certificate", "sequence", "ittt", false},
		{"reseed_in_progress", "id,started_at,source", "id", "itt", false},
		{"reseed_generation", "id,generation", "id", "ii", false},
		{"schema_state", "id,version,updated_at", "id", "iit", false},
		{"local_automation_cuts", "id,generation,incarnation,metadata,root", "id", "titbt", false},
		{"local_automation_cut_records", "cut_id,section,ordinal,record", "cut_id,section,ordinal", "tiib", false},
		{"local_automation_identities", "stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired", "stage,uid", "tttttttii", true},
		{"local_automation_aliases", "stage,cluster_uid,project_scope,kind,alias,uid,generation", "stage,cluster_uid,project_scope,kind,alias", "tttttti", true},
		{"local_automation_owners", "stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation", "stage,cluster_uid,project_uid,owner_id", "ttttttti", true},
		{"local_automation_semantic_heads", "stage,cluster_uid,sequence,digest", "stage", "ttit", true},
		{"local_automation_resources", "stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence", "stage,uid", "tttttttttititti", true},
		{"local_automation_names", "stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id", "stage,cluster_uid,name", "ttttitt", true},
		{"local_automation_bindings", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation,resource_uid,operation_id,revision,retired", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation", "tttttittti", true},
		{"local_automation_admissions", "stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json", "stage,operation_id", "tttttttttttiiit", true},
		{"local_automation_key_epochs", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,equality_epoch,predecessor_activation_sequence,activation_sequence", "stage,cluster_uid,recipient_epoch", "tttittii", true},
		{"local_automation_key_recipients", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence", "stage,cluster_uid,recipient_epoch,host", "tttittitttttttti", true},
		{"local_automation_payload_wrappings", "stage,cluster_uid,operation_id,payload_id,admission_sequence,wrapping_sequence,wrapping_digest,recipient_epoch,membership_generation,config_digest", "stage,cluster_uid,operation_id,wrapping_sequence", "ttttiittit", true},
		{"local_automation_target_operations", "stage,cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json", "stage,cluster_uid,operation_id", "tttttttttittt", true},
		{"local_automation_target_reservations", "stage,cluster_uid,target_key,operation_id,sequence", "stage,cluster_uid,target_key", "tttti", true},
		{"local_automation_executors", "stage,cluster_uid,operation_id,resource_uid,executor_generation,grant_sequence,grant_digest,admission_sequence,admission_digest,grant_json", "stage,cluster_uid,operation_id", "ttttiititt", true},
		{"local_automation_execution_progress", "stage,cluster_uid,operation_id,resource_uid,applied_sequence,progress_json", "stage,cluster_uid,operation_id", "ttttit", true},
		{"local_automation_execution_artifacts", "stage,cluster_uid,operation_id,artifact_id,resource_uid,artifact_key,artifact_kind,backend,object_id,applied_sequence,artifact_json", "stage,cluster_uid,operation_id,artifact_id", "tttttttttit", true},
		{"local_automation_execution_terminals", "stage,cluster_uid,operation_id,resource_uid,applied_sequence,terminal_json", "stage,cluster_uid,operation_id", "ttttit", true},
		{"local_automation_lifetimes", "kind,name,witness,origin,retired,valid", "kind,name,witness", "ttttii", false},
		{"local_automation_credential_issuance", "kind,credential_id,username,witness,principal_uid,cluster_uid,valid", "kind,credential_id", "tttttti", false},
	}
}
