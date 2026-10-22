package corrosion

import "testing"

// appendOnlyLedger is every ADD COLUMN unit of the schema ledger, in
// schemaMigrations order: its positional ID and its schema version.
//
// A unit's ID is its INDEX in schemaMigrations ("a%03d_<table>_<col>", see
// init in schema.go), and InitSchema refuses to start on a database whose
// applied_migrations holds that ID with another checksum ("checksum drift").
// So once any database has applied the list, an entry inserted, moved or
// removed shifts the IDs after it and every such node stops starting. New
// ALTERs go at the END of schemaMigrations (with their alterVersions entry at
// the end too), whatever their version number; then append them here.
var appendOnlyLedger = []struct {
	id      string
	version int
}{
	{"a000_host_pci_devices_pcie_root_port", 1},
	{"a001_host_pci_devices_pcie_bridge", 1},
	{"a002_host_pci_devices_link_clique", 1},
	{"a003_host_pci_devices_link_peers", 1},
	{"a004_vm_disks_target_dev", 1},
	{"a005_image_hosts_progress_pct", 1},
	{"a006_hosts_version", 1},
	{"a007_lb_configs_ports", 1},
	{"a008_lb_configs_stack_name", 1},
	{"a009_hosts_role", 1},
	{"a010_users_realm", 2},
	{"a011_users_display_name", 2},
	{"a012_users_email", 2},
	{"a013_tokens_scope_paths", 2},
	{"a014_vm_interfaces_security_groups", 4},
	{"a015_hosts_region", 6},
	{"a016_audit_log_prev_hash", 8},
	{"a017_audit_log_content_hash", 8},
	{"a018_vms_project", 9},
	{"a019_backup_schedules_pool_name", 10},
	{"a020_storage_pools_options", 11},
	{"a021_backup_schedules_scope", 12},
	{"a022_backup_schedules_project_name", 12},
	{"a023_user_2fa_last_step", 15},
	{"a024_vms_is_template", 16},
	{"a025_vm_disks_backing_disk", 16},
	{"a026_backup_schedules_type", 17},
	{"a027_backup_schedules_target_pool", 17},
	{"a028_backup_schedules_target_host", 17},
	{"a029_backup_schedules_keep_replicas", 17},
	{"a030_backup_schedules_incremental", 18},
	{"a031_backup_schedules_auto_promote", 18},
	{"a032_backup_schedules_last_checkpoint", 18},
	{"a033_snapshots_type", 19},
	{"a034_snapshots_vmstate_path", 19},
	{"a035_snapshots_vmstate_size_bytes", 19},
	{"a036_containers_restart_policy", 24},
	{"a037_containers_state_detail", 24},
	{"a038_containers_project", 25},
	{"a039_containers_is_template", 28},
	{"a040_containers_on_host_failure", 28},
	{"a041_tokens_updated_at", 29},
	{"a042_lb_backends_deleted_at", 29},
	{"a043_hosts_schema_version", 30},
	{"a044_lb_configs_generation", 31},
	{"a045_lb_backends_generation", 31},
	{"a046_user_2fa_deleted_at", 32},
	{"a047_user_2fa_epoch", 32},
	{"a048_recovery_codes_set_id", 32},
	{"a049_recovery_codes_updated_at", 32},
	{"a050_recovery_codes_deleted_at", 32},
	{"a051_containers_create_spec", 34},
	{"a052_containers_relocate_token", 34},
	{"a053_ip_allocations_owner_kind", 36},
	{"a054_ip_allocations_owner_host", 36},
	{"a055_networks_project", 37},
	{"a056_storage_pools_project", 37},
	{"a057_volumes_project", 37},
	{"a058_vms_pending_action_id", 38},
	{"a059_vms_vm_owner_epoch", 41},
	{"a060_vms_spec_generation", 41},
	{"a061_vms_active_operation_id", 41},
	{"a062_vm_disks_bus", 42},
	{"a063_vm_disks_device_kind", 42},
	{"a064_vm_disks_delete_with_vm", 42},
	{"a065_vm_disks_controller_model", 42},
	{"a066_vms_hardware_adoption_state", 42},
	{"a067_vms_hardware_adoption_error", 42},
	{"a068_hosts_cpu_overcommit", 43},
	{"a069_hosts_mem_overcommit", 43},
	{"a070_hosts_cpu_reserve", 43},
	{"a071_hosts_mem_reserve_mib", 43},
	{"a072_containers_owner_epoch", 44},
	{"a073_containers_spec_generation", 44},
	{"a074_containers_active_operation_id", 44},
	{"a075_hosts_capacity_policy_hash", 44},
	{"a076_notification_routes_subject_pattern", 44},
	{"a077_notification_routes_project", 44},
	{"a078_audit_log_key_id", 45},
	{"a079_audit_log_signature", 45},
	{"a080_audit_log_seq", 45},
	{"a081_hosts_isolation_epoch", 49},
	{"a082_hosts_isolation_reason", 49},
	{"a083_ip_allocations_netbox_ip_id", 51},
	{"a084_ip_allocations_netbox_prefix_id", 51},
	{"a085_netbox_bindings_netbox_cluster", 51},
	{"a086_runtime_action_proofs_lease_term", 53},
	{"a087_runtime_action_proofs_lease_key", 54},
	{"a088_runtime_action_proofs_claim_certificate", 60},
	{"a089_host_fence_credentials_after_retirement", 68},
	{"a090_hosts_incarnation", 69},
	{"a091_security_groups_project", 70},
	{"a092_projects_incarnation", 71},
	{"a093_local_automation_receiver_current_established_inventory", 82},
	{"a094_tokens_user_created_at", schemaVersionTokenUserIncarnation},
	{"a095_local_automation_credential_issuance_proof_mode", 89},
	{"a096_local_automation_credential_issuance_identity_generation", 89},
	{"a097_local_automation_credential_issuance_original_witness", 89},
	{"a098_local_automation_credential_issuance_parent_kind", 89},
	{"a099_local_automation_credential_issuance_parent_alias", 89},
	{"a100_local_automation_credential_issuance_parent_realm", 89},
	{"a101_local_automation_credential_issuance_parent_birth", 89},
}

const appendOnlyRule = "schemaMigrations is append-only: add new ALTERs at the end; never reorder"

// TestSchemaMigrations_AreAppendOnlyNeverReordered pins the order of
// schemaMigrations and alterVersions. See appendOnlyLedger for why.
func TestSchemaMigrations_AreAppendOnlyNeverReordered(t *testing.T) {
	var units []migration
	for _, m := range schemaMigrationLedger {
		if m.Kind == kindAddColumn {
			units = append(units, m)
		}
	}
	for i, want := range appendOnlyLedger {
		if i >= len(units) {
			t.Fatalf("%s. schemaMigrations has %d entries; the pinned list has %d, so %q (v%d) and later were removed. "+
				"Ledger IDs are positional (a%%03d by index): a removal renames every later ALTER, and a database that "+
				"applied them refuses to start (checksum drift)", appendOnlyRule, len(units), len(appendOnlyLedger), want.id, want.version)
		}
		if got := units[i]; got.ID != want.id || got.Version != want.version {
			t.Fatalf("%s. Entry %d is %q (v%d), pinned as %q (v%d): an ALTER was inserted, moved or removed before it. "+
				"Ledger IDs are positional (a%%03d by index): a database that applied %q refuses to start (checksum drift). "+
				"Put the ALTER and its alterVersions entry back, and add new ones at the end",
				appendOnlyRule, i, got.ID, got.Version, want.id, want.version, want.id)
		}
	}
	for _, m := range units[len(appendOnlyLedger):] {
		t.Errorf("%s. %q (v%d) is appended after the pinned list; append it to appendOnlyLedger too", appendOnlyRule, m.ID, m.Version)
	}
}

func TestSchemaExecution86HasFourAdditiveLocalUnits(t *testing.T) {
	want := map[string]bool{"local_automation_executors": false, "local_automation_execution_progress": false, "local_automation_execution_artifacts": false, "local_automation_execution_terminals": false}
	for _, m := range schemaMigrationLedger {
		if m.Version != 87 {
			continue
		}
		if _, ok := want[m.Target]; !ok || m.Kind != kindCreateTable {
			t.Fatal("unexpected execution86 migration unit", m)
		}
		if want[m.Target] {
			t.Fatal("duplicate execution86 migration unit", m)
		}
		want[m.Target] = true
	}
	for table, seen := range want {
		if !seen {
			t.Fatal("missing execution86 table migration", table)
		}
	}
	if CurrentSchemaVersion < 87 || schemaVersionTokenUserIncarnation != 86 {
		t.Fatal("execution86 changed an allocated predecessor meaning")
	}
}
