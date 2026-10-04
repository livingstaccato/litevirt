package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The removed-host pass (recoverRemovedHosts) visits a removed host's
// workloads on every tick, and a workload it cannot recover was audited as
// failover.skip on every one of them: one row every poll, for as long as it
// stayed stranded. A skip is now audited once per change of state: when the
// workload is first skipped, and again only when the reason changes.
//
// Mutation: audit unconditionally in auditSkip — three passes write three rows.
func TestFailoverSkip_AuditedOncePerChangeOfState(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "alive", Address: "10.0.0.41", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	// A vTPM VM recorded on a host removed for good: never auto-recovered.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "tpm-vm", HostName: "gone", State: "running",
		Spec: `{"on_host_failure":"restart-any","tpm":true}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	skips := func() []string {
		t.Helper()
		rows, err := db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'failover.skip' AND target = 'tpm-vm'`)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r.String("detail")
		}
		return out
	}

	c := newTestCoordinator("coordinator", db)
	removed := &corrosion.HostRecord{Name: "gone", State: "removed"}
	for i := 0; i < 3; i++ {
		c.recoverWorkloads(ctx, removed)
	}
	if got := skips(); len(got) != 1 {
		t.Fatalf("three passes over the same stranded VM wrote %d failover.skip rows, want 1: %q", len(got), got)
	}

	// The reason changes: the VM is no longer vTPM, and no host can hold it.
	if err := db.Execute(ctx, `UPDATE vms SET spec = ?, cpu_actual = 64, mem_actual = 1048576, updated_at = ? WHERE name = 'tpm-vm'`,
		`{"on_host_failure":"restart-any"}`, db.NowTS()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c.recoverWorkloads(ctx, removed)
	}
	if got := skips(); len(got) != 2 {
		t.Fatalf("a changed reason should be audited once more: %d rows, want 2: %q", len(got), got)
	}
}
