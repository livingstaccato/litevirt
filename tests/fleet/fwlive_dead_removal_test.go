package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// D2 re-review of 78580365c, I-3 (design a): `lv host rm --dead` of a host
// that is the target of a Secure Boot / vTPM VM's live firmware move that is
// not settled is refused before anything is revoked, naming the doctor and
// --force; `--dead --force` removes it anyway, and the VM stays recorded.
//
// Mutation: drop the firmware refusal from removeHostRefusal — the plain
// removal goes through, red.
func TestFleet_DeadRemovalRefusesAnUnsettledFirmwareMoveTarget(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2611})
	a, b, e, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: "fw-old", HostName: d.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"fw-old","secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"6f1c2d3e-4b5a-4c6d-8e7f-0011223344aa"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	ev, _ := json.Marshal(map[string]any{"vm": "fw-old", "attempt": "6f1c2d3e-4b5a-4c6d-8e7f-0011223344bb",
		"source": a.Name, "target": d.Name, "host": a.Name, "detail": "the source cleanup stopped"})
	now := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, a.DB, corrosion.HealthCondition{Evaluator: "firmware_migration",
		Code: "firmware_migration_cleanup_failed", SubjectKind: "vm", SubjectID: "fw-old", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityCritical, FirstSeen: now, ConfirmedAt: now, LastSeen: now, Evidence: string(ev),
		Hosts: []string{a.Name}, Reporter: a.Name}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)
	c.Kill(d)
	if err := corrosion.InsertFenceLog(ctx, a.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	withOperatorPKI(t, a)

	err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false)
	if err == nil || !strings.Contains(err.Error(), "lv doctor firmware-move fw-old") ||
		!strings.Contains(err.Error(), "lv host rm --dead --force "+d.Name) {
		t.Fatalf("lv host rm --dead %s = %v, want refused naming the doctor and --force", d.Name, err)
	}
	if h, _ := corrosion.GetHost(ctx, a.DB, d.Name); h == nil || h.State == "removed" {
		t.Fatalf("%s was removed by a refused removal: %+v", d.Name, h)
	}

	if err := cli.HostRemoveDeadForce(ctx, c.SelfClient(a), d.Name, false, true); err != nil {
		t.Fatalf("lv host rm --dead --force %s: %v", d.Name, err)
	}
	if h, _ := corrosion.GetHost(ctx, a.DB, d.Name); h != nil && h.State != "removed" {
		t.Fatalf("%s is %s after --dead --force", d.Name, h.State)
	}
	if vm, _ := corrosion.GetVM(ctx, a.DB, "fw-old"); vm == nil || vm.HostName != d.Name {
		t.Errorf("fw-old after the forced removal: %+v, want still recorded on %s", vm, d.Name)
	}
	_, _ = b, e
}
