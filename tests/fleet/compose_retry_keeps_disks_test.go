package fleet

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A VM left in error by a deploy that did not finish is retried by the next
// deploy. When anything of it was made — its disks — the retry repairs it:
// the domain is redefined from the desired spec over the existing disks and
// started, so the disks, MAC and incarnation survive. Only a VM of which
// nothing was made is created again. The regression: every retry was a
// DeleteVM plus a fresh create, wiping whatever the disks held.

// breakVM puts db in the state a deploy that failed half-way leaves it in:
// recorded in error, its domain not running. With undefine, the domain is
// gone too (a failed define); its disks stay.
func breakVM(t *testing.T, ctx context.Context, node *Node, vm string, undefine bool) {
	t.Helper()
	node.Virt.SetState(vm, libvirtfake.State("shutoff"))
	if undefine {
		if err := node.Virt.UndefineDomain(vm, false); err != nil {
			t.Fatalf("undefine %s: %v", vm, err)
		}
	}
	if err := node.DB.Execute(ctx, `UPDATE vms SET state = 'error', updated_at = ? WHERE name = ?`, node.DB.NowTS(), vm); err != nil {
		t.Fatalf("mark %s error: %v", vm, err)
	}
}

func assertRetryRepairs(t *testing.T, undefine bool) {
	ctx, node, client, before := setupUpdateVM(t)
	breakVM(t, ctx, node, "db", undefine)

	phase, detail := planDetailFor(t, ctx, client, composeUpdateBase, "db")
	if phase != string(compose.OpUpdate) || !strings.Contains(detail, "retry — repaired in place, disks kept") {
		t.Fatalf("plan for the retry = %s %q, want a repair that keeps the disks", phase, detail)
	}
	from := len(node.Virt.EventLog())
	deployClean(t, ctx, client, composeUpdateBase)
	assertSameVM(t, ctx, node, "db", before, from, true)
	waitRunning(t, ctx, node, "db")
}

// The domain is still defined; the disks hold data.
func TestFleet_ComposeRetryRepairsAVMWithItsDomain(t *testing.T) {
	assertRetryRepairs(t, false)
}

// The domain is gone (a failed define) but the disks exist: the repair
// defines it again over them.
func TestFleet_ComposeRetryRepairsAVMWhoseDomainIsGone(t *testing.T) {
	assertRetryRepairs(t, true)
}

// A repair that fails is reported and leaves the VM in error — it never falls
// through to a recreate.
func TestFleet_ComposeFailedRetryRepairNeverRecreates(t *testing.T) {
	ctx, node, client, before := setupUpdateVM(t)
	breakVM(t, ctx, node, "db", true)
	node.Virt.FailDefineDomain = func(xml string) error {
		if strings.Contains(xml, "<name>db</name>") {
			return errors.New("injected: define refused")
		}
		return nil
	}

	from := len(node.Virt.EventLog())
	msgs := deployCollect(t, ctx, client, composeUpdateBase)
	if p := errorPhaseFor(msgs, "db"); p == nil || !strings.Contains(p.Error, "define refused") {
		t.Fatalf("failed repair of db: error phase %+v, want the define failure; got %v", p, msgs)
	}
	rec, err := corrosion.GetVM(ctx, node.DB, "db")
	if err != nil || rec == nil {
		t.Fatalf("db is gone after a failed repair: %v %v", rec, err)
	}
	if rec.State != "error" {
		t.Errorf("db state after a failed repair = %q, want error", rec.State)
	}
	if rec.CreatedAt != before.createdAt {
		t.Errorf("db was recreated: created_at %s → %s", before.createdAt, rec.CreatedAt)
	}
	for name, path := range before.disks {
		if b, err := os.ReadFile(path); err != nil || string(b) != diskSentinel {
			t.Errorf("disk %s at %s lost its data (err=%v)", name, path, err)
		}
	}
	for _, e := range node.Virt.EventLog()[from:] {
		if e.Domain == "db" && e.Op == "undefine" && strings.Contains(e.Note, "remove_storage=true") {
			t.Errorf("the failed repair removed db's storage")
		}
	}
	if got := stackState(t, ctx, node.DB, "upd"); got != "degraded" {
		t.Errorf("stack state = %q, want degraded", got)
	}
}

// Nothing of the VM was made — no domain, no disks: the retry creates it.
func TestFleet_ComposeRetryOfAVMWithNothingMadeCreatesIt(t *testing.T) {
	ctx, node, client, before := setupUpdateVM(t)
	breakVM(t, ctx, node, "db", true)
	for _, path := range before.disks {
		_ = os.Remove(path)
	}
	if err := node.DB.Execute(ctx, `UPDATE vm_disks SET deleted_at = ?, updated_at = ? WHERE vm_name = 'db'`, "2026-01-01T00:00:00Z", node.DB.NowTS()); err != nil {
		t.Fatalf("drop db's disk rows: %v", err)
	}

	phase, detail := planDetailFor(t, ctx, client, composeUpdateBase, "db")
	if phase != string(compose.OpUpdate) || !strings.Contains(detail, "retry — created again (nothing was made)") {
		t.Fatalf("plan for the retry = %s %q, want a create of a VM with nothing made", phase, detail)
	}
	deployClean(t, ctx, client, composeUpdateBase)
	waitRunning(t, ctx, node, "db")
}
