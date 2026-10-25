package failover

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A BMC address stored with a bracket before ConfigureHost refused one (an
// IPMI address ending in a token body, say) is what an earlier build wrote raw
// into its fence rows. The coordinator flags each such host with
// ha.fence.bmc_address_unsafe, naming the address and how to fix it, and
// resolves it once the address is fixed. A plain IPv6 Redfish endpoint is not
// flagged.
//
// Mutation: drop syncUnsafeBMC from the cycle — no condition, red.
func TestUnsafeBMC_AStoredBracketedAddressIsFlagged(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	if err := db.Execute(ctx, `UPDATE hosts SET ipmi_address = '10.0.0.9 [trust=on;path=managed;v=2' WHERE name = 'down'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `UPDATE hosts SET state = 'active' WHERE name = 'alive'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, corrosion.HostFenceRedfishUpsertSQL, "alive", "https://[fd00::9]", "", "", "", "", "",
		"2026-10-25T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	c := newTestCoordinator("coordinator", db)
	c.run(ctx)
	row, ok, err := corrosion.GetHealthCondition(ctx, db, RefenceEvaluator, CondFenceBMCAddressUnsafe, "host", "down")
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("no open %s for down: %+v (%v)", CondFenceBMCAddressUnsafe, row, err)
	}
	var ev struct{ Field, Value, Remedy string }
	_ = json.Unmarshal([]byte(row.Evidence), &ev)
	if ev.Field != "ipmi_address" || !strings.Contains(ev.Remedy, "lv host config down --ipmi-address") {
		t.Errorf("evidence %+v", ev)
	}
	if _, ok, _ := corrosion.GetHealthCondition(ctx, db, RefenceEvaluator, CondFenceBMCAddressUnsafe, "host", "alive"); ok {
		t.Error("a plain IPv6 Redfish endpoint was flagged")
	}
	if err := db.Execute(ctx, `UPDATE hosts SET ipmi_address = '10.0.0.9' WHERE name = 'down'`); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	if row, _, _ := corrosion.GetHealthCondition(ctx, db, RefenceEvaluator, CondFenceBMCAddressUnsafe, "host", "down"); row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("%s not resolved once the address was fixed: %+v", CondFenceBMCAddressUnsafe, row)
	}
}
