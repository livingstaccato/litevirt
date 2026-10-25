package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// ha.fence.bmc_address_unsafe (docs/diagnostics.md): a host's stored IPMI
// address or Redfish endpoint carries a bracket other than around a plain
// IPv6 literal (fence.UnsafeBMCAddress). ConfigureHost refuses one now, but
// an address stored before was written raw by earlier builds into the target
// note of their fence rows, where it could open or close a token. This build
// reads those tokens only from balanced text, and writes the address
// sanitised; the condition asks the operator to fix the stored address.
// Visibility only; written by the lease holder.
const CondFenceBMCAddressUnsafe = "ha.fence.bmc_address_unsafe"

type unsafeBMCEvidence struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Remedy string `json:"remedy"`
}

// syncUnsafeBMC raises ha.fence.bmc_address_unsafe for each host whose stored
// BMC address is unsafe, and resolves it for every host whose address no
// longer is, or that is removed. A read error changes nothing.
func (c *Coordinator) syncUnsafeBMC(ctx context.Context) {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return
	}
	unsafe := map[string]unsafeBMCEvidence{}
	for _, h := range hosts {
		switch {
		case fence.UnsafeBMCAddress(h.IPMIAddress):
			unsafe[h.Name] = unsafeBMCEvidence{Field: "ipmi_address", Value: fence.DetailField(h.IPMIAddress),
				Remedy: fmt.Sprintf("set an address without '[' or ']': `lv host config %s --ipmi-address <addr>`", h.Name)}
		case fence.UnsafeBMCAddress(h.Redfish.Endpoint):
			unsafe[h.Name] = unsafeBMCEvidence{Field: "redfish_endpoint", Value: fence.DetailField(h.Redfish.Endpoint),
				Remedy: fmt.Sprintf("set an endpoint with brackets only around a plain IPv6 address: "+
					"`lv host config %s --redfish-endpoint https://<host>[:port]`", h.Name)}
		}
	}
	ts := c.now().UTC().Format(time.RFC3339)
	for host, ev := range unsafe {
		row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondFenceBMCAddressUnsafe, "host", host)
		if err != nil {
			continue
		}
		b, _ := json.Marshal(ev)
		if ok && row.Lifecycle != corrosion.ConditionResolved && row.Evidence == string(b) {
			continue
		}
		if !ok || row.Lifecycle == corrosion.ConditionResolved {
			row = corrosion.HealthCondition{Evaluator: RefenceEvaluator, Code: CondFenceBMCAddressUnsafe,
				SubjectKind: "host", SubjectID: host, FirstSeen: ts, ConfirmedAt: ts}
		}
		row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
		row.ObserveCount++
		row.Evidence = string(b)
		row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityWarning, []string{host}, ts, c.hostName
		if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
			slog.Warn("failover: could not record "+CondFenceBMCAddressUnsafe, "host", host, "error", err)
			continue
		}
		slog.Warn("failover: a host's stored BMC address carries a bracket; fix it", "host", host, "field", ev.Field)
	}
	rows, err := c.db.Query(ctx, `SELECT subject_id FROM health_conditions
		WHERE evaluator = ? AND code = ? AND subject_kind = 'host' AND lifecycle != ? AND deleted_at IS NULL`,
		RefenceEvaluator, CondFenceBMCAddressUnsafe, corrosion.ConditionResolved)
	if err != nil {
		return
	}
	for _, r := range rows {
		host := r.String("subject_id")
		if _, still := unsafe[host]; still {
			continue
		}
		row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondFenceBMCAddressUnsafe, "host", host)
		if err != nil || !ok {
			continue
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, c.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
			slog.Warn("failover: could not resolve "+CondFenceBMCAddressUnsafe, "host", host, "error", err)
		}
	}
}
