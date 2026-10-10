package firewall

import (
	"context"
	"log/slog"
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// warnedLegacyRules remembers the rules already reported, so the reconcile loop
// says it once per rule and not on every pass.
var warnedLegacyRules sync.Map

// warnUnattributableLegacyRules reports rules an older client stored with a
// group NAME in sg_id when two live groups hold that name: which group they
// meant is not in the data, so they are applied to neither.
func warnUnattributableLegacyRules(ctx context.Context, db *corrosion.Client, name string) {
	rules, err := corrosion.ListSGRules(ctx, db, name)
	if err != nil {
		return
	}
	for _, r := range rules {
		if _, seen := warnedLegacyRules.LoadOrStore(r.ID, true); seen {
			continue
		}
		slog.Warn("security group rule is not applied: it was stored under a group name that two groups share",
			"rule", r.ID, "name", name, "fix", "remove it (lv sg rule-rm) and re-add it by group id")
	}
}
