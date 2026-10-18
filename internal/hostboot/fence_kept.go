package hostboot

import (
	"context"
	"encoding/json"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// CondFenceKeptOnBoot is the condition a host raises about itself when its
// boot kept the fence the cluster recorded because it could not record its
// own unclean-boot history (Boot.KeptFence): the daemon runs and serves, and
// the host stays fenced or offline until an operator returns it. Resolved once
// the host is recorded as anything else.
const CondFenceKeptOnBoot = "boot_kept_fence"

// FenceKeptRemedy is what the condition and the log tell an operator about
// host.
func FenceKeptRemedy(host string) string {
	return "fix what the cause names (this host's data_dir must take boot-unclean-history), confirm the host " +
		"should run workloads again, then run 'lv host undrain " + host + "'"
}

// RaiseFenceKept raises (or refreshes) host's boot_kept_fence condition,
// warning severity, with the state kept, the cause and the remedy.
func RaiseFenceKept(ctx context.Context, db *corrosion.Client, host, state, cause string, now time.Time) error {
	b, _ := json.Marshal(struct {
		State  string `json:"state"`
		Cause  string `json:"cause"`
		Remedy string `json:"remedy"`
	}{state, cause, FenceKeptRemedy(host)})
	return writeHostCondition(ctx, db, CondFenceKeptOnBoot, host, string(b), now, false)
}

// ResolveFenceKept resolves host's boot_kept_fence condition if one is open,
// including one an earlier process left.
func ResolveFenceKept(ctx context.Context, db *corrosion.Client, host string, now time.Time) error {
	return writeHostCondition(ctx, db, CondFenceKeptOnBoot, host, "", now, true)
}

// FenceKeptOpen reports whether host's boot_kept_fence condition is open.
func FenceKeptOpen(ctx context.Context, db *corrosion.Client, host string) (bool, error) {
	row, ok, err := corrosion.GetHealthCondition(ctx, db, BootEvaluator, CondFenceKeptOnBoot, "host", host)
	if err != nil || !ok {
		return false, err
	}
	return row.Lifecycle != corrosion.ConditionResolved, nil
}
