package corrosion

// Firewall logging (docs/firewall.md, "Logging"): the release feature
// firewall_log (capabilities.FeatureFirewallLog). A logged rule is stored with
// the server's "+log" action suffix in the rule tables it always had; the API
// never carries the suffix (spec §3.3, m-13).

import (
	"context"
	"strings"

	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// clusterPolicyFirewallLog is the cluster's log policy key; a host's is
// clusterPolicyFirewallLog + "/" + host.
const clusterPolicyFirewallLog = "firewall_log"

// LoggedAction is the stored action of a rule logged with verdict: the
// verdict ("" is accept) plus the server's log suffix.
func LoggedAction(verdict string) string {
	v := strings.ToLower(strings.TrimSpace(verdict))
	if v == "" {
		v = "accept"
	}
	return v + rulefield.LogActionSuffix
}

// SplitLoggedAction is a stored action as the API shows it: the plain verdict
// and whether the rule logs. An action not in the log form is returned as is.
func SplitLoggedAction(stored string) (verdict string, log bool) {
	if v, ok := rulefield.LogActionVerdict(stored); ok && v != "" {
		return v, true
	}
	return stored, false
}

// FirewallLogDataPresent reports whether this replica holds firewall_log data
// (0-F): a log policy row with a value, or a live rule of any tier whose
// action is in the log form, in any case and padding (as an older entry
// daemon stores a client's text verbatim).
func FirewallLogDataPresent(ctx context.Context, c *Client) (bool, error) {
	lo, hi := keyRange(clusterPolicyFirewallLog + "/")
	rows, err := c.Query(ctx,
		`SELECT 1 FROM cluster_policies
		 WHERE (key = ? OR (key >= ? AND key < ?)) AND deleted_at IS NULL AND value != '' LIMIT 1`,
		clusterPolicyFirewallLog, lo, hi)
	if err != nil {
		return false, err
	}
	if len(rows) > 0 {
		return true, nil
	}
	for _, table := range []string{"cluster_firewall_rules", "host_firewall_rules", "sg_rules"} {
		rows, err := c.Query(ctx,
			`SELECT 1 FROM `+table+`
			 WHERE deleted_at IS NULL AND LOWER(RTRIM(COALESCE(action, ''), ?)) LIKE '%+log' LIMIT 1`, tagCIDRTrimSet)
		if err != nil {
			return false, err
		}
		if len(rows) > 0 {
			return true, nil
		}
	}
	return false, nil
}
