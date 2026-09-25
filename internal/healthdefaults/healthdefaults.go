// Package healthdefaults holds the VM health checker's defaults for a
// healthcheck field that is left out. It is the one source for both the
// checker (internal/health), which applies them, and compose, which shows
// them in a plan — compose cannot import internal/health, which imports it.
package healthdefaults

import "time"

const (
	// Interval is the checker's sweep period: the default interval, and
	// its floor — a shorter interval probes at each sweep.
	Interval = 10 * time.Second
	// Timeout bounds one probe.
	Timeout = 5 * time.Second
	// Retries is the consecutive failures that make a VM unhealthy and
	// trigger its action.
	Retries = 3
	// Action is what the checker does to an unhealthy VM.
	Action = "restart"
)
