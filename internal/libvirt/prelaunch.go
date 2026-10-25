package libvirt

import (
	"encoding/json"
	"fmt"
)

// QEMU's run state for a domain created paused whose vCPUs have never run
// (QMP query-status). libvirt reports the same paused reason, "user", for
// such a start and for a guest that ran and was then suspended, so only
// this proves a guest never ran.
const QEMUStatusPrelaunch = "prelaunch"

// DomainQEMUStatus is QEMU's own run state for name's domain (QMP
// query-status: "prelaunch", "paused", "running", ...), asked through
// libvirt's qemu-monitor-command. libvirt marks a domain it is asked for this
// way as tainted (custom-monitor), which is only a note in its log; litevirt
// asks only for a domain a start of this host recorded as left paused.
func (c *Client) DomainQEMUStatus(name string) (string, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return "", fmt.Errorf("lookup domain %s: %w", name, err)
	}
	out, err := c.virt.QEMUDomainMonitorCommand(dom, `{"execute":"query-status"}`, 0)
	if err != nil {
		return "", fmt.Errorf("query-status %s: %w", name, err)
	}
	return parseQueryStatus(out)
}

// parseQueryStatus reads the status out of a QMP query-status reply.
func parseQueryStatus(reply string) (string, error) {
	var r struct {
		Return *struct {
			Status string `json:"status"`
		} `json:"return"`
		Error *struct {
			Class string `json:"class"`
			Desc  string `json:"desc"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(reply), &r); err != nil {
		return "", fmt.Errorf("query-status: unreadable reply %q: %w", reply, err)
	}
	switch {
	case r.Error != nil:
		return "", fmt.Errorf("query-status: %s: %s", r.Error.Class, r.Error.Desc)
	case r.Return == nil || r.Return.Status == "":
		return "", fmt.Errorf("query-status: no status in reply %q", reply)
	}
	return r.Return.Status, nil
}
