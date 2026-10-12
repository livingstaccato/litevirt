package e2ehelp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// VirtioDevice is one entry of QEMU's x-query-virtio reply.
type VirtioDevice struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// QMPReturn extracts the "return" member of a QMP reply as `virsh
// qemu-monitor-command` prints it. A QMP error reply (CommandNotFound on a QEMU
// older than 7.2, say) has no "return" and is reported as an error.
func QMPReturn(reply string) (json.RawMessage, error) {
	var r struct {
		Return json.RawMessage `json:"return"`
		Error  *struct {
			Class string `json:"class"`
			Desc  string `json:"desc"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(reply)), &r); err != nil {
		return nil, fmt.Errorf("not a QMP reply: %v: %.200s", err, reply)
	}
	if r.Error != nil {
		return nil, fmt.Errorf("QMP error %s: %s", r.Error.Class, r.Error.Desc)
	}
	if r.Return == nil {
		return nil, fmt.Errorf("QMP reply has no return: %.200s", reply)
	}
	return r.Return, nil
}

// VirtioDevices parses the return of x-query-virtio.
func VirtioDevices(ret json.RawMessage) ([]VirtioDevice, error) {
	var devs []VirtioDevice
	if err := json.Unmarshal(ret, &devs); err != nil {
		return nil, fmt.Errorf("x-query-virtio: %v", err)
	}
	return devs, nil
}

// virtioDriverOKName is how QEMU names the DRIVER_OK status bit. Since QEMU 7.2,
// x-query-virtio-status reports status bits as decoded descriptions, e.g.
//
//	"VIRTIO_CONFIG_S_DRIVER_OK: Driver setup and ready"
//
// so the bit is matched by its name, the part before the colon.
const virtioDriverOKName = "VIRTIO_CONFIG_S_DRIVER_OK"

// VirtioDriverOK reports whether the return of x-query-virtio-status has the
// DRIVER_OK bit set: the guest's driver has bound the device and finished
// setting it up.
//
// It reads status.statuses and compares each entry's name (the text before
// the first ':') exactly, so VIRTIO_CONFIG_S_DRIVER (a different, earlier bit)
// never counts. A reply without status.statuses is an error, not "not ready":
// it means the format is not the one this parses, and a wait on it would
// otherwise time out looking like a guest that never booted.
func VirtioDriverOK(ret json.RawMessage) (bool, error) {
	var st struct {
		Status *struct {
			Statuses *[]string `json:"statuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal(ret, &st); err != nil {
		return false, fmt.Errorf("x-query-virtio-status: %v", err)
	}
	if st.Status == nil || st.Status.Statuses == nil {
		return false, fmt.Errorf("x-query-virtio-status has no status.statuses: %.200s", ret)
	}
	for _, s := range *st.Status.Statuses {
		name, _, _ := strings.Cut(s, ":")
		if strings.TrimSpace(name) == virtioDriverOKName {
			return true, nil
		}
	}
	return false, nil
}
