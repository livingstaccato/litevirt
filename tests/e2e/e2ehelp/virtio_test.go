package e2ehelp

import (
	"strings"
	"testing"
)

// The replies below are in the format QEMU >= 7.2 prints through `virsh
// qemu-monitor-command` (qapi/virtio.json; the status strings are the ones in the
// QEMU 10.2.1 binary). The first version of TestVM_AttachDetachNIC's readiness
// wait looked for "driver-ok", a token only early drafts of that QEMU series
// used, so it never matched and the test failed on every lab run (review C1).

const virtioListReply = `{"return":[` +
	`{"path":"/machine/peripheral/virtio-disk0/virtio-backend","name":"virtio-blk"},` +
	`{"path":"/machine/peripheral/net0/virtio-backend","name":"virtio-net"},` +
	`{"path":"/machine/peripheral/virtio-serial0/virtio-backend","name":"virtio-serial"}],"id":"libvirt-412"}`

func statusReply(statuses ...string) string {
	q := make([]string, len(statuses))
	for i, s := range statuses {
		q[i] = `"` + s + `"`
	}
	return `{"return":{"name":"virtio-net","device-id":1,"vhost-started":false,` +
		`"device-endian":"little","num-vqs":3,` +
		`"status":{"statuses":[` + strings.Join(q, ",") + `]},` +
		`"isr":1,"queue-sel":2,"vm-running":true,"broken":false,"disabled":false,` +
		`"use-started":true,"started":true,"start-on-kick":false,` +
		`"disable-legacy-check":false,"bus-name":"","use-guest-notifier-mask":true},"id":"libvirt-413"}`
}

const (
	stAck      = "VIRTIO_CONFIG_S_ACKNOWLEDGE: Valid virtio device found"
	stDriver   = "VIRTIO_CONFIG_S_DRIVER: Guest OS compatible with device"
	stFeatures = "VIRTIO_CONFIG_S_FEATURES_OK: Feature negotiation complete"
	stDriverOK = "VIRTIO_CONFIG_S_DRIVER_OK: Driver setup and ready"
)

func TestVirtioDevices_ParsesTheList(t *testing.T) {
	ret, err := QMPReturn(virtioListReply)
	if err != nil {
		t.Fatal(err)
	}
	devs, err := VirtioDevices(ret)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 3 || devs[1].Name != "virtio-net" || devs[1].Path != "/machine/peripheral/net0/virtio-backend" {
		t.Fatalf("devices = %+v", devs)
	}
}

func TestVirtioDriverOK(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []string
		want     bool
	}{
		{"driver set up", []string{stAck, stDriver, stFeatures, stDriverOK}, true},
		{"driver bound, features still negotiating", []string{stAck, stDriver}, false},
		{"no guest driver yet", nil, false},
		{"DRIVER is not DRIVER_OK", []string{stDriver}, false},
	} {
		ret, err := QMPReturn(statusReply(tc.statuses...))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, err := VirtioDriverOK(ret)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: DRIVER_OK = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A format this does not parse must be an error, never a silent "not ready" that
// times out looking like a guest that did not boot.
func TestVirtioDriverOK_UnknownFormatIsAnError(t *testing.T) {
	ret, err := QMPReturn(`{"return":{"name":"virtio-net","device-status":["driver-ok"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VirtioDriverOK(ret); err == nil {
		t.Fatal("a reply without status.statuses must be an error")
	}
}

func TestQMPReturn_ErrorReply(t *testing.T) {
	_, err := QMPReturn(`{"id":"libvirt-9","error":{"class":"CommandNotFound","desc":"The command x-query-virtio has not been found"}}`)
	if err == nil || !strings.Contains(err.Error(), "CommandNotFound") {
		t.Fatalf("a QMP error reply must surface as an error, got %v", err)
	}
}
