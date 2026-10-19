package fleet

import (
	"context"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// fleetFirmwareRuntime is the firmware code every fleet node runs: exactly
// the live firmware floors (lv.LiveFirmwareFloors), installed and running.
var fleetFirmwareRuntime = lv.FirmwareRuntime{Libvirt: "10.0.0", QEMU: "8.2.2", Swtpm: "0.7.3", Libtpms: "0.9.3", OVMFFingerprint: "fleet-ovmf"}

// fleetLiveFirmwareHost is a node's live firmware host check
// (grpcapi.LiveFirmwareHost), as the daemon installs its own: the fleet has
// no swtpm, QEMU or /proc to probe, so each node reports the same code, and
// a guest runs what is installed.
type fleetLiveFirmwareHost struct{}

func (fleetLiveFirmwareHost) Check(context.Context) (lv.InstalledFirmwareCode, error) {
	return lv.InstalledFirmwareCode{Runtime: fleetFirmwareRuntime}, nil
}

func (fleetLiveFirmwareHost) RunningFirmwareCode(context.Context, string) (lv.FirmwareRuntime, error) {
	return fleetFirmwareRuntime, nil
}
