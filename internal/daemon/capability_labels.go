package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// capabilityLabelInterval is how often the daemon re-asserts its capability
// labels.
const capabilityLabelInterval = time.Minute

// capabilityLabel is one host label the daemon publishes from a probe of its
// own runtime: "true" where the probe finds the capability, else "false".
type capabilityLabel struct {
	key     string
	capable func() bool
}

// probeCapabilityLabels is every label's value from its probe.
func probeCapabilityLabels(labels []capabilityLabel) map[string]string {
	set := make(map[string]string, len(labels))
	for _, l := range labels {
		set[l.key] = "false"
		if l.capable() {
			set[l.key] = "true"
		}
	}
	return set
}

// assertCapabilityLabels is the start-time publication: every label from its
// probe, in one write of the labels column and none when they already say so
// (SetHostLabels). It returns what it published, which keepCapabilityLabels
// takes as this daemon's own values.
func assertCapabilityLabels(ctx context.Context, db *corrosion.Client, host string, labels []capabilityLabel) (map[string]string, error) {
	set := probeCapabilityLabels(labels)
	return set, corrosion.SetHostLabels(ctx, db, host, set, nil)
}

// keepCapabilityLabels re-asserts the labels every interval until ctx ends; the
// daemon asserts them once at start (assertCapabilityLabels), and asserted is
// what that published, or nil if that write failed.
//
// Placement is strict about each of them: a host whose record does not say
// litevirt.lxc=true runs no container (corrosion.HostRunsContainers), and one
// that does not say litevirt.tpm / litevirt.secureboot=true gets no vTPM or
// Secure Boot VM. Written once at start, a label was lost until the next
// restart whenever:
//   - the start-time write found no host row yet (the UPDATE matched nothing);
//   - a concurrent read-modify-write of the labels column replaced it;
//   - the host was re-added while its data directory still held its old
//     database. At start its own row there already carried every label, so
//     nothing was written; then the re-admission's row, whose labels are
//     reset, won on every node (host_readmit.go, THE INCARNATION), this one
//     included.
//
// So each interval a MISSING label is written again. A label that is present
// is written only while it still holds the value this daemon published last,
// so it follows a runtime installed or removed while the daemon runs. A
// different value is an operator's override (`lv host label`) and stands until
// the operator changes it; the next start publishes the probe again, as it
// always has. A failure is logged once per run of failures.
func keepCapabilityLabels(ctx context.Context, db *corrosion.Client, host string, labels []capabilityLabel, asserted map[string]string, interval time.Duration) {
	own := make(map[string]string, len(asserted))
	for k, v := range asserted {
		own[k] = v
	}
	failing := false
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		set, err := reassertCapabilityLabels(ctx, db, host, labels, own)
		switch {
		case err != nil && !failing && ctx.Err() == nil:
			slog.Warn("set capability host labels failed; retrying — until they land, placement may put no "+
				"container, vTPM or Secure Boot VM on this host",
				"labels", set, "retry_in", interval, "error", err)
			failing = true
		case err == nil && failing:
			slog.Info("set capability host labels", "labels", set)
			failing = false
		}
	}
}

// reassertCapabilityLabels writes the labels that are missing, or that still
// hold this daemon's own last value and whose probe now says otherwise, and
// records what it wrote in own.
func reassertCapabilityLabels(ctx context.Context, db *corrosion.Client, host string, labels []capabilityLabel, own map[string]string) (map[string]string, error) {
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil || h == nil {
		return nil, err // no row yet: nothing to label; the next interval retries
	}
	set := map[string]string{}
	for key, want := range probeCapabilityLabels(labels) {
		cur, ok := h.Labels[key]
		switch {
		case !ok:
			set[key] = want
		case cur != want && (own[key] == "" || cur == own[key]):
			// own is empty for a label the start-time write did not land:
			// the value there is not known to be an override, so the probe's
			// stands, as a retry of that write.
			set[key] = want
		}
	}
	if len(set) == 0 {
		return set, nil
	}
	if err := corrosion.SetHostLabels(ctx, db, host, set, nil); err != nil {
		return set, err
	}
	for k, v := range set {
		own[k] = v
	}
	return set, nil
}

// fwLiveInputs are what litevirt.fw_live_migrate is computed from.
type fwLiveInputs struct {
	enabled    bool // migration.live_firmware
	tpm        func() bool
	secureBoot func() bool
	installed  func(ctx context.Context) (libvirt.InstalledFirmwareCode, error)
	guests     func(ctx context.Context) error // D-9
}

// fwLiveMigrateCapable is true only when every condition holds. An unreadable
// version, or one that is not X.Y.Z, is "not capable". The label is advisory:
// stage A and Prepare re-check each condition live (fwLiveMigrateCheck).
func fwLiveMigrateCapable(ctx context.Context, in fwLiveInputs) bool {
	_, err := fwLiveMigrateCheck(ctx, in)
	return err == nil
}

// fwLiveMigrateCheck is the label's condition list with its reason: the
// host's installed firmware code when every condition holds, else the first
// that fails.
func fwLiveMigrateCheck(ctx context.Context, in fwLiveInputs) (libvirt.InstalledFirmwareCode, error) {
	switch {
	case !in.enabled:
		return libvirt.InstalledFirmwareCode{}, errors.New("migration.live_firmware is off")
	case !in.tpm():
		return libvirt.InstalledFirmwareCode{}, errors.New("no vTPM support (swtpm and swtpm_setup)")
	case !in.secureBoot():
		return libvirt.InstalledFirmwareCode{}, errors.New("no Secure Boot firmware")
	}
	code, err := in.installed(ctx)
	if err != nil {
		return libvirt.InstalledFirmwareCode{}, fmt.Errorf("installed firmware code: %w", err)
	}
	// The installed-version floors (spec §3.1), in internal/libvirt only.
	if err := libvirt.FirmwareFloorsMet(code.Runtime); err != nil {
		return libvirt.InstalledFirmwareCode{}, err
	}
	if err := in.guests(ctx); err != nil {
		return libvirt.InstalledFirmwareCode{}, fmt.Errorf("libvirt-guests: %w; a guest it saves or restores runs outside litevirt's firmware move guard", err)
	}
	return code, nil
}

// fwLiveProbeTimeout bounds the whole label probe, and the libvirt version
// call inside it.
const fwLiveProbeTimeout = 15 * time.Second

// fwLiveHost are the host-side probes behind litevirt.fw_live_migrate and a
// live firmware move's host check.
type fwLiveHost struct {
	tpm, secureBoot func() bool
	installed       func(ctx context.Context) (libvirt.InstalledFirmwareCode, error)
	running         func(ctx context.Context, liveXML string) (libvirt.FirmwareRuntime, error)
	guests          func(ctx context.Context) error
}

// fwLiveLabelProbe is the probe of the litevirt.fw_live_migrate label: the
// whole condition list of fwLiveMigrateCapable, bounded in time. A probe that
// outlives its bound is "not capable", and the label loop goes on.
func fwLiveLabelProbe(cfg MigrationConfig, h fwLiveHost) func() bool {
	return func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), fwLiveProbeTimeout)
		defer cancel()
		return fwLiveMigrateCapable(ctx, fwLiveInputs{
			enabled: cfg.LiveFirmwareEnabled(), tpm: h.tpm, secureBoot: h.secureBoot,
			installed: h.installed, guests: h.guests,
		})
	}
}

// newFwLiveLabel is the production probe: this host's installed firmware code,
// read with the libvirt version call bounded, and the live D-9 check.
func newFwLiveLabel(cfg MigrationConfig, store *libvirt.FirmwareStore, fp libvirt.FirmwarePaths,
	libvirtVersion func() (uint64, error), tpm func() bool) func() bool {
	return fwLiveLabelProbe(cfg, newFwLiveHost(store, fp, libvirtVersion, tpm))
}

// newFwLiveHost is this host's probes behind the label and a live firmware
// move's host check: its installed firmware code and the running code check
// over one probe (the libvirt version call bounded), and the live D-9 check.
// Each caller gets probes of its own, so the label loop never holds up a
// move behind its in-flight version call.
func newFwLiveHost(store *libvirt.FirmwareStore, fp libvirt.FirmwarePaths,
	libvirtVersion func() (uint64, error), tpm func() bool) fwLiveHost {
	probe := libvirt.NewFirmwareCodeProbe(store, fp, boundedVersion(fwLiveProbeTimeout, libvirtVersion))
	return fwLiveHost{
		tpm: tpm, secureBoot: fp.SecureBootAvailable,
		installed: probe.Installed, running: probe.RunningFirmwareCode, guests: CheckLibvirtGuests,
	}
}

// fwLiveHostCheck is grpcapi.LiveFirmwareHost: the one host check stage A
// (as a move's source) and Prepare (as its target) read. Every call is
// bounded by fwLiveProbeTimeout.
type fwLiveHostCheck struct {
	cfg MigrationConfig
	h   fwLiveHost
}

// Check is the label's conditions, each read now, with the reason of the
// first that fails (spec §3.2 item 1, §6.2 item 1).
func (c fwLiveHostCheck) Check(ctx context.Context) (libvirt.InstalledFirmwareCode, error) {
	ctx, cancel := context.WithTimeout(ctx, fwLiveProbeTimeout)
	defer cancel()
	return fwLiveMigrateCheck(ctx, fwLiveInputs{
		enabled: c.cfg.LiveFirmwareEnabled(), tpm: c.h.tpm, secureBoot: c.h.secureBoot,
		installed: c.h.installed, guests: c.h.guests,
	})
}

// RunningFirmwareCode is the probe's running code check (spec §3.5).
func (c fwLiveHostCheck) RunningFirmwareCode(ctx context.Context, liveXML string) (libvirt.FirmwareRuntime, error) {
	ctx, cancel := context.WithTimeout(ctx, fwLiveProbeTimeout)
	defer cancel()
	return c.h.running(ctx, liveXML)
}

// newFwLiveHostCheck is the production live firmware host check.
func newFwLiveHostCheck(cfg MigrationConfig, store *libvirt.FirmwareStore, fp libvirt.FirmwarePaths,
	libvirtVersion func() (uint64, error), tpm func() bool) grpcapi.LiveFirmwareHost {
	return fwLiveHostCheck{cfg: cfg, h: newFwLiveHost(store, fp, libvirtVersion, tpm)}
}

// boundedVersion calls fn with a deadline. A call that does not return in
// time is an error (the host counts as not capable), and while it is still
// blocked a later call fails at once rather than piling up another goroutine
// behind a wedged libvirtd.
func boundedVersion(timeout time.Duration, fn func() (uint64, error)) func() (uint64, error) {
	var inflight atomic.Bool
	return func() (uint64, error) {
		if !inflight.CompareAndSwap(false, true) {
			return 0, errors.New("libvirt version: an earlier call has not returned")
		}
		type res struct {
			v   uint64
			err error
		}
		ch := make(chan res, 1)
		go func() {
			defer inflight.Store(false)
			v, err := fn()
			ch <- res{v, err}
		}()
		select {
		case r := <-ch:
			return r.v, r.err
		case <-time.After(timeout):
			return 0, errors.New("libvirt version: timed out")
		}
	}
}
