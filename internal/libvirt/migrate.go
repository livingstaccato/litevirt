package libvirt

import (
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// MigrateParams configures migration behaviour.
type MigrateParams struct {
	Live          bool
	WithStorage   bool
	BandwidthMiB  int
	AutoConverge  bool     // enable auto-converge (throttle vCPUs to help convergence)
	MaxDowntimeMS int64    // max downtime in ms during cutover (0 = libvirt default)
	TargetAddress string   // target host IP/hostname for explicit migrate_uri (non-tunnelled)
	DiskTargets   []string // disk target devices to migrate (e.g. "vda"); empty = all
	// TLS encrypts QEMU's own migration stream and the NBD disk copy
	// (VIR_MIGRATE_TLS), using the migration credentials both hosts installed in
	// /etc/pki/qemu. It is what makes a WithStorage migration safe on an
	// untrusted network; a tunnelled migration is already inside libvirt's TLS.
	TLS bool
	// TLSDestination is the name the target's migration certificate is checked
	// against (libvirt's tls.destination). Set it to the target address when the
	// migrate_uri uses an IP, which the certificate carries as a SAN.
	TLSDestination string
	// Direct moves a memory-only migration out of libvirt's tunnel (port 16514
	// on the address the host is dialed on) onto QEMU's own TLS stream to
	// TargetAddress, so its data can take the dedicated migration network. It
	// takes effect only with TLS: without it the migration stays tunnelled
	// rather than send guest memory in the clear. A storage migration is
	// always direct.
	Direct bool
	// CDROMSources points CD-ROMs at other files on the destination (source
	// path here → path there): the target resolved the VM's installer ISO on
	// its own filesystem, and a link (virtio-win.iso → a versioned file) or a
	// library directory can name another file there. MigrateToTarget hands
	// libvirt a destination definition (and persistent definition) with those
	// sources; libvirt allows a disk's source to change in it. Empty: the
	// domain migrates as it is.
	CDROMSources map[string]string
	// DestXML and PersistXML are the definitions MigrateToTarget builds from
	// CDROMSources; callers leave them empty.
	DestXML    string
	PersistXML string
	// SharesWeight is the VM's cpu-shares weight (the user's scale, 0 = unset)
	// and TargetCgroup the target's cgroup version ("v2"/"v1", "" = unknown).
	// When the scales differ, the destination and persistent definitions carry
	// the TARGET's <shares>, not the value this host rendered.
	SharesWeight int
	TargetCgroup string
}

// MigrateToTarget performs a live (or cold) P2P migration of a domain to
// the given destination libvirt URI (e.g. "qemu+tls://10.0.0.2/system").
// When WithStorage is true, disk contents are copied alongside memory
// (MigrateNonSharedDisk), enabling migration of VMs with local disks.
// The call blocks until migration completes or fails.
func (c *Client) MigrateToTarget(name, dconnuri string, p MigrateParams) error {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", name, err)
	}

	// Set max downtime before starting migration.
	if p.MaxDowntimeMS > 0 {
		_ = c.virt.DomainMigrateSetMaxDowntime(dom, uint64(p.MaxDowntimeMS), 0)
	}

	retarget := shareRetargetNeeded(p, cgroupV2())
	if len(p.CDROMSources) > 0 || retarget {
		live, err := c.virt.DomainGetXMLDesc(dom, golibvirt.DomainXMLSecure|golibvirt.DomainXMLMigratable)
		if err != nil {
			return fmt.Errorf("get migratable XML for %q: %w", name, err)
		}
		persist, err := c.virt.DomainGetXMLDesc(dom, golibvirt.DomainXMLSecure|golibvirt.DomainXMLMigratable|golibvirt.DomainXMLInactive)
		if err != nil {
			return fmt.Errorf("get persistent migratable XML for %q: %w", name, err)
		}
		dest, persistOut := live, persist
		if len(p.CDROMSources) > 0 {
			if dest, persistOut, err = MigrationCDROMXML(live, persist, p.CDROMSources); err != nil {
				return fmt.Errorf("domain %q: %w", name, err)
			}
		}
		if d, pr, ok := MigrationShareXML(dest, persistOut, p.SharesWeight, p.TargetCgroup, cgroupV2()); ok {
			dest, persistOut = d, pr
		}
		p.DestXML, p.PersistXML = dest, persistOut
	}

	flags, params := migrationFlagsAndParams(p)
	_, err = c.virt.DomainMigratePerform3Params(
		dom,
		[]string{dconnuri}, // OptString
		params,
		nil, // cookieIn
		flags,
	)
	return err
}

// shareRetargetNeeded reports whether a migration must hand libvirt
// definitions with <shares> on the target's scale: the VM has a weight, the
// target reported its cgroup version, and that version differs from the
// source's (srcV2).
func shareRetargetNeeded(p MigrateParams, srcV2 bool) bool {
	return p.SharesWeight > 0 && (p.TargetCgroup == "v1" || p.TargetCgroup == "v2") && (p.TargetCgroup == "v2") != srcV2
}

// MigrationCDROMXML builds the destination and persistent definitions of a
// migration whose CD-ROMs are pointed at other files there (CDROMSources).
// The running domain must still carry every CD-ROM the destination judged:
// one that changed since would land on a file nobody judged there.
func MigrationCDROMXML(live, persist string, remap map[string]string) (dest, persistOut string, err error) {
	dest, n, err := RewriteCDROMSources(live, remap)
	if err != nil {
		return "", "", err
	}
	if n == 0 {
		return "", "", fmt.Errorf("the running domain no longer carries the installer CD-ROM the destination judged; migrate again")
	}
	persistOut, _, err = RewriteCDROMSources(persist, remap)
	if err != nil {
		return "", "", err
	}
	return dest, persistOut, nil
}

// migrationFlagsAndParams builds the flags and typed parameters MigrateToTarget
// hands DomainMigratePerform3Params. It is pure so the security-relevant bits —
// VIR_MIGRATE_TLS and tls.destination on an untunnelled storage copy — can be
// asserted without a libvirt connection.
func migrationFlagsAndParams(p MigrateParams) (golibvirt.DomainMigrateFlags, []golibvirt.TypedParam) {
	flags := golibvirt.MigratePeer2peer |
		golibvirt.MigratePersistDest |
		golibvirt.MigrateUndefineSource

	if p.Live {
		flags |= golibvirt.MigrateLive
		if p.AutoConverge {
			flags |= golibvirt.MigrateAutoConverge
		}
	}

	if p.WithStorage {
		// QEMU doesn't support tunnelled + non-shared disk together.
		// Without tunnelling, QEMU opens a direct connection to the target for
		// the migration stream and the NBD block copy (migration port range,
		// default 49152-49215). Without p.TLS both carry RAM and disk blocks
		// UNENCRYPTED; MigrateVM sends that only when the source's
		// migration.allow_unencrypted_storage is set.
		flags |= golibvirt.MigrateNonSharedDisk
		if p.TLS {
			// Encrypts the migration stream AND the NBD disk copy, with the
			// migration-CA credentials QEMU reads from /etc/pki/qemu.
			flags |= golibvirt.MigrateTLS
		}
		// libvirt's qemuMigrationSrcIsSafe rejects a non-shared-storage
		// migration ("Migration without shared storage is unsafe") whenever a
		// disk's cache mode isn't none/directsync — and our generated domains
		// use cache='writeback'. With NonSharedDisk the disk content IS copied
		// over the NBD block-mirror channel, so the cache-coherency concern
		// that gate guards against doesn't apply; assert that explicitly.
		flags |= golibvirt.MigrateUnsafe
	} else if p.Direct && p.TLS && p.TargetAddress != "" {
		// Over the dedicated migration network: QEMU's own stream, encrypted
		// with the migration credentials, to the address on that network.
		flags |= golibvirt.MigrateTLS
	} else {
		// Memory-only migration can be tunnelled through the single
		// libvirt TLS connection (port 16514) — no extra ports needed.
		flags |= golibvirt.MigrateTunnelled
	}

	var params []golibvirt.TypedParam
	if p.BandwidthMiB > 0 {
		params = append(params, golibvirt.TypedParam{
			Field: "bandwidth",
			Value: golibvirt.TypedParamValue{I: uint64(p.BandwidthMiB)},
		})
	}

	// For non-tunnelled migration (--with-storage), provide an explicit
	// migrate_uri so the target listens on the right address and QEMU
	// can establish the NBD data channel for disk copy.
	direct := p.WithStorage || (p.Direct && p.TLS)
	if direct && p.TargetAddress != "" {
		params = append(params, golibvirt.TypedParam{
			Field: golibvirt.MigrateParamURI,
			Value: *golibvirt.NewTypedParamValueString(fmt.Sprintf("tcp://%s", p.TargetAddress)),
		})
	}

	if direct && p.TLS && p.TLSDestination != "" {
		params = append(params, golibvirt.TypedParam{
			Field: golibvirt.MigrateParamTLSDestination,
			Value: *golibvirt.NewTypedParamValueString(p.TLSDestination),
		})
	}

	// When specific disk targets are provided, tell libvirt which disks to
	// block-copy — this avoids copying read-only devices like CDROMs.
	for _, dt := range p.DiskTargets {
		params = append(params, golibvirt.TypedParam{
			Field: golibvirt.MigrateParamMigrateDisks,
			Value: *golibvirt.NewTypedParamValueString(dt),
		})
	}

	if p.DestXML != "" {
		params = append(params, golibvirt.TypedParam{
			Field: golibvirt.MigrateParamDestXML,
			Value: *golibvirt.NewTypedParamValueString(p.DestXML),
		})
	}
	if p.PersistXML != "" {
		params = append(params, golibvirt.TypedParam{
			Field: golibvirt.MigrateParamPersistXML,
			Value: *golibvirt.NewTypedParamValueString(p.PersistXML),
		})
	}

	return flags, params
}

// DomainJobProgress returns the memory and disk migration progress (0–100)
// for a running migration, or -1 if no migration job is active.
func (c *Client) DomainJobProgress(name string) (memPct, diskPct float32) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return -1, -1
	}
	_, _, _, _, _, _, rMemTotal, rMemProcessed, _, rFileTotal, rFileProcessed, _, err := c.virt.DomainGetJobInfo(dom)
	if err != nil || rMemTotal == 0 {
		return -1, -1
	}
	memPct = float32(rMemProcessed) / float32(rMemTotal) * 100
	if rFileTotal > 0 {
		diskPct = float32(rFileProcessed) / float32(rFileTotal) * 100
	}
	return memPct, diskPct
}

// AbortMigration aborts name's running job — for a domain mid-migration, the
// migration. MigrateToTarget blocks in libvirt and takes no context, so this is
// the only way to stop a migration that will not converge; MigrateToTarget then
// returns an error and the guest stays on the source.
func (c *Client) AbortMigration(name string) error {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", name, err)
	}
	return c.virt.DomainAbortJob(dom)
}
