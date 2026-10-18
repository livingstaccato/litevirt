package grpcapi

import (
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/cloudinit"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// keepCDROMs gives cfg, a full regenerate of vmName's domain, the CD-ROMs
// CreateVM attached and its current definition (priorXML) still has: the
// VM's cloud-init seed, and every other file-backed CD-ROM (an installer
// ISO). Neither is a vm_disks row, and the seed is set on the create's
// VMConfig alone, so a regenerate built from the tables and the spec dropped
// both: the guest booted next without its NoCloud datasource (hostname,
// network-config) and without its installer.
//
// They are rendered as CreateVM renders them — the installer ISOs after the
// disks, the seed last — so with the create's disks they land on the
// create's targets, and with more disks they move past them rather than onto
// one. Each installer keeps the file the definition had: a start judges it
// again (judgedCDROMDefinition).
//
// The seed is also attached when the definition lacks it but the seed on
// this host is this VM's (cloudinit.SeedIsFor) — a definition an earlier
// regenerate stripped, or none at all — as the reconciler's start does. One
// that is another VM's is not: it would boot that VM's user-data.
func (s *Server) keepCDROMs(cfg *lv.VMConfig, vmName, vmUUID, priorXML string) {
	seed, err := lv.SafeCloudInitISOPath(s.dataDir, vmName)
	if err != nil {
		seed = ""
	}
	hadSeed := false
	if priorXML != "" {
		files, perr := domainCDROMFiles(priorXML)
		if perr != nil {
			slog.Warn("regenerate: the current definition does not parse; its CD-ROMs are not carried over",
				"vm", vmName, "error", perr)
		}
		installers := 0
		for _, f := range files {
			if seed != "" && f == seed {
				hadSeed = true
				continue
			}
			installers++
			name := "installer"
			if installers > 1 {
				name = fmt.Sprintf("installer-%d", installers)
			}
			cfg.Disks = append(cfg.Disks, lv.DiskConfig{Name: name, Path: f, IsISO: true})
		}
	}
	if seed != "" && (hadSeed || cloudinit.SeedIsFor(seed, vmUUID)) {
		cfg.CloudInitISO = seed
	}
}
