package cloudinit

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/randid"
)

// Config holds cloud-init data for a VM.
type Config struct {
	InstanceID    string
	LocalHostname string
	UserData      string // #cloud-config YAML
	NetworkConfig string // optional netplan config
	VendorData    string // optional; see SeedVendorData
}

// GenerateISO creates a NoCloud cloud-init ISO at the given path.
// Uses genisoimage to create a CDROM with label "cidata".
func GenerateISO(cfg Config, outputPath string) error {
	userData := cfg.UserData
	if userData == "" {
		userData = "#cloud-config\n{}\n"
	}
	return writeISO(Seed{
		MetaData:      fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", cfg.InstanceID, cfg.LocalHostname),
		UserData:      userData,
		NetworkConfig: cfg.NetworkConfig,
		VendorData:    cfg.VendorData,
	}, outputPath, true)
}

// writeISO writes seed's files as a NoCloud seed at outputPath, replacing
// any file there. A seed with no network-config or vendor-data carries no
// such file. fresh is a new seed (GenerateISO), which its caller stamps only
// once this returns nil; a rebuild (RebuildISO) rewrites a seed already
// stamped as the VM's.
func writeISO(seed Seed, outputPath string, fresh bool) error {
	tmpDir, err := os.MkdirTemp("", "litevirt-cloudinit-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "meta-data"), []byte(seed.MetaData), 0644); err != nil {
		return fmt.Errorf("write meta-data: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "user-data"), []byte(seed.UserData), 0644); err != nil {
		return fmt.Errorf("write user-data: %w", err)
	}
	if seed.NetworkConfig != "" {
		if err := os.WriteFile(filepath.Join(tmpDir, "network-config"), []byte(seed.NetworkConfig), 0644); err != nil {
			return fmt.Errorf("write network-config: %w", err)
		}
	}
	if seed.VendorData != "" {
		if err := os.WriteFile(filepath.Join(tmpDir, "vendor-data"), []byte(seed.VendorData), 0644); err != nil {
			return fmt.Errorf("write vendor-data: %w", err)
		}
	}

	// Ensure output directory exists
	if err := diskmode.MkdirAll(filepath.Dir(outputPath)); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// The seed carries the user-data — passwords, keys, tokens — and is
	// attached to the guest as a disk, so it is owner-only like one
	// (internal/diskmode): genisoimage writes into a 0600 file made for it
	// (it keeps an existing file's mode), which then takes the seed's name.
	sweepStaleSeedTemps(outputPath)
	tmp := filepath.Join(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+"."+randid.New()+".tmp")
	if err := diskmode.Create(tmp); err != nil {
		return fmt.Errorf("create seed: %w", err)
	}
	defer os.Remove(tmp) // gone after the rename

	if err := buildISO(tmpDir, tmp); err != nil {
		return err
	}
	diskmode.NarrowBestEffort(tmp)
	// Durable, as the stamp is (StampSeed): the image's bytes reach the disk
	// before the rename makes it the seed, and the rename before this
	// returns. Every caller stamps the seed only after this returns, so a
	// stamp that survives a power cut never names an empty or truncated
	// seed.
	if err := syncFile(tmp); err != nil {
		return fmt.Errorf("sync seed: %w", err)
	}
	placed, err := os.Lstat(tmp)
	if err != nil {
		return fmt.Errorf("place seed: %w", err)
	}
	if err := renameFile(tmp, outputPath); err != nil {
		return fmt.Errorf("place seed: %w", err)
	}
	if err := syncDir(filepath.Dir(outputPath)); err != nil {
		if !fresh {
			return fmt.Errorf("sync seed directory: %w", err)
		}
		// A new seed whose name may not survive a power cut is not left at
		// the path, unstamped: its caller never records it, so nothing
		// would remove it, and it would hold the path a seed the create
		// moved aside (a kept one, at its .kept- name) is linked back to.
		// Only the file this wrote is removed. A rebuild keeps its seed:
		// the path held the VM's own, stamped, and has its new content.
		if cur, lerr := os.Lstat(outputPath); lerr == nil && os.SameFile(placed, cur) {
			if rerr := os.Remove(outputPath); rerr != nil && !os.IsNotExist(rerr) {
				return fmt.Errorf("sync seed directory: %w; the new seed is left at %s, and removing it failed: %v", err, outputPath, rerr)
			}
		}
		return fmt.Errorf("sync seed directory: %w; the new seed is not left in place", err)
	}
	clearSeedStale(outputPath)
	return nil
}

// staleSeedTempAge is how old a seed temp is before a later generation of the
// same seed removes it as a crashed run's: no genisoimage run takes that long,
// so a concurrent run's temp is never touched.
const staleSeedTempAge = time.Hour

// sweepStaleSeedTemps removes the temps of outputPath a run that died between
// making its temp and renaming it left behind: they hold the user-data. Best
// effort.
func sweepStaleSeedTemps(outputPath string) {
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+".*.tmp"))
	for _, m := range matches {
		fi, err := os.Lstat(m)
		if err != nil || !fi.Mode().IsRegular() || time.Since(fi.ModTime()) < staleSeedTempAge {
			continue
		}
		_ = os.Remove(m)
	}
}
