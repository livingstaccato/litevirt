package cloudinit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Seed is the files of a NoCloud seed. NetworkConfig and VendorData are ""
// for a seed with no such file.
type Seed struct {
	MetaData, UserData, NetworkConfig, VendorData string
}

// InstanceID is the instance-id the seed's meta-data names, "" for none.
func (s Seed) InstanceID() string {
	for _, line := range strings.Split(s.MetaData, "\n") {
		if v, ok := strings.CutPrefix(line, "instance-id:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// RebuildISO replaces the network-config and vendor-data of the seed at path
// with networkConfig and vendorData ("" for none) and keeps its meta-data and
// user-data byte for byte, so cloud-init never sees a new instance (a new
// instance-id would run first boot again). It reports whether the seed was
// rewritten: a seed that already carries both is left as it is. A seed that
// cannot be read, or names no instance-id, is left as it is and is an error.
func RebuildISO(path, networkConfig, vendorData string) (bool, error) {
	seed, err := ReadSeed(path)
	if err != nil {
		return false, err
	}
	if seed.InstanceID() == "" {
		return false, fmt.Errorf("seed %s names no instance-id", path)
	}
	if seed.NetworkConfig == networkConfig && seed.VendorData == vendorData {
		return false, nil
	}
	seed.NetworkConfig, seed.VendorData = networkConfig, vendorData
	if err := writeISO(seed, path); err != nil {
		return false, err
	}
	return true, nil
}

const (
	isoSector = 2048
	// maxSeedFile bounds what one seed file read may allocate.
	maxSeedFile = 64 << 20
)

// ReadSeed reads the NoCloud seed at path, an ISO 9660 image with Rock Ridge
// names as GenerateISO writes it (genisoimage -rock). meta-data is required;
// user-data, network-config and vendor-data are "" when the image has none.
func ReadSeed(path string) (Seed, error) {
	f, err := os.Open(path)
	if err != nil {
		return Seed{}, err
	}
	defer f.Close()
	files, err := isoRootFiles(f)
	if err != nil {
		return Seed{}, fmt.Errorf("read seed %s: %w", path, err)
	}
	read := func(name string) (string, bool, error) {
		e, ok := files[name]
		if !ok {
			return "", false, nil
		}
		if e.size > maxSeedFile {
			return "", false, fmt.Errorf("read seed %s: %s is %d bytes", path, name, e.size)
		}
		b := make([]byte, e.size)
		if _, err := f.ReadAt(b, int64(e.extent)*isoSector); err != nil {
			return "", false, fmt.Errorf("read seed %s: %s: %w", path, name, err)
		}
		return string(b), true, nil
	}
	var s Seed
	var ok bool
	if s.MetaData, ok, err = read("meta-data"); err != nil {
		return Seed{}, err
	} else if !ok {
		return Seed{}, fmt.Errorf("read seed %s: no meta-data", path)
	}
	if s.UserData, _, err = read("user-data"); err != nil {
		return Seed{}, err
	}
	if s.NetworkConfig, _, err = read("network-config"); err != nil {
		return Seed{}, err
	}
	if s.VendorData, _, err = read("vendor-data"); err != nil {
		return Seed{}, err
	}
	return s, nil
}

type isoFile struct {
	extent, size uint32
}

// isoRootFiles lists the regular files of the root directory of the ISO 9660
// image r by their Rock Ridge names. An entry with no Rock Ridge name is not
// listed.
func isoRootFiles(r io.ReaderAt) (map[string]isoFile, error) {
	pvd := make([]byte, isoSector)
	if _, err := r.ReadAt(pvd, 16*isoSector); err != nil {
		return nil, fmt.Errorf("no ISO 9660 volume descriptor: %w", err)
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return nil, errors.New("not an ISO 9660 image")
	}
	root := pvd[156 : 156+34]
	extent := binary.LittleEndian.Uint32(root[2:6])
	size := binary.LittleEndian.Uint32(root[10:14])
	if size == 0 || size > maxSeedFile {
		return nil, fmt.Errorf("root directory of %d bytes", size)
	}
	dir := make([]byte, size)
	if _, err := r.ReadAt(dir, int64(extent)*isoSector); err != nil {
		return nil, fmt.Errorf("read root directory: %w", err)
	}
	out := map[string]isoFile{}
	for off := 0; off < len(dir); {
		n := int(dir[off])
		if n == 0 {
			// Records do not cross a sector; the rest of this one is padding.
			off = (off/isoSector + 1) * isoSector
			continue
		}
		if n < 34 || off+n > len(dir) {
			return nil, errors.New("malformed directory record")
		}
		rec := dir[off : off+n]
		off += n
		if rec[25]&0x02 != 0 { // a directory, "." or ".." among them
			continue
		}
		idLen := int(rec[32])
		su := 33 + idLen
		if idLen%2 == 0 {
			su++ // padding byte after an even-length identifier
		}
		if su > len(rec) {
			return nil, errors.New("malformed directory record")
		}
		if name := rockRidgeName(rec[su:]); name != "" {
			out[name] = isoFile{extent: binary.LittleEndian.Uint32(rec[2:6]), size: binary.LittleEndian.Uint32(rec[10:14])}
		}
	}
	return out, nil
}

// rockRidgeName is the name the Rock Ridge NM entries of a directory record's
// system use area spell, "" for none.
func rockRidgeName(su []byte) string {
	var name bytes.Buffer
	for len(su) >= 4 {
		l := int(su[2])
		if l < 4 || l > len(su) {
			break
		}
		if su[0] == 'N' && su[1] == 'M' && l >= 5 {
			name.Write(su[5:l])
		}
		su = su[l:]
	}
	return name.String()
}

// NetworkUpdatesVendorData is the vendor-data of a seed whose network-config
// litevirt writes. It enables cloud-init's network update events, so the
// guest applies the seed's network-config again on every boot and on a NIC
// hot-plug (cloud-init "Events and updates"), not only on a new instance's
// first boot: a NIC attached since then is configured. cloud-init merges
// user-data over vendor-data, so `updates:` in the user-data wins.
const NetworkUpdatesVendorData = "#cloud-config\nupdates:\n  network:\n    when: [boot-new-instance, boot, hotplug]\n"

// SeedVendorData is the vendor-data of a seed whose network-config is
// networkConfig, for a VM with spec (nil for one whose network-config is
// litevirt's by construction, a clone's): NetworkUpdatesVendorData when
// litevirt writes that network-config, none when the spec names its own or
// there is none — a VM litevirt writes none for boots on cloud-init's
// fallback, which is not re-rendered on every boot.
func SeedVendorData(spec *pb.VMSpec, networkConfig string) string {
	if spec.GetCloudInit().GetNetworkconfig() != "" || networkConfig == "" {
		return ""
	}
	return NetworkUpdatesVendorData
}

// NetworkUpdatesOffVendorData is the vendor-data of a seed litevirt writes
// with no network-config of its own making (NetworkConfigDisabled): it turns
// cloud-init's per-boot network update events back off, so a guest that
// recorded NetworkUpdatesVendorData on an earlier boot stops re-rendering its
// network. cloud-init applies a seed's vendor-data from the boot after the
// one that records it; NetworkConfigDisabled covers the boot between.
const NetworkUpdatesOffVendorData = "#cloud-config\nupdates:\n  network:\n    when: [boot-new-instance]\n"

// NetworkConfigDisabled is the network-config litevirt writes where it cannot
// tell the VM's NICs and keeps no seed of the VM's (cloudinit.ErrNICsAmbiguous
// on a host without one). cloud-init reads a datasource network config of
// `config: disabled` as "render nothing" (net.is_disabled_cfg) on every boot,
// whatever update events are enabled, so the guest keeps the network it has
// rendered — where a seed with no network-config would have it render its
// fallback, DHCP on one NIC.
const NetworkConfigDisabled = "network:\n  config: disabled\n"

// SeedClaim is what a host knows of the VM a seed at its path may belong to.
type SeedClaim struct {
	VMName string
	// UUID is the VM's spec uuid (SpecUUID), "" for a VM from before them.
	UUID string
	// CloudInit is whether the VM's spec has cloud-init (SpecHasCloudInit).
	CloudInit bool
	// DomainXML returns the VM's current domain definition on this host,
	// read from libvirt: "" when the host has none or it could not be read.
	// It is called only for an unstamped seed; nil reads as none.
	DomainXML func() string
}

// SpecHasCloudInit reports whether a VM with spec boots on a seed: a cloud
// image, or a spec with a cloud-init section. Any seed at the path of a VM
// without either is not the VM's.
func SpecHasCloudInit(spec *pb.VMSpec) bool {
	return spec.GetImage() != "" || spec.GetCloudInit() != nil
}

// OwnSeed reads the seed at iso and reports whether it is the seed of the VM
// c describes. Only a VM whose spec has cloud-init owns a seed. Then:
//   - a seed stamped (StampSeed) for the VM's uuid is its own; one stamped for
//     another uuid is not;
//   - an unstamped seed (written before seeds were stamped) is its own only
//     when the VM's current domain definition on this host attaches exactly
//     that file as its cdrom (so the guest already boots from it), the
//     domain is not another VM's (its uuid, when both are known), and its
//     instance-id is one the VM's create wrote: its name, or <name>-next, the
//     name a replacement is created under before a cutover gives it the name
//     (vm_replace). The instance-id is the VM's name, so it cannot tell a
//     deleted VM of the name from this one: an unstamped seed such a VM left
//     on this host is never this VM's on that ground alone.
//
// The error is fs.ErrNotExist for no seed, or the read's.
func OwnSeed(iso string, c SeedClaim) (Seed, bool, error) {
	owner, stamped, err := SeedOwner(iso)
	if err != nil {
		return Seed{}, false, err
	}
	seed, err := ReadSeed(iso)
	if err != nil {
		return Seed{}, false, err
	}
	if !c.CloudInit {
		return seed, false, nil
	}
	if stamped {
		return seed, c.UUID != "" && owner == c.UUID, nil
	}
	domXML := ""
	if c.DomainXML != nil {
		domXML = c.DomainXML()
	}
	if !lv.DomainAttachesCDROM(domXML, iso) {
		return seed, false, nil
	}
	if dom := lv.UUIDFromXML(domXML); c.UUID != "" && dom != "" && !strings.EqualFold(dom, c.UUID) {
		return seed, false, nil
	}
	id := seed.InstanceID()
	return seed, id != "" && (id == c.VMName || id == c.VMName+"-next"), nil
}
