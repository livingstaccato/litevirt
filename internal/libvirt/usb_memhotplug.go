package libvirt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// ── USB passthrough ──

// USBHostdevConfig is one USB device to pass through, already resolved on the
// host that defines the domain: either a vendor:product pair (4 lower-case hex
// digits each, no 0x) or a bus/device address as the host enumerated it.
// Exactly one form is set.
type USBHostdevConfig struct {
	Vendor  string
	Product string
	Bus     int
	Device  int
}

// USBDeviceRef is a USB device as a user or a resource mapping names it: by
// vendor:product, or by physical bus-port. It is resolved to a
// USBHostdevConfig on the host that runs the VM (ResolveUSBDevice).
type USBDeviceRef struct {
	Vendor  string
	Product string
	BusPort string
}

var (
	usbIDRe = regexp.MustCompile(`^[0-9a-f]{4}$`)
	// usbBusPortRe is "<bus>-<port>[.<port>...]", the name sysfs gives a USB
	// device by where it is plugged in. Digits only, so it can never name a
	// path outside /sys/bus/usb/devices.
	usbBusPortRe = regexp.MustCompile(`^[1-9][0-9]{0,2}-[1-9][0-9]{0,2}(\.[1-9][0-9]{0,2}){0,6}$`)
)

// NormalizeUSBID lower-cases a vendor or product id, strips an optional 0x,
// and reports whether it is 4 hex digits.
func NormalizeUSBID(id string) (string, bool) {
	id = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(id)), "0x")
	return id, usbIDRe.MatchString(id)
}

// ValidUSBBusPort reports whether p is a well-formed bus-port name.
func ValidUSBBusPort(p string) bool { return usbBusPortRe.MatchString(p) }

// ParseUSBMappingAddress parses a resource-mapping device address that names a
// USB device: "usb:<vendor>:<product>" or "usb:<bus>-<port>[.<port>...]".
func ParseUSBMappingAddress(addr string) (USBDeviceRef, error) {
	rest, ok := strings.CutPrefix(addr, "usb:")
	if !ok {
		return USBDeviceRef{}, fmt.Errorf("%q is not a USB device address (want usb:<vendor>:<product> or usb:<bus>-<port>)", addr)
	}
	if v, p, pair := strings.Cut(rest, ":"); pair {
		vendor, vok := NormalizeUSBID(v)
		product, pok := NormalizeUSBID(p)
		if !vok || !pok {
			return USBDeviceRef{}, fmt.Errorf("USB device address %q: vendor and product must be 4 hex digits each", addr)
		}
		return USBDeviceRef{Vendor: vendor, Product: product}, nil
	}
	if !ValidUSBBusPort(rest) {
		return USBDeviceRef{}, fmt.Errorf("USB device address %q: want usb:<vendor>:<product> or usb:<bus>-<port>[.<port>...]", addr)
	}
	return USBDeviceRef{BusPort: rest}, nil
}

// usbSysfsRoot is where the host lists its USB devices by bus-port.
var usbSysfsRoot = "/sys/bus/usb/devices"

// SetUSBSysfsRootForTest points bus-port resolution at a fake sysfs tree and
// returns a restore func.
func SetUSBSysfsRootForTest(root string) (restore func()) {
	old := usbSysfsRoot
	usbSysfsRoot = root
	return func() { usbSysfsRoot = old }
}

// ResolveUSBBusPort reads the bus and device numbers the host currently gives
// the device plugged into port. They change when the device is re-plugged, so
// they are resolved each time a domain is defined, never stored.
func ResolveUSBBusPort(port string) (USBHostdevConfig, error) {
	if !ValidUSBBusPort(port) {
		return USBHostdevConfig{}, fmt.Errorf("USB bus-port %q is malformed (want <bus>-<port>[.<port>...])", port)
	}
	read := func(f string) (int, error) {
		b, err := os.ReadFile(filepath.Join(usbSysfsRoot, port, f))
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%s/%s: %q is not a positive number", port, f, strings.TrimSpace(string(b)))
		}
		return n, nil
	}
	bus, err := read("busnum")
	if err != nil {
		return USBHostdevConfig{}, fmt.Errorf("no USB device on port %s of this host: %w", port, err)
	}
	dev, err := read("devnum")
	if err != nil {
		return USBHostdevConfig{}, fmt.Errorf("no USB device on port %s of this host: %w", port, err)
	}
	return USBHostdevConfig{Bus: bus, Device: dev}, nil
}

// ResolveUSBDevice turns a device reference into the hostdev this host defines.
// A vendor:product pair needs no host lookup (libvirt finds the device when the
// domain starts); a bus-port is read from this host's sysfs.
func ResolveUSBDevice(ref USBDeviceRef) (USBHostdevConfig, error) {
	if ref.BusPort != "" {
		if ref.Vendor != "" || ref.Product != "" {
			return USBHostdevConfig{}, fmt.Errorf("a USB device is named by vendor:product or by bus-port, not both")
		}
		return ResolveUSBBusPort(ref.BusPort)
	}
	vendor, vok := NormalizeUSBID(ref.Vendor)
	product, pok := NormalizeUSBID(ref.Product)
	if !vok || !pok {
		return USBHostdevConfig{}, fmt.Errorf("USB device %q:%q: vendor and product must be 4 hex digits each", ref.Vendor, ref.Product)
	}
	return USBHostdevConfig{Vendor: vendor, Product: product}, nil
}

// usbHostdev renders one USB passthrough hostdev, refusing a config that is
// not exactly one well-formed form.
func usbHostdev(u USBHostdevConfig) (hostdevDevice, error) {
	hd := hostdevDevice{Mode: "subsystem", Type: "usb", Managed: "yes"}
	byID := u.Vendor != "" || u.Product != ""
	byAddr := u.Bus != 0 || u.Device != 0
	switch {
	case byID && byAddr:
		return hd, fmt.Errorf("USB hostdev %+v names both an id and an address", u)
	case byID:
		v, vok := NormalizeUSBID(u.Vendor)
		p, pok := NormalizeUSBID(u.Product)
		if !vok || !pok {
			return hd, fmt.Errorf("USB hostdev %q:%q: vendor and product must be 4 hex digits each", u.Vendor, u.Product)
		}
		hd.Source.Vendor = &hostdevUSBID{ID: "0x" + v}
		hd.Source.Product = &hostdevUSBID{ID: "0x" + p}
	case byAddr:
		if u.Bus <= 0 || u.Device <= 0 {
			return hd, fmt.Errorf("USB hostdev bus %d device %d: both must be positive", u.Bus, u.Device)
		}
		hd.Source.Address = &hostdevAddress{Bus: strconv.Itoa(u.Bus), Device: strconv.Itoa(u.Device)}
	default:
		return hd, fmt.Errorf("USB hostdev names no device")
	}
	return hd, nil
}

// reUSBHostdev matches one complete USB <hostdev> element in libvirt's
// serialized XML (single- or double-quoted attributes), including the
// indentation before it and the newline after it.
var reUSBHostdev = regexp.MustCompile(`(?s)[ \t]*<hostdev\b[^>]*\btype=['"]usb['"][^>]*>.*?</hostdev>[ \t]*\n?`)

// ReplaceUSBHostdevs returns domXML with every USB hostdev removed and usb
// rendered in their place, inside <devices>; everything else is kept verbatim.
// A cold migration uses it: the source's definition names the source host's
// device, and the target defines the one its own mapping entry names.
func ReplaceUSBHostdevs(domXML string, usb []USBHostdevConfig) (string, error) {
	out := reUSBHostdev.ReplaceAllString(domXML, "")
	if len(usb) == 0 {
		return out, nil
	}
	var b strings.Builder
	for _, u := range usb {
		hd, err := usbHostdev(u)
		if err != nil {
			return "", err
		}
		x, err := xml.Marshal(hd)
		if err != nil {
			return "", fmt.Errorf("render USB hostdev: %w", err)
		}
		b.WriteString("    ")
		b.Write(x)
		b.WriteString("\n")
	}
	i := strings.LastIndex(out, "</devices>")
	if i < 0 {
		return "", fmt.Errorf("domain XML has no </devices> to add USB hostdevs to")
	}
	return out[:i] + b.String() + "  " + out[i:], nil
}

// ── Memory hot-add (virtio-mem) ──

// memoryHotplugSlots is <maxMemory slots>. virtio-mem consumes no slot, but
// libvirt requires the attribute. <maxMemory> equals the region's top, so no
// DIMM fits beside it: one slot, and no claim of room for more.
const memoryHotplugSlots = 1

// virtioMemBlockKiB is the virtio-mem block size: the granularity memory is
// plugged in, and the alignment the region and every request must keep. 2 MiB
// matches x86 transparent hugepages and the 2 MiB hugepage size.
const virtioMemBlockKiB = 2048

// validateMemoryHotplug checks the hot-add band before anything is rendered:
// a boot cell, a region above it that is a whole number of blocks, the current
// size inside [base, max], and no balloon ceiling beside it (the two describe
// <memory> differently).
func validateMemoryHotplug(cfg VMConfig) error {
	base, max, cur := cfg.HotplugBaseMiB, cfg.HotplugMaxMiB, cfg.MemoryMiB
	switch {
	case base <= 0:
		return fmt.Errorf("memory hot-add needs a boot memory size (got %d MiB)", base)
	case max <= base:
		return fmt.Errorf("memory hot-add maximum %d MiB must be above the boot memory %d MiB", max, base)
	case ((max-base)*1024)%virtioMemBlockKiB != 0:
		return fmt.Errorf("memory hot-add region %d MiB (maximum minus boot memory) must be a multiple of %d MiB", max-base, virtioMemBlockKiB/1024)
	case cur < base || cur > max:
		return fmt.Errorf("memory %d MiB is outside the hot-add band [%d, %d] MiB", cur, base, max)
	case ((cur-base)*1024)%virtioMemBlockKiB != 0:
		return fmt.Errorf("hot-added memory %d MiB must be a multiple of %d MiB", cur-base, virtioMemBlockKiB/1024)
	case cfg.MaxMemoryMiB > cur || cfg.MinMemoryMiB > 0:
		return fmt.Errorf("memory hot-add and a balloon band (min/max memory) cannot be combined")
	case cfg.HugePages:
		// The 2 MiB block cannot be plugged into memory backed by larger
		// hugepages (1 GiB on many hosts), so the pair is refused up front
		// rather than failing at define or start.
		return fmt.Errorf("memory hot-add and hugepages cannot be combined")
	}
	return nil
}

// virtioMemDevice is the virtio-mem device covering regionMiB, with
// requestedMiB plugged, on guest NUMA node 0.
func virtioMemDevice(regionMiB, requestedMiB int) *memoryDevice {
	return &memoryDevice{
		Model: "virtio-mem",
		Target: memoryTarget{
			Size:      memSize{Unit: "KiB", Value: regionMiB * 1024},
			Node:      0,
			Block:     memSize{Unit: "KiB", Value: virtioMemBlockKiB},
			Requested: memSize{Unit: "KiB", Value: requestedMiB * 1024},
		},
	}
}

type maxMemory struct {
	Slots int    `xml:"slots,attr"`
	Unit  string `xml:"unit,attr"`
	Value int    `xml:",chardata"`
}

type cpuNuma struct {
	Cells []numaCell `xml:"cell"`
}

type numaCell struct {
	ID     int    `xml:"id,attr"`
	CPUs   string `xml:"cpus,attr"`
	Memory int    `xml:"memory,attr"`
	Unit   string `xml:"unit,attr"`
}

type memoryDevice struct {
	Model  string       `xml:"model,attr"`
	Target memoryTarget `xml:"target"`
}

type memoryTarget struct {
	Size      memSize `xml:"size"`
	Node      int     `xml:"node"`
	Block     memSize `xml:"block"`
	Requested memSize `xml:"requested"`
}

type memSize struct {
	Unit  string `xml:"unit,attr"`
	Value int    `xml:",chardata"`
}

var (
	reVirtioMemElem = regexp.MustCompile(`(?s)<memory\b[^>]*\bmodel=['"]virtio-mem['"][^>]*>.*?</memory>`)
	reVirtioMemSize = regexp.MustCompile(`<size\b[^>]*>(\d+)</size>`)
	reVirtioMemReq  = regexp.MustCompile(`(<requested\b[^>]*>)\d+(</requested>)`)
	reMemUnit       = regexp.MustCompile(`\bunit=['"]([A-Za-z]+)['"]`)
)

// VirtioMemUpdateXML returns the domain's virtio-mem element with its
// requested size set to requestedMiB — the element DomainUpdateDeviceFlags
// takes to plug or unplug memory. Everything else in the element (its alias
// and address, which libvirt matches the device by) is kept verbatim. Refuses
// a request outside [0, region].
func VirtioMemUpdateXML(domXML string, requestedMiB int) (string, error) {
	elem := reVirtioMemElem.FindString(domXML)
	if elem == "" {
		return "", ErrNoVirtioMem
	}
	if requestedMiB < 0 {
		return "", fmt.Errorf("hot-added memory %d MiB is negative", requestedMiB)
	}
	if m := reVirtioMemSize.FindStringSubmatch(elem); m != nil {
		sizeKiB, _ := strconv.Atoi(m[1])
		if u := reMemUnit.FindStringSubmatch(m[0]); u != nil && !strings.EqualFold(u[1], "KiB") && !strings.EqualFold(u[1], "k") {
			return "", fmt.Errorf("virtio-mem size is in %s, expected KiB", u[1])
		}
		if requestedMiB*1024 > sizeKiB {
			return "", fmt.Errorf("hot-added memory %d MiB exceeds the virtio-mem region %d MiB", requestedMiB, sizeKiB/1024)
		}
	}
	if !reVirtioMemReq.MatchString(elem) {
		return "", fmt.Errorf("virtio-mem device has no <requested> size")
	}
	return reVirtioMemReq.ReplaceAllString(elem, fmt.Sprintf("${1}%d${2}", requestedMiB*1024)), nil
}

// SetVirtioMemRequested sets how much of a domain's virtio-mem region is
// plugged, in MiB: the PERSISTENT definition first (its error propagates, so a
// live change never lands on top of a rejected persistent one), then the live
// domain when it runs. The guest onlines (or offlines) the blocks itself.
func (c *Client) SetVirtioMemRequested(domainName string, requestedMiB int) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	inactive, err := c.DumpXMLInactive(domainName)
	if err != nil {
		return err
	}
	elem, err := VirtioMemUpdateXML(inactive, requestedMiB)
	if err != nil {
		return fmt.Errorf("domain %q: %w", domainName, err)
	}
	if err := c.virt.DomainUpdateDeviceFlags(dom, elem, golibvirt.DomainDeviceModifyConfig); err != nil {
		return fmt.Errorf("set hot-added memory of %q to %d MiB (config): %w", domainName, requestedMiB, err)
	}
	active, err := c.virt.DomainIsActive(dom)
	if err != nil {
		return fmt.Errorf("domain %q is-active: %w", domainName, err)
	}
	if active == 0 {
		return nil
	}
	live, err := c.DumpXML(domainName)
	if err != nil {
		return err
	}
	if elem, err = VirtioMemUpdateXML(live, requestedMiB); err != nil {
		return fmt.Errorf("running domain %q: %w", domainName, err)
	}
	if err := c.virt.DomainUpdateDeviceFlags(dom, elem, golibvirt.DomainDeviceModifyLive); err != nil {
		return fmt.Errorf("set hot-added memory of %q to %d MiB (live): %w", domainName, requestedMiB, err)
	}
	return nil
}

// ErrNoVirtioMem is a hot-add change on a domain defined without a virtio-mem
// device: a definition that drifted from its spec. Retrying cannot fix it.
var ErrNoVirtioMem = errors.New("domain has no virtio-mem device (memory hot-add is not configured in its definition)")

// HasVirtioMem reports whether a domain XML carries a virtio-mem device.
func HasVirtioMem(domXML string) bool { return reVirtioMemElem.MatchString(domXML) }

var reVirtioMemCurrent = regexp.MustCompile(`<current\b[^>]*>(\d+)</current>`)

// VirtioMemCurrentMiB is how much of the virtio-mem region the guest has
// actually plugged (<current>, which libvirt reports in the live XML), and
// whether the domain reports it at all. It can lag <requested> — a guest that
// cannot offline its memory keeps it — so it, not the request, is what the
// host is holding.
func VirtioMemCurrentMiB(domXML string) (int, bool) {
	elem := reVirtioMemElem.FindString(domXML)
	if elem == "" {
		return 0, false
	}
	m := reVirtioMemCurrent.FindStringSubmatch(elem)
	if m == nil {
		return 0, false
	}
	kib, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return kib / 1024, true
}

var (
	reNumaCellMemory  = regexp.MustCompile(`<cell\b[^>]*\bmemory=['"](\d+)['"]`)
	reVirtioMemReqKiB = regexp.MustCompile(`<requested\b[^>]*>(\d+)</requested>`)
)

// HeldMemoryMiBFromXML is the memory a domain holds, in MiB. For a hot-add
// domain that is its NUMA cells (the boot memory) plus the larger of the
// virtio-mem size requested and the size the guest has actually plugged:
// never the whole region, and never less than the guest still holds. Any
// other domain is CurrentMemoryMiBFromXML.
func HeldMemoryMiBFromXML(domXML string) int {
	elem := reVirtioMemElem.FindString(domXML)
	if elem == "" {
		return CurrentMemoryMiBFromXML(domXML)
	}
	cellsKiB := 0
	for _, m := range reNumaCellMemory.FindAllStringSubmatch(domXML, -1) {
		n, _ := strconv.Atoi(m[1])
		cellsKiB += n
	}
	plugged := 0
	if m := reVirtioMemReqKiB.FindStringSubmatch(elem); m != nil {
		plugged, _ = strconv.Atoi(m[1])
	}
	if m := reVirtioMemCurrent.FindStringSubmatch(elem); m != nil {
		if cur, _ := strconv.Atoi(m[1]); cur > plugged {
			plugged = cur
		}
	}
	return (cellsKiB + plugged) / 1024
}
