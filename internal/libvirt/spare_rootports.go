package libvirt

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Spare PCIe root ports for hot-plug on q35.
//
// A q35 guest hot-plugs a disk, NIC or PCI device into an empty
// pcie-root-port; with none free, libvirt fails the attach with "No more
// available PCI slots". The spares therefore have to be ports that NONE of
// the domain's own devices sit on, and only libvirt knows where it puts
// those: it places every device without an <address> on the first free
// port, including the controllers it adds by itself (qemu-xhci for USB,
// virtio-serial for the guest-agent channel), and it adds ports only for
// what is still unplaced. Declaring N unaddressed ports in the generated
// XML gives libvirt N ports to fill — on libvirt 10 a typical VM ends up
// with 5 ports and 0 free, where declaring none left it 6 and 1 free (see
// testdata/rootports_libvirt10_*.xml).
//
// So the spares are added AFTER libvirt has assigned addresses: define,
// read the persistent XML back, count the ports no device uses, and append
// the shortfall as new unaddressed ports. Every existing device already
// has its address by then, so the new ports stay empty. The count comes
// from libvirt's own assignment, not from a model of it, so it holds for
// any device set (hostdevs, SCSI controllers, legacy-PCI NICs) and any
// libvirt version's choice of implicit devices.

// spareRootPortElement is what a top-up inserts, once per missing port.
// No index and no address: libvirt picks the next free index and a slot on
// pcie-root, and nothing else can sit on a port it has just created.
const spareRootPortElement = "<controller type=\"pci\" model=\"pcie-root-port\"/>\n"

// FreePCIeRootPorts counts the pcie-root-port controllers in a domain XML
// and how many of them no device's guest PCI address sits on. A port is in
// use when some element's own <address type='pci' bus=N> names its index;
// a hostdev's <source><address> is the HOST device and is not counted. A
// port without an index (one a top-up inserted, not yet assigned by
// libvirt) is free.
func FreePCIeRootPorts(domXML string) (total, free int, err error) {
	dec := xml.NewDecoder(strings.NewReader(domXML))
	var stack []string
	ports := map[int]bool{} // index -> seen
	unindexed := 0
	used := map[int]bool{}
	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return 0, 0, fmt.Errorf("parse domain XML: %w", terr)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			attr := func(name string) string {
				for _, a := range t.Attr {
					if a.Name.Local == name {
						return a.Value
					}
				}
				return ""
			}
			// domain > devices > <device> > ...
			inDevice := len(stack) == 3 && stack[1] == "devices"
			deviceLevel := len(stack) == 2 && stack[1] == "devices"
			if deviceLevel && t.Name.Local == "controller" && attr("type") == "pci" && attr("model") == "pcie-root-port" {
				if s := attr("index"); s != "" {
					idx, perr := strconv.Atoi(s)
					if perr != nil {
						return 0, 0, fmt.Errorf("root port index %q: %w", s, perr)
					}
					ports[idx] = true
				} else {
					unindexed++
				}
			}
			if inDevice && t.Name.Local == "address" && attr("type") == "pci" {
				if s := attr("bus"); s != "" {
					bus, perr := strconv.ParseInt(s, 0, 32)
					if perr != nil {
						return 0, 0, fmt.Errorf("pci address bus %q: %w", s, perr)
					}
					used[int(bus)] = true
				}
			}
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	total = len(ports) + unindexed
	free = unindexed
	for idx := range ports {
		if !used[idx] {
			free++
		}
	}
	return total, free, nil
}

// TopUpSparePCIeRootPorts returns domXML with enough new, unaddressed
// pcie-root-port controllers appended to <devices> that at least want ports
// are free, and how many it added. domXML must be the domain as libvirt
// assigned it (DumpXMLInactive after a define): a port is only known to be
// spare once every device has its address. Everything libvirt wrote is left
// as it was. A non-q35 domain, or want <= 0, is returned unchanged.
func TopUpSparePCIeRootPorts(domXML string, want int) (string, int, error) {
	if want <= 0 {
		return domXML, 0, nil
	}
	if m := MachineTypeFromXML(domXML); m == "" || !isQ35Machine(m) {
		return domXML, 0, nil
	}
	_, free, err := FreePCIeRootPorts(domXML)
	if err != nil {
		return "", 0, err
	}
	missing := want - free
	if missing <= 0 {
		return domXML, 0, nil
	}
	i := strings.LastIndex(domXML, "</devices>")
	if i < 0 {
		return "", 0, fmt.Errorf("domain XML has no </devices>")
	}
	return domXML[:i] + strings.Repeat(spareRootPortElement, missing) + domXML[i:], missing, nil
}

// SpareRootPortDefiner is the slice of the libvirt client a top-up needs.
type SpareRootPortDefiner interface {
	DumpXMLInactive(name string) (string, error)
	DefineDomain(xmlConfig string) error
}

// EnsureSparePCIeRootPorts tops a just-defined domain up to want free
// pcie-root-ports (see TopUpSparePCIeRootPorts), redefining it only when it
// is short, and returns how many ports it added. Call it right after
// defining a domain from GenerateDomainXML. A domain that is already
// defined keeps its spares through every path that redefines it from its
// own XML, so this is the only place they come from.
func EnsureSparePCIeRootPorts(d SpareRootPortDefiner, name string, want int) (int, error) {
	if want <= 0 {
		return 0, nil
	}
	cur, err := d.DumpXMLInactive(name)
	if err != nil {
		return 0, fmt.Errorf("read %s back for spare root ports: %w", name, err)
	}
	next, added, err := TopUpSparePCIeRootPorts(cur, want)
	if err != nil || added == 0 {
		return 0, err
	}
	if err := d.DefineDomain(next); err != nil {
		return 0, fmt.Errorf("redefine %s with %d spare root ports: %w", name, added, err)
	}
	return added, nil
}
