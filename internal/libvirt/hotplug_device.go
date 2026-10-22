package libvirt

import (
	"encoding/xml"
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// AttachDisk hot-attaches a disk to a running domain.
func (c *Client) AttachDisk(domainName string, path, targetDev, bus string) error {
	cache := "writeback"
	disk := diskDevice{
		Type:   "file",
		Device: "disk",
		Driver: diskDriver{Name: "qemu", Type: "qcow2", Cache: cache},
		Source: diskSource{File: path},
		Target: diskTarget{Dev: targetDev, Bus: bus},
	}
	return c.attachDeviceXML(domainName, disk)
}

// DetachDisk hot-detaches a disk from a running domain by target device name.
//
// The device element carries the disk's REAL type and source, read from the live
// domain, for the reason libvirt gives: the supplied description "should be as
// specific as its definition in the domain XML", and a partial one "may lead to
// unexpected results" — the same trap DetachNIC fell into. The live domain is read
// first, then the persistent definition, because a retry can find the disk left in
// only one of them (see DetachLiveAndConfig). Falls back to the target-only shape
// when neither holds it, where the detach is a no-op anyway.
//
// Note this only makes the REQUEST specific. The unplug itself is asynchronous and
// needs the guest's cooperation, so a nil return means "requested", not "gone";
// callers verify absence by waiting (see grpcapi's verifyDiskDetached).
func (c *Client) DetachDisk(domainName, targetDev string) error {
	return c.detachDeviceXML(domainName, diskForDetach(targetDev, c.domainCopies(domainName)...))
}

// domainCopies reads a running domain's live XML, then its persistent XML: the
// order a detach looks for the device to describe in.
func (c *Client) domainCopies(domainName string) []func() (string, error) {
	return []func() (string, error){
		func() (string, error) { return c.DumpXML(domainName) },
		func() (string, error) { return c.DumpXMLInactive(domainName) },
	}
}

// diskForDetach is the <disk> element DetachDisk sends: the disk's type and
// source from the first copy that holds targetDev (an unreadable copy is
// skipped), or the target-only shape when none does.
func diskForDetach(targetDev string, copies ...func() (string, error)) diskDevice {
	disk := diskDevice{
		Type:   "file",
		Device: "disk",
		Target: diskTarget{Dev: targetDev},
	}
	for _, read := range copies {
		xmlText, err := read()
		if err != nil {
			continue
		}
		if typ, src, ok := DiskSourceByTarget(xmlText, targetDev); ok {
			disk.Type = typ
			disk.Source = src
			break
		}
	}
	return disk
}

// AttachNIC hot-attaches a network interface to a running domain.
func (c *Client) AttachNIC(domainName, bridge, model, mac string) error {
	return c.attachDeviceXML(domainName, bridgeInterface(bridge, model, mac))
}

// DetachNIC hot-detaches a network interface by MAC address.
//
// The device element must carry the interface's REAL type and source. libvirt
// parses and validates it, and a MAC alone marshals to `type="bridge"` with an
// EMPTY <source>, which fails validation with "Missing required attribute
// 'bridge' in element 'source'" — an error that describes the XML we sent, not
// anything the operator did. Reading the live domain and reusing the
// interface's own type/source keeps the element valid (and correct for a
// non-bridge source). The live domain is read first, then the persistent
// definition: a retry can find the NIC left in only the persistent copy (see
// DetachLiveAndConfig), and the element must still be valid then. Falls back to
// the MAC-only shape when NEITHER holds it — callers guard against that case first
// (see detachNICIfPresent), so the fallback exists only for callers that skip
// the guard, and libvirt's validation error is the honest outcome there.
func (c *Client) DetachNIC(domainName, mac string) error {
	return c.detachDeviceXML(domainName, interfaceForDetach(mac, c.domainCopies(domainName)...))
}

// interfaceForDetach is the <interface> element DetachNIC sends: the
// interface's type and source from the first copy that holds mac (an unreadable
// copy is skipped), or the MAC-only shape when none does.
func interfaceForDetach(mac string, copies ...func() (string, error)) interfaceDevice {
	iface := interfaceDevice{
		Type: "bridge",
		MAC:  ifaceMAC{Address: mac},
	}
	for _, read := range copies {
		xmlText, err := read()
		if err != nil {
			continue
		}
		if typ, src, ok := InterfaceSourceByMAC(xmlText, mac); ok {
			iface.Type = typ
			iface.Source = src
			break
		}
	}
	return iface
}

// AttachHostdev hot-attaches a PCI device to a running domain.
func (c *Client) AttachHostdev(domainName, pciAddress string) error {
	addr, err := pciHostdevAddress(pciAddress)
	if err != nil {
		return err
	}
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source:  hostdevSource{Address: addr},
	}
	return c.attachDeviceXML(domainName, hd)
}

// AttachHostdevWithAlias hot-attaches a PCI device to a running domain carrying a
// stable user alias (ua-<device>-<member>), so the device is addressable by that
// alias in the persistent definition (the topology-preserving reconcile keys
// hostdevs by their <alias>). An empty alias behaves exactly like AttachHostdev.
func (c *Client) AttachHostdevWithAlias(domainName, pciAddress, alias string) error {
	addr, err := pciHostdevAddress(pciAddress)
	if err != nil {
		return err
	}
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source:  hostdevSource{Address: addr},
	}
	if alias != "" {
		hd.Alias = &hostdevAlias{Name: alias}
	}
	return c.attachDeviceXML(domainName, hd)
}

// DetachHostdev hot-detaches a PCI device from a running domain.
func (c *Client) DetachHostdev(domainName, pciAddress string) error {
	addr, err := pciHostdevAddress(pciAddress)
	if err != nil {
		return err
	}
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source:  hostdevSource{Address: addr},
	}
	return c.detachDeviceXML(domainName, hd)
}

// DetachHostdevConfig removes a PCI device from a domain's PERSISTENT definition ONLY
// (DomainDeviceModifyConfig, no Live flag). It is the counterpart to DetachHostdev for a
// SHUT-OFF domain, whose nonexistent live instance would reject a Live-flagged modify:
// this detaches the hostdev from the config a cold boot loads without touching a live
// domain. Same device XML as DetachHostdev — only the modify flags differ.
func (c *Client) DetachHostdevConfig(domainName, pciAddress string) error {
	addr, err := pciHostdevAddress(pciAddress)
	if err != nil {
		return err
	}
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source:  hostdevSource{Address: addr},
	}
	return c.detachDeviceXMLConfig(domainName, hd)
}

// attachDeviceXML marshals a device to XML and attaches it via libvirt API (live + persistent).
func (c *Client) attachDeviceXML(domainName string, device any) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	data, err := xml.MarshalIndent(device, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device XML: %w", err)
	}
	flags := uint32(golibvirt.DomainDeviceModifyLive | golibvirt.DomainDeviceModifyConfig)
	if err := c.virt.DomainAttachDeviceFlags(dom, string(data), flags); err != nil {
		return fmt.Errorf("attach device to %s: %w", domainName, err)
	}
	return nil
}

// detachDeviceXML marshals a device to XML and detaches it via libvirt API (live + persistent).
func (c *Client) detachDeviceXML(domainName string, device any) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	data, err := xml.MarshalIndent(device, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device XML: %w", err)
	}
	err = DetachLiveAndConfig(func(flags uint32) error {
		return c.virt.DomainDetachDeviceFlags(dom, string(data), flags)
	})
	if err != nil {
		return fmt.Errorf("detach device from %s: %w", domainName, err)
	}
	return nil
}

// The virDomainModificationImpact flags a detach addresses: the running domain,
// its persistent definition, or both.
const (
	ModifyLive   = uint32(golibvirt.DomainDeviceModifyLive)
	ModifyConfig = uint32(golibvirt.DomainDeviceModifyConfig)
)

// DetachLiveAndConfig runs one device detach, given as detach(flags), against a
// running domain's live instance AND its persistent definition, and detaches from
// whichever of the two still holds the device.
//
// A single LIVE|CONFIG call is not enough on a retry. libvirt applies it
// all-or-nothing (qemuDomainDetachDeviceLiveAndConfig): when either copy lacks the
// device the whole call fails with VIR_ERR_DEVICE_MISSING and the other half is not
// applied. The copies diverge in exactly the case a retry exists for: the first
// detach removes the device from the persistent definition at once but only
// REQUESTS the live unplug, and a guest still booting drops that eject. From then on
// every LIVE|CONFIG retry fails on the config half and the live unplug is never
// re-issued (lab finding N1: the VM's operation barrier held for >9 minutes until a
// manual `virsh detach-interface --live`). The opposite divergence, live gone and
// persistent copy left, fails the same way on the live half.
//
// So: try LIVE|CONFIG (the common case, one call). Only on VIR_ERR_DEVICE_MISSING,
// ask each copy on its own, and treat DEVICE_MISSING from that copy as "this copy
// is already clear". Every other error is returned as it stands.
//
// A nil return therefore means libvirt accepted the detach for every copy that held
// the device, or both copies reported it missing. It never means "gone": the live
// half only requests the unplug, and callers still verify absence. Classification
// is by the TYPED error code only (IsDeviceMissing), so nothing that merely reads
// like "not found" — a dead connection, a vanished domain — can pass for done.
//
// An error does NOT always mean "nothing changed". On the fallback path the LIVE
// request can be accepted and the CONFIG call then fail with something other than
// DEVICE_MISSING. That needs the persistent copy to regain the device between the
// first call and the CONFIG call, which the caller's per-VM operation barrier
// excludes for litevirt's own writers; a caller that maps any error to a "nothing
// applied" terminal failure relies on that barrier.
//
// Not covered: a device element libvirt cannot match at all (a NIC described by a
// MAC with no source fails XML validation, VIR_ERR_XML_ERROR, before matching), so
// callers still describe the device as it stands in the copy that holds it.
func DetachLiveAndConfig(detach func(flags uint32) error) error {
	err := detach(ModifyLive | ModifyConfig)
	if err == nil || !IsDeviceMissing(err) {
		return err
	}
	if lerr := detach(ModifyLive); lerr != nil && !IsDeviceMissing(lerr) {
		return lerr
	}
	if cerr := detach(ModifyConfig); cerr != nil && !IsDeviceMissing(cerr) {
		return cerr
	}
	return nil
}

// detachDeviceXMLConfig marshals a device to XML and detaches it from a domain's
// PERSISTENT definition ONLY (DomainDeviceModifyConfig, no Live flag) — the shut-off-safe
// detach that never touches a live domain.
func (c *Client) detachDeviceXMLConfig(domainName string, device any) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	data, err := xml.MarshalIndent(device, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device XML: %w", err)
	}
	flags := uint32(golibvirt.DomainDeviceModifyConfig)
	if err := c.virt.DomainDetachDeviceFlags(dom, string(data), flags); err != nil {
		return fmt.Errorf("detach device from %s config: %w", domainName, err)
	}
	return nil
}
