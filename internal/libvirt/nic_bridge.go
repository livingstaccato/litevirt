package libvirt

import (
	"fmt"
	"regexp"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

var (
	interfaceElemRE = regexp.MustCompile(`(?s)<interface\b.*?</interface>`)
	macAddrRE       = regexp.MustCompile(`<mac\s+address=['"]([^'"]+)['"]`)
	sourceBridgeRE  = regexp.MustCompile(`(<source\b[^>]*\bbridge=)(['"])[^'"]*(['"])`)
)

// RetargetInterfaceXML returns the <interface> element of domXML whose MAC is
// mac, with its <source bridge> set to bridge — and ok=false when no bridge
// interface carries that MAC.
//
// It edits the element's text rather than re-marshalling it, so every child
// libvirt put there (model, target, alias, PCI address, driver, mtu) is sent
// back unchanged. libvirt's update-device matches the interface by MAC and
// refuses a changed model or address, so a partial element would fail.
func RetargetInterfaceXML(domXML, mac, bridge string) (string, bool) {
	_, elem, ok := retargetInterface(domXML, mac, bridge)
	return elem, ok
}

// RetargetDomainXML is RetargetInterfaceXML applied to the whole domain: the
// domain XML with that one interface's bridge changed.
func RetargetDomainXML(domXML, mac, bridge string) (string, bool) {
	old, elem, ok := retargetInterface(domXML, mac, bridge)
	if !ok {
		return domXML, false
	}
	return strings.Replace(domXML, old, elem, 1), true
}

func retargetInterface(domXML, mac, bridge string) (old, elem string, ok bool) {
	want := strings.ToLower(strings.TrimSpace(mac))
	for _, e := range interfaceElemRE.FindAllString(domXML, -1) {
		m := macAddrRE.FindStringSubmatch(e)
		if m == nil || strings.ToLower(m[1]) != want {
			continue
		}
		if !sourceBridgeRE.MatchString(e) {
			return "", "", false
		}
		return e, sourceBridgeRE.ReplaceAllString(e, "${1}${2}"+bridge+"${3}"), true
	}
	return "", "", false
}

// SetNICBridge moves the domain's NIC with MAC mac onto bridge, in place: the
// same device, the same MAC, no detach and no redefine. The persistent
// definition is updated so a cold boot keeps it, and a running domain is
// updated live, which libvirt supports for a bridge interface's source.
func (c *Client) SetNICBridge(domainName, mac, bridge string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	inactive, err := c.DumpXMLInactive(domainName)
	if err != nil {
		return err
	}
	elem, ok := RetargetInterfaceXML(inactive, mac, bridge)
	if !ok {
		return fmt.Errorf("domain %s has no bridge interface with MAC %s", domainName, mac)
	}
	if err := c.virt.DomainUpdateDeviceFlags(dom, elem, golibvirt.DomainDeviceModifyConfig); err != nil {
		return fmt.Errorf("update NIC %s of %s (config): %w", mac, domainName, err)
	}
	active, err := c.virt.DomainIsActive(dom)
	if err != nil {
		return fmt.Errorf("domain %s is-active: %w", domainName, err)
	}
	if active == 0 {
		return nil
	}
	live, err := c.DumpXML(domainName)
	if err != nil {
		return err
	}
	elem, ok = RetargetInterfaceXML(live, mac, bridge)
	if !ok {
		return fmt.Errorf("running domain %s has no bridge interface with MAC %s", domainName, mac)
	}
	if err := c.virt.DomainUpdateDeviceFlags(dom, elem, golibvirt.DomainDeviceModifyLive); err != nil {
		return fmt.Errorf("update NIC %s of %s (live): %w", mac, domainName, err)
	}
	return nil
}
