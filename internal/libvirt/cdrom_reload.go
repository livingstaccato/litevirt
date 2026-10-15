package libvirt

import (
	"fmt"
	"regexp"

	golibvirt "github.com/digitalocean/go-libvirt"
)

var (
	diskElemRE     = regexp.MustCompile(`(?s)<disk\b[^>]*>.*?</disk>`)
	cdromOpenTagRE = regexp.MustCompile(`^<disk\b[^>]*\bdevice=['"]cdrom['"]`)
	diskSourceRE   = regexp.MustCompile(`(?s)\s*<source\b[^>]*/>|\s*<source\b[^>]*>.*?</source>`)
	sourceFileRE   = regexp.MustCompile(`<source\b[^>]*\bfile=['"]([^'"]*)['"]`)
)

// cdromReloadElems finds the cdrom of domXML whose source file is path and
// returns the two device elements that reload its media: the cdrom with no
// source (an eject) and the cdrom as it is (an insert).
func cdromReloadElems(domXML, path string) (eject, insert string, ok bool) {
	for _, e := range diskElemRE.FindAllString(domXML, -1) {
		if !cdromOpenTagRE.MatchString(e) {
			continue
		}
		m := sourceFileRE.FindStringSubmatch(e)
		if m == nil || m[1] != path {
			continue
		}
		return diskSourceRE.ReplaceAllString(e, ""), e, true
	}
	return "", "", false
}

// ReloadCDROMMedia makes the running domain open the file of its cdrom whose
// source is path again: an eject, then an insert of the same file. libvirt
// changes a cdrom's media only when the update names another source, so a
// file rewritten at the same path (a cloud-init seed) is otherwise read from
// the copy qemu opened at start until the domain is next started. Live only:
// the persistent definition already names the file.
func (c *Client) ReloadCDROMMedia(domainName, path string) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	live, err := c.DumpXML(domainName)
	if err != nil {
		return err
	}
	eject, insert, ok := cdromReloadElems(live, path)
	if !ok {
		return fmt.Errorf("running domain %s has no cdrom with source %s", domainName, path)
	}
	if err := c.virt.DomainUpdateDeviceFlags(dom, eject, golibvirt.DomainDeviceModifyLive); err != nil {
		return fmt.Errorf("eject %s from %s: %w", path, domainName, err)
	}
	if err := c.virt.DomainUpdateDeviceFlags(dom, insert, golibvirt.DomainDeviceModifyLive); err != nil {
		return fmt.Errorf("insert %s into %s (the cdrom is left empty until the domain is next started): %w", path, domainName, err)
	}
	return nil
}
