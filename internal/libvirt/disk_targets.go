package libvirt

import (
	"encoding/xml"
	"strings"
)

// DomainDiskTargets returns the <target dev> of every <disk> in a domain
// definition: disks, CD-ROMs (the cloud-init seed, an installer) and any other
// disk-shaped device. A hot-plug that allocates a target from vm_disks alone
// does not see the CD-ROMs, which are in no table.
func DomainDiskTargets(domXML string) ([]string, error) {
	var d struct {
		Disks []struct {
			Target struct {
				Dev string `xml:"dev,attr"`
			} `xml:"target"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return nil, err
	}
	var out []string
	for _, disk := range d.Disks {
		if dev := strings.TrimSpace(disk.Target.Dev); dev != "" {
			out = append(out, dev)
		}
	}
	return out, nil
}
