package libvirt

import (
	"encoding/xml"
	"strings"
)

// HostdevPCIAliases maps the source address of each PCI <hostdev> that
// carries a user alias ("ua-…") to that alias. The address is in
// HostdevSourcePCIAddresses's form: the 0x prefixes stripped, not re-padded.
func HostdevPCIAliases(domXML string) (map[string]string, error) {
	var d struct {
		Hostdevs []struct {
			Type   string `xml:"type,attr"`
			Source struct {
				Address struct {
					Domain   string `xml:"domain,attr"`
					Bus      string `xml:"bus,attr"`
					Slot     string `xml:"slot,attr"`
					Function string `xml:"function,attr"`
				} `xml:"address"`
			} `xml:"source"`
			Alias struct {
				Name string `xml:"name,attr"`
			} `xml:"alias"`
		} `xml:"devices>hostdev"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, h := range d.Hostdevs {
		a := h.Source.Address
		if h.Type != "pci" || !strings.HasPrefix(h.Alias.Name, "ua-") || (a.Domain == "" && a.Bus == "" && a.Slot == "" && a.Function == "") {
			continue
		}
		strip := func(v string) string { return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "0x") }
		out[strip(a.Domain)+":"+strip(a.Bus)+":"+strip(a.Slot)+"."+strip(a.Function)] = h.Alias.Name
	}
	return out, nil
}
