package libvirt

import (
	"encoding/xml"
	"io"
	"strings"
)

// DomainAttachesCDROM reports whether the domain definition domXML attaches
// the file path as a CD-ROM: a <disk device='cdrom'> under <devices> whose
// <source file> is exactly path (compared decoded, as libvirt escapes
// attribute values). A document that does not parse attaches nothing.
func DomainAttachesCDROM(domXML, path string) bool {
	if domXML == "" || path == "" {
		return false
	}
	dec := xml.NewDecoder(strings.NewReader(domXML))
	dec.Strict = true
	var stack []string
	cdromDepth := -1 // stack depth of the <disk device='cdrom'> being read
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			name := t.Name.Local
			if t.Name.Space != "" {
				name = t.Name.Space + ":" + name
			}
			if name == "disk" && parent == "devices" && attrValue(t, "device") == "cdrom" {
				cdromDepth = len(stack)
			}
			if name == "source" && parent == "disk" && cdromDepth >= 0 && cdromDepth == len(stack)-1 &&
				attrValue(t, "file") == path {
				return true
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == cdromDepth {
				cdromDepth = -1
			}
		}
	}
}
