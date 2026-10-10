package libvirt

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

// RewriteRBDHosts replaces the <host> children of every rbd disk source whose
// name is in hosts with that list, leaving every other byte of the document
// as it was (the <auth> beside them included). A source with no children is
// given them.
func RewriteRBDHosts(domXML string, hosts map[string][]diskSourceHost) (string, error) {
	if len(hosts) == 0 {
		return domXML, nil
	}
	type edit struct {
		start, end int
		raw        string
	}
	var edits []edit
	dec := xml.NewDecoder(strings.NewReader(domXML))
	dec.Strict = true
	var stack []string
	srcDepth := -1 // stack depth of the matched rbd <source> being read
	hostStart := -1
	for {
		off := int(dec.InputOffset())
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("parse domain xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			name := t.Name.Local
			end := int(dec.InputOffset())
			switch {
			case name == "source" && parent == "disk" && attrValue(t, "protocol") == "rbd":
				list, ok := hosts[attrValue(t, "name")]
				if !ok {
					break
				}
				raw := domXML[off:end]
				if strings.HasSuffix(raw, "/>") {
					// <source …/>: becomes <source …>hosts</source>. Its
					// matching EndElement carries no bytes of its own.
					edits = append(edits, edit{start: off, end: end,
						raw: strings.TrimSpace(strings.TrimSuffix(raw, "/>")) + ">" + hostElements(list) + "</source>"})
				} else {
					edits = append(edits, edit{start: end, end: end, raw: hostElements(list)})
					srcDepth = len(stack) + 1
				}
			case name == "host" && srcDepth >= 0 && len(stack) == srcDepth:
				hostStart = off
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if t.Name.Local == "host" && hostStart >= 0 && len(stack) == srcDepth {
				edits = append(edits, edit{start: hostStart, end: int(dec.InputOffset())})
				hostStart = -1
			}
			if t.Name.Local == "source" && len(stack) == srcDepth-1 {
				srcDepth = -1
			}
		}
	}
	// Back to front; at one offset a removal goes before the insertion, so
	// a <host> right after the <source> tag never takes the new list with it.
	sort.SliceStable(edits, func(i, j int) bool {
		if edits[i].start != edits[j].start {
			return edits[i].start > edits[j].start
		}
		return edits[i].end > edits[j].end
	})
	out := domXML
	for _, e := range edits {
		out = out[:e.start] + e.raw + out[e.end:]
	}
	return out, nil
}

func hostElements(list []diskSourceHost) string {
	var b strings.Builder
	for _, h := range list {
		b.WriteString("<host name='" + xmlEscape(h.Name) + "'")
		if h.Port != "" {
			b.WriteString(" port='" + xmlEscape(h.Port) + "'")
		}
		b.WriteString("/>")
	}
	return b.String()
}
