package libvirt

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// RewriteCDROMSources points the CD-ROMs of a domain definition at other
// files: every <disk device='cdrom'> under <devices> whose <source file> is a
// key of remap gets the value instead. It returns the new definition and how
// many CD-ROMs it changed.
//
// It edits only the file attribute of those <source> elements, in place, and
// leaves every other byte of the document as it was — so a domain carrying XML
// namespaces (qemu:commandline) survives, unlike a tokenizer round trip. The
// paths are compared decoded (libvirt writes &amp; &apos; &quot; in
// attribute values) and the new path is written escaped, so a path holding
// an ampersand, an angle bracket or a quote is matched and written correctly.
func RewriteCDROMSources(domXML string, remap map[string]string) (string, int, error) {
	if len(remap) == 0 {
		return domXML, 0, nil
	}
	type edit struct {
		start, end int // the raw <source ...> tag
		raw        string
	}
	var edits []edit
	dec := xml.NewDecoder(strings.NewReader(domXML))
	dec.Strict = true
	var stack []string
	cdromDepth := -1 // stack depth of the <disk device='cdrom'> being read
	for {
		off := dec.InputOffset()
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", 0, fmt.Errorf("parse domain xml: %w", err)
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
			if name == "source" && parent == "disk" && cdromDepth >= 0 && cdromDepth == len(stack)-1 {
				if to, ok := remap[attrValue(t, "file")]; ok {
					end := int(dec.InputOffset())
					raw, rerr := rewriteFileAttr(domXML[off:end], to)
					if rerr != nil {
						return "", 0, rerr
					}
					edits = append(edits, edit{start: int(off), end: end, raw: raw})
				}
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
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := domXML
	for _, e := range edits {
		out = out[:e.start] + e.raw + out[e.end:]
	}
	return out, len(edits), nil
}

func attrValue(t xml.StartElement, local string) string {
	for _, a := range t.Attr {
		if a.Name.Space == "" && a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

var fileAttrRE = regexp.MustCompile(`(\sfile\s*=\s*)('[^']*'|"[^"]*")`)

// rewriteFileAttr replaces the value of the file attribute in one raw start
// tag, keeping its quote character.
func rewriteFileAttr(tag, to string) (string, error) {
	loc := fileAttrRE.FindStringSubmatchIndex(tag)
	if loc == nil {
		return "", fmt.Errorf("no file attribute in %q", tag)
	}
	q := tag[loc[4] : loc[4]+1]
	return tag[:loc[4]] + q + escapeAttr(to) + q + tag[loc[5]:], nil
}

// escapeAttr escapes an attribute value for either quote character.
func escapeAttr(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "'", "&apos;", `"`, "&quot;").Replace(s)
}
