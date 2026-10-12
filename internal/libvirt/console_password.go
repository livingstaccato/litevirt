package libvirt

import (
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Console passwords (docs/ui.md "Console passwords").
//
// A VM's VNC and SPICE consoles listen on the host's 127.0.0.1, which keeps
// them off the network but not away from every other local process and user
// on the host. Each console therefore carries a per-VM password in libvirt's
// <graphics passwd='...'>. Libvirt is the store: the password lives in the
// domain definition (root-only, /etc/libvirt/qemu) and reaches QEMU over the
// monitor (set_password), never on QEMU's command line. Libvirt omits it from
// every XML dump that does not ask for VIR_DOMAIN_XML_SECURE, so the ordinary
// DumpXML that litevirt logs, diffs and stores never carries it. A live
// migration hands the destination the secure migratable XML, so the password
// travels with the running guest.
//
// Only the daemon on the VM's own host ever reads it back (ConsolePassword),
// and only to authenticate its console proxy to the listener; nothing writes it
// to the cluster database.

// VNCPasswordLen is the length of a VNC console password. VNC authentication
// keys DES with the first eight bytes of the password and ignores the rest,
// so eight is the most a VNC password can be: a longer one would only look
// stronger. The loopback bind and the password are the protection together.
const VNCPasswordLen = 8

// SPICEPasswordLen is the length of a SPICE console password (a SPICE ticket
// has no eight-byte limit).
const SPICEPasswordLen = 24

const consolePasswordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// newConsolePassword returns n characters drawn uniformly from
// consolePasswordAlphabet with crypto/rand. Alphanumeric only, so it needs no
// escaping in an XML attribute and survives any client's password field.
func newConsolePassword(n int) (string, error) {
	max := big.NewInt(int64(len(consolePasswordAlphabet)))
	var b strings.Builder
	for i := 0; i < n; i++ {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("console password: %w", err)
		}
		b.WriteByte(consolePasswordAlphabet[k.Int64()])
	}
	return b.String(), nil
}

// rePasswdAttr matches a passwd attribute (either quote style) and the space
// before it. `passwd\s*=` cannot match passwdValidTo.
var rePasswdAttr = regexp.MustCompile(`\s+passwd\s*=\s*('[^']*'|"[^"]*")`)

// consoleGraphicsTag is one <graphics> start tag of a console type, by byte
// span in the document.
type consoleGraphicsTag struct {
	start, end int
	kind       string // "vnc" or "spice"
	passwd     string
}

// consoleGraphicsTags finds every <graphics type='vnc'|'spice'> start tag in
// domXML by byte offset, so a rewrite touches those bytes and nothing else.
func consoleGraphicsTags(domXML string) ([]consoleGraphicsTag, error) {
	d := xml.NewDecoder(strings.NewReader(domXML))
	var tags []consoleGraphicsTag
	for {
		start := int(d.InputOffset())
		tok, err := d.RawToken()
		if err == io.EOF {
			return tags, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse domain XML: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Space != "" || se.Name.Local != "graphics" {
			continue
		}
		var kind, passwd string
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "type":
				kind = a.Value
			case "passwd":
				passwd = a.Value
			}
		}
		if kind != "vnc" && kind != "spice" {
			continue
		}
		end := int(d.InputOffset())
		if !strings.HasPrefix(domXML[start:end], "<graphics") {
			return nil, fmt.Errorf("parse domain XML: graphics element at offset %d does not start with <graphics", start)
		}
		tags = append(tags, consoleGraphicsTag{start: start, end: end, kind: kind, passwd: passwd})
	}
}

// ApplyConsolePasswords returns domXML with every VNC and SPICE <graphics>
// element carrying a FRESH password when on, and no password when off.
// Nothing outside those start tags changes. A domain with no console is
// returned unchanged.
//
// Fresh on every call is the rotation: each define of a domain gives its
// consoles new passwords, which take effect when the guest next starts. A
// running guest keeps the password it started with (libvirt changes only the
// persistent definition), and the console proxy reads the LIVE one.
func ApplyConsolePasswords(domXML string, on bool) (string, error) {
	tags, err := consoleGraphicsTags(domXML)
	if err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return domXML, nil
	}
	var b strings.Builder
	prev := 0
	for _, t := range tags {
		b.WriteString(domXML[prev:t.start])
		tag := rePasswdAttr.ReplaceAllString(domXML[t.start:t.end], "")
		if on {
			n := VNCPasswordLen
			if t.kind == "spice" {
				n = SPICEPasswordLen
			}
			pw, err := newConsolePassword(n)
			if err != nil {
				return "", err
			}
			tag = "<graphics passwd='" + pw + "'" + strings.TrimPrefix(tag, "<graphics")
		}
		b.WriteString(tag)
		prev = t.end
	}
	b.WriteString(domXML[prev:])
	return b.String(), nil
}

// ConsolePasswordFromXML returns the password of domXML's first <graphics>
// of kind ("vnc" or "spice"), or "" when it has none. Only a SECURE dump
// carries one.
func ConsolePasswordFromXML(domXML, kind string) (string, error) {
	tags, err := consoleGraphicsTags(domXML)
	if err != nil {
		return "", err
	}
	for _, t := range tags {
		if t.kind == kind {
			return t.passwd, nil
		}
	}
	return "", nil
}

// SetConsolePasswordPolicy registers the decision every DefineDomain applies
// to the domain's consoles: true gives each console a fresh password, false
// removes any. Until it is set, DefineDomain leaves the XML as it is. The
// daemon wires enforcement.console_password AND the console_password_v1
// latch here (grpcapi.Server.ConsolePasswordActive), so a password is set
// only once every host can present one.
func (c *Client) SetConsolePasswordPolicy(fn func() bool) {
	c.consolePolicy.Store(&fn)
}

// applyConsolePolicy applies the registered policy to a definition about to
// be defined.
func (c *Client) applyConsolePolicy(domXML string) (string, error) {
	p := c.consolePolicy.Load()
	if p == nil || *p == nil {
		return domXML, nil
	}
	return ApplyConsolePasswords(domXML, (*p)())
}

// ConsolePassword returns the password the RUNNING domain's console of kind
// ("vnc" or "spice") requires, or "" when it requires none. It reads the live
// definition with VIR_DOMAIN_XML_SECURE — the one dump that carries it — and
// the result must never be logged.
func (c *Client) ConsolePassword(name, kind string) (string, error) {
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return "", fmt.Errorf("lookup domain %s: %w", name, err)
	}
	x, err := c.virt.DomainGetXMLDesc(dom, golibvirt.DomainXMLSecure)
	if err != nil {
		return "", fmt.Errorf("get secure domain XML %s: %w", name, err)
	}
	return ConsolePasswordFromXML(x, kind)
}
