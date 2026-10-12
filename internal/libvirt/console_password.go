package libvirt

import (
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
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

// ConsolePasswordMode is what ApplyConsolePasswords does to a definition's
// console passwords.
type ConsolePasswordMode int

const (
	// ConsoleLeave leaves the definition exactly as it is: the policy is not
	// in force (console_password_v1 has not latched), so this build neither
	// sets nor removes a password — one an operator gave an imported domain
	// included.
	ConsoleLeave ConsolePasswordMode = iota
	// ConsoleFresh gives every console a FRESH password: a define.
	ConsoleFresh
	// ConsoleKeep keeps whatever password each console has: a redefine of a
	// domain from a secure dump of itself (a snapshot revert, a point-in-time
	// repair, a boot-order change), which is not a new definition.
	ConsoleKeep
	// ConsoleStrip removes every console password: the kill switch.
	ConsoleStrip
)

// ConsolePolicy is the host's decision for the definitions it writes
// (grpcapi.Server.ConsolePasswordPolicy).
type ConsolePolicy int

const (
	// PolicyLeave: console_password_v1 has not latched; touch nothing.
	PolicyLeave ConsolePolicy = iota
	// PolicySet: latched and enforcement.console_password on.
	PolicySet
	// PolicyStrip: latched and enforcement.console_password off.
	PolicyStrip
)

// ApplyConsolePasswords returns domXML with its VNC and SPICE <graphics>
// passwords set by mode. noVNC drops the VNC password whatever the mode
// (but ConsoleLeave): this host's QEMU cannot do VNC password authentication
// (ProbeVNCPassword — a FIPS-mode host has no DES), and a start with one
// would fail. Nothing outside those start tags changes. A domain with no
// console is returned unchanged.
//
// ConsoleFresh is the rotation: each define of a domain gives its consoles
// new passwords, which take effect when the guest next starts. A running
// guest keeps the password it started with (libvirt changes only the
// persistent definition), and the console proxy reads the LIVE one.
func ApplyConsolePasswords(domXML string, mode ConsolePasswordMode, noVNC bool) (string, error) {
	if mode == ConsoleLeave {
		return domXML, nil
	}
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
		orig := domXML[t.start:t.end]
		stripped := rePasswdAttr.ReplaceAllString(orig, "")
		tag := stripped
		switch {
		case mode == ConsoleStrip, t.kind == "vnc" && noVNC:
		case mode == ConsoleKeep:
			tag = orig
		case mode == ConsoleFresh:
			n := VNCPasswordLen
			if t.kind == "spice" {
				n = SPICEPasswordLen
			}
			pw, err := newConsolePassword(n)
			if err != nil {
				return "", err
			}
			tag = "<graphics passwd='" + pw + "'" + strings.TrimPrefix(stripped, "<graphics")
		}
		b.WriteString(tag)
		prev = t.end
	}
	b.WriteString(domXML[prev:])
	return b.String(), nil
}

// StripConsolePasswords removes every console password from domXML.
func StripConsolePasswords(domXML string) (string, error) {
	return ApplyConsolePasswords(domXML, ConsoleStrip, false)
}

// StripVNCPassword removes the VNC console's password from domXML and keeps
// SPICE's: a live migration onto a host that cannot do VNC password
// authentication (MigrateParams.StripVNCPassword).
func StripVNCPassword(domXML string) (string, error) {
	return ApplyConsolePasswords(domXML, ConsoleKeep, true)
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

// HasConsolePassword reports whether any console in domXML has a password.
func HasConsolePassword(domXML string) bool {
	tags, err := consoleGraphicsTags(domXML)
	if err != nil {
		return false
	}
	for _, t := range tags {
		if t.passwd != "" {
			return true
		}
	}
	return false
}

// SetConsolePasswordPolicy registers the decision this host's defines apply
// to a domain's consoles (ConsolePolicy). Until it is set, nothing is
// touched. The daemon wires enforcement.console_password AND the
// console_password_v1 latch here (grpcapi.Server.ConsolePasswordPolicy), so
// a password is set only once every host can present one.
func (c *Client) SetConsolePasswordPolicy(fn func() ConsolePolicy) {
	c.consolePolicy.Store(&fn)
}

// SetVNCPasswordUnavailable records that this host's QEMU cannot do VNC
// password authentication, and why (ProbeVNCPassword, or a start QEMU
// refused). From then on no definition this host writes carries a VNC
// password; SPICE keeps its own. "" clears it.
func (c *Client) SetVNCPasswordUnavailable(reason string) {
	c.vncUnavailable.Store(&reason)
}

// VNCPasswordUnavailable is the reason this host's QEMU cannot do VNC
// password authentication, "" when it can.
func (c *Client) VNCPasswordUnavailable() string {
	if p := c.vncUnavailable.Load(); p != nil {
		return *p
	}
	return ""
}

func (c *Client) consoleDecision() ConsolePolicy {
	p := c.consolePolicy.Load()
	if p == nil || *p == nil {
		return PolicyLeave
	}
	return (*p)()
}

// ConsoleModeFor maps a host policy onto what a write does: a define (fresh)
// or a redefine of a domain from a secure dump of itself (keep).
func ConsoleModeFor(p ConsolePolicy, define bool) ConsolePasswordMode {
	switch p {
	case PolicySet:
		if define {
			return ConsoleFresh
		}
		return ConsoleKeep
	case PolicyStrip:
		return ConsoleStrip
	default:
		return ConsoleLeave
	}
}

// applyConsolePolicy applies the registered policy to a definition about to
// be defined: fresh passwords (define) or the ones it has (a redefine from a
// secure dump of itself), none under the kill switch, untouched before the
// latch, and never a VNC one on a host that cannot do VNC passwords.
func (c *Client) applyConsolePolicy(domXML string, define bool) (string, error) {
	return ApplyConsolePasswords(domXML, ConsoleModeFor(c.consoleDecision(), define), c.VNCPasswordUnavailable() != "")
}

// consoleXMLAPI is what ConsolePassword reads through: *golibvirt.Libvirt in
// production, a recording model in the tests.
type consoleXMLAPI interface {
	DomainLookupByName(name string) (golibvirt.Domain, error)
	DomainGetXMLDesc(dom golibvirt.Domain, flags golibvirt.DomainXMLFlags) (string, error)
}

// ConsolePassword returns the password the RUNNING domain's console of kind
// ("vnc" or "spice") requires, or "" when it requires none. It reads the live
// definition with VIR_DOMAIN_XML_SECURE — the one dump that carries it — and
// the result must never be logged.
func (c *Client) ConsolePassword(name, kind string) (string, error) {
	return consolePassword(c.virt, name, kind)
}

func consolePassword(v consoleXMLAPI, name, kind string) (string, error) {
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return "", fmt.Errorf("lookup domain %s: %w", name, err)
	}
	// Secure, and NOT inactive: the password the running guest started with,
	// not the one a later define gave its next start.
	x, err := v.DomainGetXMLDesc(dom, golibvirt.DomainXMLSecure)
	if err != nil {
		return "", fmt.Errorf("get secure domain XML %s: %w", name, err)
	}
	return ConsolePasswordFromXML(x, kind)
}

// keepConsoleSnapshotAPI routes the direct DomainDefineXML of the snapshot
// reverts through the console policy in keep mode, so the kill switch and a
// host without VNC passwords reach them too.
type keepConsoleSnapshotAPI struct {
	snapshotAPI
	c *Client
}

func (k keepConsoleSnapshotAPI) DomainDefineXML(x string) (golibvirt.Domain, error) {
	x, err := k.c.applyConsolePolicy(x, false)
	if err != nil {
		return golibvirt.Domain{}, err
	}
	return k.snapshotAPI.DomainDefineXML(x)
}

// keepConsolePITAPI is keepConsoleSnapshotAPI for the point-in-time repair.
type keepConsolePITAPI struct {
	pitAPI
	c *Client
}

func (k keepConsolePITAPI) DomainDefineXML(x string) (golibvirt.Domain, error) {
	x, err := k.c.applyConsolePolicy(x, false)
	if err != nil {
		return golibvirt.Domain{}, err
	}
	return k.pitAPI.DomainDefineXML(x)
}

// reConsoleRefusalCause and reConsoleRefusalSubject recognise QEMU refusing a
// console password it cannot do: "VNC password auth disabled due to FIPS
// mode" (older QEMU), "Cipher backend does not support DES algorithm" on a
// -vnc ...,password=on (newer). Both must match, so an unrelated FIPS or
// cipher failure is not mistaken for one.
var (
	reConsoleRefusalCause   = regexp.MustCompile(`(?i)fips|\bdes\b|cipher`)
	reConsoleRefusalSubject = regexp.MustCompile(`(?i)vnc|password`)
)

// IsConsolePasswordRefusal reports whether a domain start failed because
// QEMU cannot do the console password it was given.
func IsConsolePasswordRefusal(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return reConsoleRefusalCause.MatchString(s) && reConsoleRefusalSubject.MatchString(s)
}

// startWithConsoleBackstop starts name, and when QEMU refuses the start
// because it cannot do a console password, redefines the domain without its
// console passwords, reports why (unavailable), and starts it once more. A
// host whose QEMU cannot do VNC passwords (FIPS) therefore never fails a start,
// a failover or a restart because of them: the guest runs with an open
// console, and the host stops setting VNC passwords. Any other failure, or a
// domain with no console password, is returned as it is.
func startWithConsoleBackstop(v snapshotAPI, g StartGuard, name string, unavailable func(string)) error {
	err := startDomainGuarded(v, g, name)
	if err == nil || !IsConsolePasswordRefusal(err) {
		return err
	}
	dom, lerr := v.DomainLookupByName(name)
	if lerr != nil {
		return err
	}
	x, xerr := v.DomainGetXMLDesc(dom, golibvirt.DomainXMLInactive|golibvirt.DomainXMLSecure)
	if xerr != nil || !HasConsolePassword(x) {
		return err
	}
	stripped, serr := StripConsolePasswords(x)
	if serr != nil {
		return err
	}
	if _, derr := v.DomainDefineXML(stripped); derr != nil {
		return err
	}
	reason := strings.TrimSpace(strings.SplitN(err.Error(), "\n", 2)[0])
	slog.Warn("QEMU refused the console password; starting the domain without it, and setting no VNC passwords on this host",
		"domain", name, "reason", reason)
	if unavailable != nil {
		unavailable(reason)
	}
	return startDomainGuarded(v, g, name)
}
