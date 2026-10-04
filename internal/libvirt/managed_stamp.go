package libvirt

import (
	"encoding/xml"
	"fmt"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// The managed stamp: a domain-metadata element that says only "litevirt manages
// this domain". It carries no generation and gates nothing. It exists for the
// orphan-runtime report (internal/health/orphan_runtime.go), which must
// recognise a litevirt domain after its row is gone, and which may not guess.
//
// The owner-epoch element cannot serve that on its own. It is written only for
// a RUNNING domain whose row has graduated to a real generation, so a VM whose
// row is still at the pre-epoch 0 (enforcement.owner_epoch off, which is the
// default) and any VM that is shut off carry none. Stamping those with an
// owner epoch would assert a generation the row does not hold. This element
// asserts nothing of the kind, so the reconciler can write it on every domain
// it has a live row for, whatever the row's epoch or the domain's state.
//
// Like the owner-epoch element it lives and dies with the domain: undefining a
// domain destroys its metadata, so a later hand-made domain that reuses the
// name starts without it.
const (
	managedMetadataURI = "https://litevirt.dev/xmlns/managed/1"
	managedMetadataKey = "litevirt-managed"
)

// SetDomainManaged writes the managed stamp. running selects the flag set, as
// for SetDomainOwnerEpoch: LIVE|CONFIG on an active domain, CONFIG on an
// inactive one (LIVE on an inactive domain is a libvirt error).
func (c *Client) SetDomainManaged(name string, running bool) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", name, err)
	}
	flags := golibvirt.DomainAffectConfig
	if running {
		flags |= golibvirt.DomainAffectLive
	}
	if err := c.virt.DomainSetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{"<managed/>"}, golibvirt.OptString{managedMetadataKey},
		golibvirt.OptString{managedMetadataURI}, flags); err != nil {
		return fmt.Errorf("set managed metadata on %q: %w", name, err)
	}
	return nil
}

// SetDomainManagedIncarnation writes the managed stamp carrying the
// INCARNATION of the row it was adopted from (the row's created_at):
// <managed incarnation="..."/>. It says which incarnation of the name this
// domain is, from evidence written while a live row named this host, so a
// later decision about the domain never has to infer it from a row that may
// have moved (docs/design/partition-pause.md §6). An older binary's parser
// reads only the element name, so the attribute is invisible to it.
func (c *Client) SetDomainManagedIncarnation(name, incarnation string, running bool) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", name, err)
	}
	flags := golibvirt.DomainAffectConfig
	if running {
		flags |= golibvirt.DomainAffectLive
	}
	var b strings.Builder
	b.WriteString(`<managed incarnation="`)
	if err := xml.EscapeText(&b, []byte(incarnation)); err != nil {
		return err
	}
	b.WriteString(`"/>`)
	if err := c.virt.DomainSetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{b.String()}, golibvirt.OptString{managedMetadataKey},
		golibvirt.OptString{managedMetadataURI}, flags); err != nil {
		return fmt.Errorf("set managed metadata on %q: %w", name, err)
	}
	return nil
}

// GetDomainManagedIncarnation reads the incarnation the managed stamp carries.
// ok=false when there is no stamp, or a stamp without one (written by an older
// binary, or before this attribute existed).
func (c *Client) GetDomainManagedIncarnation(name string) (string, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return "", false, fmt.Errorf("lookup domain %q: %w", name, err)
	}
	raw, err := c.virt.DomainGetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{managedMetadataURI}, golibvirt.DomainAffectCurrent)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "metadata") {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get managed metadata on %q: %w", name, err)
	}
	return parseManagedIncarnation(name, raw)
}

// parseManagedIncarnation decodes the incarnation attribute of the stamp.
func parseManagedIncarnation(name, raw string) (string, bool, error) {
	var el struct {
		XMLName     xml.Name
		Incarnation string `xml:"incarnation,attr"`
	}
	if err := xml.Unmarshal([]byte(raw), &el); err != nil {
		return "", false, fmt.Errorf("corrupt managed metadata on %q: %w", name, err)
	}
	if el.XMLName.Local != "managed" {
		return "", false, fmt.Errorf("corrupt managed metadata on %q: element <%s>, want <managed>", name, el.XMLName.Local)
	}
	return el.Incarnation, el.Incarnation != "", nil
}

// GetDomainManaged reports whether the domain carries the managed stamp. An
// absent element is (false, nil). Content under litevirt's namespace that is
// not the stamp is an error: it is not proof, and it is not absence either.
func (c *Client) GetDomainManaged(name string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return false, fmt.Errorf("lookup domain %q: %w", name, err)
	}
	raw, err := c.virt.DomainGetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{managedMetadataURI}, golibvirt.DomainAffectCurrent)
	if err != nil {
		// VIR_ERR_NO_DOMAIN_METADATA, as GetDomainOwnerEpoch reads it.
		if strings.Contains(strings.ToLower(err.Error()), "metadata") {
			return false, nil
		}
		return false, fmt.Errorf("get managed metadata on %q: %w", name, err)
	}
	return parseManagedMetadata(name, raw)
}

// parseManagedMetadata decodes the stored element. Split out so the contract
// is testable without a libvirt connection.
func parseManagedMetadata(name, raw string) (bool, error) {
	var el struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal([]byte(raw), &el); err != nil {
		return false, fmt.Errorf("corrupt managed metadata on %q: %w", name, err)
	}
	if el.XMLName.Local != "managed" {
		return false, fmt.Errorf("corrupt managed metadata on %q: element <%s>, want <managed>", name, el.XMLName.Local)
	}
	return true, nil
}
