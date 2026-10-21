package libvirt

import (
	"encoding/xml"
	"fmt"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// The partition-pause mark: a LIVE-only domain-metadata element the partition
// pauser (internal/health) puts on a running domain just before it suspends
// it, carrying the token its pause record holds. It is the pauser's evidence
// that a paused domain is paused by its own pause: an operator's suspend and
// QEMU's I/O-error pause leave no mark, and the pauser removes the mark
// before it resumes, so a record a crash left behind never matches a later
// pause made by someone else. Live only, so it ends with the QEMU process: a
// domain that stops and starts again carries none.
const (
	partitionPauseMetadataURI = "https://litevirt.dev/xmlns/partition-pause/1"
	partitionPauseMetadataKey = "litevirt-partition-pause"
)

// MarkPartitionPaused puts the mark carrying token on the running domain.
func (c *Client) MarkPartitionPaused(name, token string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", name, err)
	}
	var b strings.Builder
	b.WriteString(`<pause token="`)
	if err := xml.EscapeText(&b, []byte(token)); err != nil {
		return err
	}
	b.WriteString(`"/>`)
	if err := c.virt.DomainSetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{b.String()}, golibvirt.OptString{partitionPauseMetadataKey},
		golibvirt.OptString{partitionPauseMetadataURI}, golibvirt.DomainAffectLive); err != nil {
		return fmt.Errorf("set partition-pause metadata on %q: %w", name, err)
	}
	return nil
}

// PartitionPauseMark reads the mark's token from the live domain; ok=false
// when the domain carries none.
func (c *Client) PartitionPauseMark(name string) (string, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return "", false, fmt.Errorf("lookup domain %q: %w", name, err)
	}
	raw, err := c.virt.DomainGetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{partitionPauseMetadataURI}, golibvirt.DomainAffectLive)
	if err != nil {
		if noDomainMetadata(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get partition-pause metadata on %q: %w", name, err)
	}
	return parsePartitionPauseMark(name, raw)
}

// ClearPartitionPauseMark removes the mark from the live domain. Absent is
// success.
func (c *Client) ClearPartitionPauseMark(name string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %q: %w", name, err)
	}
	if err := c.virt.DomainSetMetadata(dom, virDomainMetadataElement,
		golibvirt.OptString{}, golibvirt.OptString{},
		golibvirt.OptString{partitionPauseMetadataURI}, golibvirt.DomainAffectLive); err != nil && !noDomainMetadata(err) {
		return fmt.Errorf("clear partition-pause metadata on %q: %w", name, err)
	}
	return nil
}

// noDomainMetadata reports libvirt's VIR_ERR_NO_DOMAIN_METADATA.
func noDomainMetadata(err error) bool {
	if e, ok := err.(golibvirt.Error); ok {
		return e.Code == uint32(golibvirt.ErrNoDomainMetadata)
	}
	return strings.Contains(strings.ToLower(err.Error()), "metadata not found")
}

// parsePartitionPauseMark decodes the stored element. A mark without a token
// is corrupt, not absent: it is not evidence either way.
func parsePartitionPauseMark(name, raw string) (string, bool, error) {
	var el struct {
		XMLName xml.Name
		Token   string `xml:"token,attr"`
	}
	if err := xml.Unmarshal([]byte(raw), &el); err != nil {
		return "", false, fmt.Errorf("corrupt partition-pause metadata on %q: %w", name, err)
	}
	if el.XMLName.Local != "pause" || el.Token == "" {
		return "", false, fmt.Errorf("corrupt partition-pause metadata on %q: %q", name, raw)
	}
	return el.Token, true, nil
}
