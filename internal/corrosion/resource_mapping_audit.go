package corrosion

import (
	"context"
	"strconv"
	"strings"
)

// Audit renderings for resource mappings (#14), in the same
// `before=<state> after=<state>` form as the firewall rows (firewall_audit.go).
//
// A mapping decides which host PCI device a VM asking for it by name is handed,
// so repointing one is a privileged change. A removed device row is tombstoned:
// once it is gone the audit row is the only record of which device the mapping
// used to hand out. The state words are the firewall's: `{...}` for a row,
// `none` when a read that succeeded found nothing, and `unknown(<error>)` when
// the read failed.
//
// Nothing in a mapping is secret. The renderings carry names, hosts, PCI
// addresses and the operator's free-text vendor, device and description, and
// nothing about the caller's credential.

// AuditText renders one device under a mapping for an audit row.
func (d MappingDevice) AuditText() string {
	var b strings.Builder
	b.WriteString("{host=" + d.HostName + " address=" + d.Address)
	if d.Vendor != "" {
		b.WriteString(" vendor=" + strconv.Quote(d.Vendor))
	}
	if d.Device != "" {
		b.WriteString(" device=" + strconv.Quote(d.Device))
	}
	b.WriteByte('}')
	return b.String()
}

// AuditText renders a mapping, with every device under it, for an audit row.
func (m ResourceMappingRecord) AuditText() string {
	var b strings.Builder
	b.WriteString("{name=" + m.Name)
	if m.Description != "" {
		b.WriteString(" description=" + strconv.Quote(m.Description))
	}
	texts := make([]string, len(m.Devices))
	for i, d := range m.Devices {
		texts[i] = d.AuditText()
	}
	b.WriteString(" devices=[" + strings.Join(texts, ",") + "]}")
	return b.String()
}

// ResourceMappingAuditState reads a mapping and renders it as an audit state.
func ResourceMappingAuditState(ctx context.Context, c *Client, name string) string {
	m, err := GetResourceMapping(ctx, c, name)
	switch {
	case err != nil:
		return AuditUnknown(err)
	case m == nil:
		return AuditStateNone
	}
	return m.AuditText()
}

// MappingDeviceAuditState reads one live device row of a mapping and renders
// it as an audit state.
func MappingDeviceAuditState(ctx context.Context, c *Client, name, host, address string) string {
	m, err := GetResourceMapping(ctx, c, name)
	switch {
	case err != nil:
		return AuditUnknown(err)
	case m == nil:
		return AuditStateNone
	}
	for _, d := range m.Devices {
		if d.HostName == host && d.Address == address {
			return d.AuditText()
		}
	}
	return AuditStateNone
}
