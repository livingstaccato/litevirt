package compose

import (
	"fmt"
	"strings"
)

// A NIC's MTU (docs/networking.md "Per-NIC MTU"). Stored in
// NetworkAttachment.mtu: 0 renders no <mtu>, NICMTUBridge renders the bridge's
// own MTU read when the domain is defined, and N asserts the bridge is N.

// NICMTUBridge is the stored value of `mtu: bridge` (Proxmox writes mtu=1).
const NICMTUBridge int32 = 1

// MinNICMTU and MaxNICMTU bound an explicit MTU: IPv4's minimum datagram, and
// the largest a virtio-net device takes.
const (
	MinNICMTU int32 = 576
	MaxNICMTU int32 = 65520
)

// NICMTU is a NIC's mtu: a number, or "bridge".
type NICMTU struct {
	N int32
}

// UnmarshalYAML accepts an int or "bridge".
func (m *NICMTU) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var i int32
	if err := unmarshal(&i); err == nil {
		*m = NICMTU{N: i}
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(s), "bridge") {
		*m = NICMTU{N: NICMTUBridge}
		return nil
	}
	return fmt.Errorf("invalid mtu %q: want a number or bridge", s)
}

// IsZero lets yaml omit an unset value.
func (m NICMTU) IsZero() bool { return m.N == 0 }

// MarshalYAML writes the form the file takes: a number, or bridge.
func (m NICMTU) MarshalYAML() (interface{}, error) {
	if m.N == NICMTUBridge {
		return "bridge", nil
	}
	return m.N, nil
}

// ValidateNICMTU checks a NIC's stored MTU against its model.
func ValidateNICMTU(model string, mtu int32) error {
	if mtu == 0 {
		return nil
	}
	if mtu != NICMTUBridge && (mtu < MinNICMTU || mtu > MaxNICMTU) {
		return fmt.Errorf("mtu %d: want %d to %d, or bridge", mtu, MinNICMTU, MaxNICMTU)
	}
	if model != "" && model != "virtio" {
		return fmt.Errorf("mtu needs the virtio model (this NIC is %s)", model)
	}
	return nil
}
