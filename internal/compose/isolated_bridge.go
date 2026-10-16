package compose

import (
	"crypto/sha1"
	"encoding/hex"
)

// IsolatedBridgePrefix starts the name of every host bridge of an `isolated`
// network (IsolatedBridgeName). The name says nothing to the firewall: a
// `bridge` network may have a bridge of that name too.
const IsolatedBridgePrefix = "br-iso-"

// IsolatedBridgeGroup is the interface group (`ip link set <br> group N`)
// litevirt gives every bridge it creates for an `isolated` network. The
// firewall drops anything routed between a device in the group and one
// outside it, whatever the database says, so a bridge stays held to its host
// once litevirt has marked it, even after its network row is gone.
const IsolatedBridgeGroup = 27766

// maxIfaceName is the Linux interface-name limit (IFNAMSIZ - 1).
const maxIfaceName = 15

// IsolatedBridgeName returns the host bridge name for an isolated network.
// It is "br-iso-<name>" when that fits IFNAMSIZ, otherwise a stable hashed
// form "br-iso-<8 hex>" (exactly 15 chars) so long network names don't fail
// bridge creation. Every site that creates, deletes, or resolves an isolated
// bridge MUST use this so the names always agree.
func IsolatedBridgeName(networkName string) string {
	if len(IsolatedBridgePrefix)+len(networkName) <= maxIfaceName {
		return IsolatedBridgePrefix + networkName
	}
	sum := sha1.Sum([]byte(networkName))
	return IsolatedBridgePrefix + hex.EncodeToString(sum[:])[:maxIfaceName-len(IsolatedBridgePrefix)]
}
