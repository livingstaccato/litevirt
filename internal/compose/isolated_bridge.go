package compose

import (
	"crypto/sha1"
	"encoding/hex"
)

// IsolatedBridgePrefix starts the name of every host bridge of an `isolated`
// network (IsolatedBridgeName). The firewall drops forwarded traffic into and
// out of any device with this prefix, whatever the database says.
const IsolatedBridgePrefix = "br-iso-"

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
