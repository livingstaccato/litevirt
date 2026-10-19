package pki

import (
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/safename"
)

// migrationPairSuffix is what the operator's PKI directory appends to a host
// name for that host's migration pair (<name>-migration.crt|.key).
const migrationPairSuffix = "-migration"

// reservedHostNames are the names a host may not take. The operator's PKI
// directory keeps each host's pair as <name>.crt and <name>.key beside the
// cluster's own files, so a host named after one of those stems would replace
// it: "ca" overwrites the cluster CA and its key. "lv-cli" is the Common Name
// of the distributable client certificate, which a host row of that name
// would make look like a peer.
var reservedHostNames = []string{
	strings.TrimSuffix("ca.crt", ".crt"),
	strings.TrimSuffix("client.crt", ".crt"),
	strings.TrimSuffix("host.crt", ".crt"),
	strings.TrimSuffix(GossipKeyName, ".key"),
	strings.TrimSuffix(MigrationCACertName, ".crt"),
	strings.TrimSuffix(UICertName, ".crt"),
	strings.TrimSuffix(AuditSigningCertName, ".crt"),
	"lv-cli",
}

// ValidateHostName is the rule for a NEW host name, and for any name that
// becomes a file name in a PKI directory: safename's charset (letters,
// digits, '_', '.', '-'; not "." or ".."), no leading '-' or '.', not a
// reserved name, and not ending in "-migration", which is another host's
// migration pair. Reserved names compare case-insensitively, because the
// operator's directory may be on a case-insensitive filesystem (macOS).
func ValidateHostName(name string) error {
	if err := safename.ValidateName(name); err != nil {
		return fmt.Errorf("invalid host name: %w", err)
	}
	if strings.HasPrefix(name, "-") || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid host name %q: it may not start with '-' or '.'", name)
	}
	for _, r := range reservedHostNames {
		if strings.EqualFold(name, r) {
			return fmt.Errorf("invalid host name %q: reserved (%s)", name, strings.Join(reservedHostNames, ", "))
		}
	}
	if len(name) > len(migrationPairSuffix) && strings.EqualFold(name[len(name)-len(migrationPairSuffix):], migrationPairSuffix) {
		return fmt.Errorf("invalid host name %q: a name ending in %q is another host's migration pair", name, migrationPairSuffix)
	}
	return nil
}
