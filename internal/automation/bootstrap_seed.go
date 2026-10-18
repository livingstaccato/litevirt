package automation

import "github.com/litevirt/litevirt/internal/cloudinit"

// WriteBootstrapISO delivers the exact admitted/decrypted files through the
// existing durable seed builder. The caller must establish current execution
// authority and the payload's certified binding before invoking this file effect.
// It does not decrypt, normalize, regenerate, stamp or prove artifact ownership.
func WriteBootstrapISO(files EffectiveBootstrap, outputPath string) error {
	return cloudinit.GenerateExactISO(cloudinit.ExactSeed{
		UserData: files.UserData, MetaData: files.Metadata,
		NetworkConfig: files.NetworkConfig, VendorData: files.VendorData,
	}, outputPath)
}
