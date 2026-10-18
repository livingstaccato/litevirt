package cloudinit

import "errors"

// ExactSeed contains already admitted file bytes. UserData and MetaData must
// be nonnil. For every field a nonnil empty slice writes an empty file; nil
// NetworkConfig or VendorData omits that file. No defaults are applied here.
type ExactSeed struct{ UserData, MetaData, NetworkConfig, VendorData []byte }

var errExactSeed = errors.New("exact seed generation failed")

// GenerateExactISO writes exact files through the existing durable ISO builder.
// It neither validates metadata nor establishes admission, ownership or execution
// authority. Callers must establish those facts before invoking this file effect.
func GenerateExactISO(seed ExactSeed, outputPath string) error {
	if seed.UserData == nil || seed.MetaData == nil {
		return errExactSeed
	}
	if err := writeExactISO(seed, outputPath, true); err != nil {
		return errExactSeed
	}
	return nil
}
