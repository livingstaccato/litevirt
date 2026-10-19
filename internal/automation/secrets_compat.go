package automation

import (
	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/automation/custody"
)

// These aliases preserve the automation API while custody owns the private
// cryptographic material, codecs and durable local files.
type SecretBinding = custody.SecretBinding
type EffectiveBootstrap = custody.EffectiveBootstrap
type RawBootstrapIntent = custody.RawBootstrapIntent
type IntentScope = custody.IntentScope
type BootstrapEqualityKey = custody.BootstrapEqualityKey
type CustodyScope = custody.CustodyScope
type CustodyKeyRef = custody.CustodyKeyRef
type LocalCustody = custody.LocalCustody
type LocalVoterKey = custody.LocalVoterKey

var (
	ErrCustodyUnavailable      = custody.ErrCustodyUnavailable
	ErrCustodyCorrupt          = custody.ErrCustodyCorrupt
	ErrCustodyConflict         = custody.ErrCustodyConflict
	ErrCustodyRecoveryRequired = custody.ErrCustodyRecoveryRequired
)

func EncryptBootstrap(binding SecretBinding, files EffectiveBootstrap, recipients []*age.X25519Recipient) ([]byte, error) {
	return custody.EncryptBootstrap(binding, files, recipients)
}

func DecryptBootstrap(binding SecretBinding, ciphertext []byte, identities []*age.X25519Identity) (EffectiveBootstrap, error) {
	return custody.DecryptBootstrap(binding, ciphertext, identities)
}

func NewBootstrapEqualityKey(epoch string, material []byte) (BootstrapEqualityKey, error) {
	return custody.NewBootstrapEqualityKey(epoch, material)
}

func CreateLocalCustody(path string, scope CustodyScope) (*LocalCustody, error) {
	return custody.CreateLocalCustody(path, scope)
}

func OpenLocalCustody(path string, scope CustodyScope) (*LocalCustody, error) {
	return custody.OpenLocalCustody(path, scope)
}
