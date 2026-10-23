package custody

import "filippo.io/age"

// DecryptBootstrap opens a complete bundle using the stored private identity,
// which remains inside custody. No files are returned before authenticated EOF
// and exact original-binding validation. The binding argument is not authority:
// callers must derive it from the certified original and separately establish
// native admission, execution authority, current custody and epoch eligibility.
// Local key availability is not an enrollment or quorum custody receipt.
func (key *LocalVoterKey) DecryptBootstrap(binding SecretBinding, ciphertext []byte) (EffectiveBootstrap, error) {
	if key == nil || key.identity == nil {
		return EffectiveBootstrap{}, errBootstrapSecret
	}
	return DecryptBootstrap(binding, ciphertext, []*age.X25519Identity{key.identity})
}

// RewrapBootstrap decrypts completely under the original binding and seals the
// exact files for the supplied replacement recipients using the existing format.
// Binding and recipient arguments are not authorization: callers must establish
// certified provenance, native admission, execution and current custody/epoch
// eligibility separately. This returns a new envelope only; it does not rewrite
// retained history or original receipts, activate an epoch, or revoke old copies.
func (key *LocalVoterKey) RewrapBootstrap(binding SecretBinding, ciphertext []byte, recipients []*age.X25519Recipient) ([]byte, error) {
	files, err := key.DecryptBootstrap(binding, ciphertext)
	if err != nil {
		return nil, errBootstrapSecret
	}
	return EncryptBootstrap(binding, files, recipients)
}
