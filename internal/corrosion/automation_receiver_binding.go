package corrosion

import "encoding/json"

// receiverConfigV1 freezes the original durable binding projection. Row
// observation stamps (and future VoterConfig bookkeeping) are not authority
// and must not change an immutable attempt's bytes or identity.
type receiverConfigV1 struct {
	VoterConfigValue
	MembersHash string
	Certificate string
}
type receiverFactsV1 struct {
	Incarnation, Chain, Certificates string
	Adopted                          int64
	Target                           sourceHost
	Old, Next                        *receiverConfigV1
}

func receiverConfigProjection(v *VoterConfig) *receiverConfigV1 {
	if v == nil {
		return nil
	}
	return &receiverConfigV1{v.VoterConfigValue, v.MembersHash, v.Certificate}
}
func (v *receiverConfigV1) config() *VoterConfig {
	if v == nil {
		return nil
	}
	return &VoterConfig{VoterConfigValue: v.VoterConfigValue, MembersHash: v.MembersHash, Certificate: v.Certificate}
}
func (f receiverFacts) MarshalJSON() ([]byte, error) {
	return json.Marshal(receiverFactsV1{f.Incarnation, f.Chain, f.Certificates, f.Adopted, f.Target, receiverConfigProjection(f.Old), receiverConfigProjection(f.Next)})
}
func (f *receiverFacts) UnmarshalJSON(raw []byte) error {
	var v receiverFactsV1
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	*f = receiverFacts{v.Incarnation, v.Chain, v.Certificates, v.Adopted, v.Target, v.Old.config(), v.Next.config()}
	return nil
}
