package corrosion

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

type sourceHost struct {
	Name, Address, Serial string
	Port                  int
}
type sourceTarget struct {
	Host                                          sourceHost
	Incarnation, Endpoint, Connected, Fingerprint string
	Local                                         bool
	Chain                                         [][]byte
}

func sourceReadHost(ctx context.Context, tx *LocalTx, name string) (sourceHost, error) {
	rows, err := tx.Query(ctx, `SELECT name,address,grpc_port,cert_serial FROM hosts WHERE name=? AND COALESCE(deleted_at,'')='' AND length(CAST(name AS BLOB)) BETWEEN 1 AND 253 AND length(CAST(address AS BLOB)) BETWEEN 1 AND 253 AND length(CAST(cert_serial AS BLOB)) BETWEEN 1 AND 128 LIMIT 1`, name)
	if err != nil {
		return sourceHost{}, err
	}
	if len(rows) != 1 {
		return sourceHost{}, errors.New("missing or tombstoned admitted source peer")
	}
	r := rows[0]
	h := sourceHost{Name: r.String("name"), Address: r.String("address"), Port: r.Int("grpc_port"), Serial: r.String("cert_serial")}
	if h.Port < 0 || h.Port > 65535 {
		return h, errors.New("invalid admitted peer port")
	}
	return h, nil
}

// ReportedVoterIncarnation shares the ordinary response-name/lifetime rule.
// This string check alone is never transport or publication authority.
func ReportedVoterIncarnation(host string, resp *pb.GetRecoveryClaimResponse) (string, error) {
	if resp.GetState().GetVoter() != host || resp.GetState().GetVoterIncarnation() == "" {
		return "", fmt.Errorf("%s did not report an incarnation as itself", host)
	}
	return resp.GetState().GetVoterIncarnation(), nil
}
func sourceQueryPeer(ctx context.Context, dir string, h sourceHost, g int64, reattest bool) (*pb.GetRecoveryClaimResponse, sourceTarget, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := pki.DialExpectedHostPeer(ctx, dir, h.Name, PeerTarget(h.Address, h.Port))
	if err != nil {
		return nil, sourceTarget{}, err
	}
	defer conn.Close()
	resp, err := pb.NewLiteVirtClient(conn).GetRecoveryClaim(ctx, &pb.GetRecoveryClaimRequest{Key: &pb.RecoveryClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: g}, Reattest: reattest})
	if err != nil {
		return nil, sourceTarget{}, err
	}
	inc, err := ReportedVoterIncarnation(h.Name, resp)
	if err != nil {
		return nil, sourceTarget{}, err
	}
	if len(inc) > 128 {
		return nil, sourceTarget{}, errors.New("over-bound target incarnation")
	}
	endpoint, connected, chain, err := conn.Observation()
	if err != nil {
		return nil, sourceTarget{}, err
	}
	fp := sha256.Sum256(chain[0])
	return resp, sourceTarget{Host: h, Incarnation: inc, Endpoint: endpoint, Connected: connected, Chain: chain, Fingerprint: hex.EncodeToString(fp[:])}, nil
}
func sourceAdmission(view *pki.HostTrust, h sourceHost, raw []byte) error {
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != h.Name {
		return errors.New("host admission name mismatch")
	}
	if strings.EqualFold(cert.SerialNumber.Text(16), h.Serial) {
		return nil
	}
	if prev, ok := pki.RenewedFromSerial(cert); ok && strings.EqualFold(prev, h.Serial) {
		return nil
	}
	if view.TrustRotatedPeers() {
		return nil
	}
	return errors.New("host admission serial differs")
}

func sourceAcceptFromPB(a *pb.ClaimAccept) *ClaimAccept {
	if a == nil {
		return nil
	}
	return &ClaimAccept{Key: ClaimKey{TargetKind: a.GetKey().GetTargetKind(), TargetName: a.GetKey().GetTargetName(), OwnerEpoch: a.GetKey().GetOwnerEpoch(), Attempt: a.GetKey().GetAttempt(), Incarnation: a.GetKey().GetIncarnation()}, Voter: a.GetVoter(), VoterIncarnation: a.GetVoterIncarnation(), ConfigGeneration: a.GetConfigGeneration(), ValueDigest: a.GetValueDigest(), CertPEM: a.GetCertPem(), Signature: append([]byte(nil), a.GetSignature()...), Ballot: Ballot{Round: a.GetBallot().GetRound(), Coordinator: a.GetBallot().GetCoordinator(), Nonce: append([]byte(nil), a.GetBallot().GetBootNonce()...)}}
}
