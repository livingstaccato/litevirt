package grpcapi

// withVIPProofReclaim sets enforcement.vip_proof_reclaim on a Server built from
// a struct literal; the flag is atomic, so a literal cannot carry it.
func withVIPProofReclaim(s *Server, on bool) *Server {
	s.enfVIPProofReclaim.Store(on)
	return s
}
