package pki

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	hp "google.golang.org/grpc/health/grpc_health_v1"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// Omitting expected CN admits a real wrong-host peer at the selected address.
func TestExpectedHostPeerActualTLS(t *testing.T) {
	dir := setupPKI(t)
	client := observerPKI(t, dir, "source")
	cfg, err := ServerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	hp.RegisterHealthServer(srv, health.NewServer())
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := DialExpectedHostPeer(ctx, client, "test-host", lis.Addr().String())
	if err != nil {
		t.Fatalf("real expected-host TLS unavailable: %v", err)
	}
	defer peer.Close()
	if _, err := hp.NewHealthClient(peer).Check(ctx, &hp.HealthCheckRequest{}); err != nil {
		t.Fatal("matching TLS identity failed", err)
	}
	wrong, err := DialExpectedHostPeer(ctx, client, "another-host", lis.Addr().String())
	if err == nil {
		defer wrong.Close()
		if _, err = hp.NewHealthClient(wrong).Check(ctx, &hp.HealthCheckRequest{}); err == nil {
			t.Fatal("wrong CN at real endpoint accepted")
		}
	}
}

func TestExpectedHostPeerTLSConstraints(t *testing.T) {
	for _, mode := range []string{"dns", "ipv6", "wrong-san", "server-only", "client-only", "ca-leaf", "expired"} {
		t.Run(mode, func(t *testing.T) {
			dir := setupPKI(t)
			client := observerPKI(t, dir, "source")
			cfg, err := ServerTLSConfig(dir)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := ServedHostKeyPair(dir)
			if err != nil {
				t.Fatal(err)
			}
			leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
			leaf.DNSNames = []string{"localhost"}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
			address := "127.0.0.1:0"
			valid := false
			switch mode {
			case "dns":
				ips, e := net.DefaultResolver.LookupNetIP(context.Background(), "ip", "localhost")
				if e != nil || len(ips) == 0 {
					t.Fatal(e)
				}
				address = net.JoinHostPort(ips[0].String(), "0")
				valid = true
			case "ipv6":
				address = "[::1]:0"
				valid = true
			case "wrong-san":
				leaf.DNSNames = nil
				leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.2")}
			case "server-only":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "client-only":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			case "ca-leaf":
				leaf.IsCA = true
				leaf.BasicConstraintsValid = true
			case "expired":
				leaf.NotAfter = time.Now().Add(-time.Minute)
			}
			ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := x509.ParseCertificate(raw)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "ca-leaf" && !actual.IsCA {
				t.Fatal("fixture failed to encode actual CA constraint")
			}
			cfg.GetCertificate = nil
			cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: pair.PrivateKey}}
			lis, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
			hp.RegisterHealthServer(srv, health.NewServer())
			go srv.Serve(lis)
			t.Cleanup(srv.Stop)
			endpoint := lis.Addr().String()
			if mode == "dns" {
				_, port, _ := net.SplitHostPort(endpoint)
				endpoint = net.JoinHostPort("localhost", port)
			}
			peer, err := DialExpectedHostPeer(context.Background(), client, "test-host", endpoint)
			if err == nil {
				defer peer.Close()
				_, err = hp.NewHealthClient(peer).Check(context.Background(), &hp.HealthCheckRequest{})
			}
			if valid && err != nil {
				t.Fatal("real expected endpoint refused", err)
			}
			if !valid && err == nil {
				t.Fatal("invalid TLS peer accepted")
			}
			if valid {
				selected, connected, chain, err := peer.Observation()
				if err != nil || selected != endpoint || connected != lis.Addr().String() || len(chain) != 1 {
					t.Fatal("wrong actual observation", selected, connected, err)
				}
				chain[0][0] ^= 1
				_, _, again, err := peer.Observation()
				if err != nil || again[0][0] == chain[0][0] {
					t.Fatal("observation aliases private transport")
				}
				if _, err := hp.NewHealthClient(peer).Check(context.Background(), &hp.HealthCheckRequest{}); err == nil {
					t.Fatal("transport reused across observations")
				}
				peer.Close()
				if _, _, _, err := peer.Observation(); err == nil {
					t.Fatal("closed transport evidence reused")
				}
			}
		})
	}
}
