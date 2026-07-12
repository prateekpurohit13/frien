//go:build ignore

// gen-certs generates a self-contained PKI for a local frien demo/dev cluster:
// a CA, one leaf certificate + key per node (with the node's trust tier bound in
// the certificate OU so quorum weighting is cert-driven, exactly as production
// intends), and an operator keypair (its public half as the pinned
// operator_root_cert, its private half for offline `frienctl policy sign` /
// `revoke sign`). It mirrors the format the identity package loads and the live
// QUIC/mTLS tests use.
//
//	go run scripts/gen-certs.go -out demo/certs -nodes core-1:trusted,edge-2:standard,edge-3:standard
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	out := flag.String("out", "demo/certs", "output directory")
	nodesArg := flag.String("nodes", "core-1:trusted,edge-2:standard,edge-3:standard",
		"comma-separated node:tier pairs (tier: standard|trusted|high)")
	days := flag.Int("days", 7, "certificate validity in days")
	flag.Parse()

	if err := run(*out, *nodesArg, *days); err != nil {
		fmt.Fprintln(os.Stderr, "gen-certs:", err)
		os.Exit(1)
	}
}

func run(out, nodesArg string, days int) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(time.Duration(days) * 24 * time.Hour)

	// ── CA ──
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "frien-demo-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caKey)
	if err != nil {
		return fmt.Errorf("ca cert: %w", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	if err := writePEM(filepath.Join(out, "ca.crt"), "CERTIFICATE", caDER); err != nil {
		return err
	}

	// ── Operator keypair (public half = pinned root; private half = signing) ──
	opPub, opKey, _ := ed25519.GenerateKey(rand.Reader)
	opTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "frien-operator"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	opDER, err := x509.CreateCertificate(rand.Reader, opTmpl, opTmpl, opPub, opKey)
	if err != nil {
		return fmt.Errorf("operator cert: %w", err)
	}
	if err := writePEM(filepath.Join(out, "operator.crt"), "CERTIFICATE", opDER); err != nil {
		return err
	}
	opKeyDER, _ := x509.MarshalPKCS8PrivateKey(opKey)
	if err := writePEM(filepath.Join(out, "operator.key"), "PRIVATE KEY", opKeyDER); err != nil {
		return err
	}

	// ── Node leaf certs (CN=nodeID, OU=tier) ──
	for _, pair := range strings.Split(nodesArg, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		node, tier := pair, "standard"
		if i := strings.IndexByte(pair, ':'); i >= 0 {
			node, tier = pair[:i], pair[i+1:]
		}
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{
				CommonName:         node,
				OrganizationalUnit: []string{"tier:" + tier},
			},
			NotBefore:   notBefore,
			NotAfter:    notAfter,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
		if err != nil {
			return fmt.Errorf("node %s cert: %w", node, err)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		dir := filepath.Join(out, node)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, "node.crt"), "CERTIFICATE", der); err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, "node.key"), "PRIVATE KEY", keyDER); err != nil {
			return err
		}
		fmt.Printf("  %-10s tier=%-8s -> %s\n", node, tier, dir)
	}

	fmt.Printf("wrote CA, operator keypair, and node certs to %s\n", out)
	return nil
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}
