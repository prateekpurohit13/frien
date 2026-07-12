package identity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestTrustTierFromCert(t *testing.T) {
	mk := func(ous ...string) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: ous}}
	}
	cases := []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{"exact high", mk("high"), "high"},
		{"prefixed trusted", mk("tier:trusted"), "trusted"},
		{"case insensitive", mk("TIER:HIGH"), "high"},
		{"standard explicit", mk("standard"), "standard"},
		{"unknown -> standard", mk("engineering"), "standard"},
		{"no OU -> standard", mk(), "standard"},
		{"nil cert -> standard", nil, "standard"},
		{"tier among several OUs", mk("dept-x", "tier:trusted"), "trusted"},
	}
	for _, tc := range cases {
		if got := TrustTierFromCert(tc.cert); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
