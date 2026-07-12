package identity

import (
	"crypto/x509"
	"strings"
)

// TrustTierStandard is the conservative default tier for any node whose
// certificate does not carry a recognized tier.
const TrustTierStandard = "standard"

// knownTrustTiers are the quorum trust tiers frien recognizes, in the same
// vocabulary as policy.DefaultTrustWeights.
var knownTrustTiers = map[string]bool{"standard": true, "trusted": true, "high": true}

// TrustTierFromCert extracts the operator-issued trust tier bound in a CA-signed
// leaf certificate's Organizational Unit. Because the tier travels inside the
// signed certificate rather than a mutable self-report, a node cannot claim a
// higher tier than its CA issued it — this is what makes trust-tier-weighted
// quorum Sybil-resistant (a compromised node cannot inflate its own weight by
// asserting "high"). It recognizes an OU that is exactly a tier name or is
// prefixed "tier:" (e.g. "tier:high"). Any absent, malformed, or unrecognized
// value maps to the conservative "standard".
func TrustTierFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return TrustTierStandard
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		v := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ou)), "tier:")
		if knownTrustTiers[v] {
			return v
		}
	}
	return TrustTierStandard
}
