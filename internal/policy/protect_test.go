package policy

import "testing"

func TestNewProtectedSetRejectsIPv4Only(t *testing.T) {
	_, err := NewProtectedSet([]string{"10.0.0.0/8", "192.168.0.0/16"})
	if err == nil {
		t.Fatal("expected IPv4-only protected list to be rejected")
	}
}

func TestNewProtectedSetRejectsBadCIDR(t *testing.T) {
	if _, err := NewProtectedSet([]string{"not-a-cidr", "::1/128"}); err == nil {
		t.Fatal("expected bad CIDR to be rejected")
	}
}

func TestDefaultsIncludeIPv6AndMetadata(t *testing.T) {
	ps, err := NewProtectedSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"127.0.0.1", "10.5.5.5", "169.254.169.254", "::1", "fe80::1"} {
		if prot, _ := ps.IsProtected(target); !prot {
			t.Errorf("%s should be protected by defaults", target)
		}
	}
}

func TestPublicIPNotProtected(t *testing.T) {
	ps, _ := NewProtectedSet(nil)
	if prot, reason := ps.IsProtected("8.8.8.8"); prot {
		t.Errorf("public IP should not be protected: %s", reason)
	}
}

func TestCIDRIndicatorOverlappingProtectedIsProtected(t *testing.T) {
	ps, _ := NewProtectedSet(nil)
	// Blocking 10.0.0.0/8 as a range must be refused.
	if prot, _ := ps.IsProtected("10.0.0.0/8"); !prot {
		t.Error("CIDR overlapping a protected range should be protected")
	}
	// A public CIDR is fine.
	if prot, _ := ps.IsProtected("203.0.113.0/24"); prot {
		t.Error("public CIDR should not be protected")
	}
}

func TestSelfPlaneProtection(t *testing.T) {
	ps, _ := NewProtectedSet(nil)
	ps.AddSelfPlane("198.51.100.10:7443", "mesh peer address")
	if prot, reason := ps.IsProtected("198.51.100.10"); !prot {
		t.Fatalf("self-plane IP should be protected; got reason=%q", reason)
	}
}

func TestAdminEndpointDeny(t *testing.T) {
	p := &Policy{ID: "x", Version: 1, Action: "block", DenyIfTargetIsAdminEndpoint: true}
	ps, _ := FromPolicy(p)
	ps.SetAdminEndpoint("192.0.2.50:9090")
	if prot, _ := ps.IsProtected("192.0.2.50"); !prot {
		t.Fatal("admin endpoint should be denied when deny_if_target_is_admin_endpoint is set")
	}
}

func TestHostnameIndicatorNotAddressProtected(t *testing.T) {
	ps, _ := NewProtectedSet(nil)
	if prot, _ := ps.IsProtected("evil.example.com"); prot {
		t.Error("a hostname indicator is not an address and should not hit CIDR protection")
	}
}
