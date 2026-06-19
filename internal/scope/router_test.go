package scope

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		want    Scope
		wantErr bool
	}{
		{"local", Scope{Kind: Local}, false},
		{"fleet", Scope{Kind: Fleet}, false},
		{"zone:edge-eu-west", Scope{Kind: Zone, Zone: "edge-eu-west"}, false},
		{"zone:", Scope{}, true},
		{"zone:bad name", Scope{}, true},
		{"zone:" + string(make([]byte, 65)), Scope{}, true},
		{"galaxy", Scope{}, true},
		{"", Scope{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := Parse(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) expected error", tc.in)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Parse(%q) = (%+v, %v), want %+v", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestParseRoundTrip(t *testing.T) {
	for _, s := range []string{"local", "fleet", "zone:edge-eu-west"} {
		sc, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if sc.String() != s {
			t.Errorf("round-trip %q -> %q", s, sc.String())
		}
	}
}

func mustParse(t *testing.T, s string) Scope {
	t.Helper()
	sc, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return sc
}

func TestShouldSendEgress(t *testing.T) {
	r := NewRouter("edge-eu-west")

	if r.ShouldSend(mustParse(t, "local"), "edge-eu-west") {
		t.Error("local must never be sent, even to a same-zone peer")
	}
	if !r.ShouldSend(mustParse(t, "fleet"), "edge-us-east") {
		t.Error("fleet should be sent to any peer")
	}
	if !r.ShouldSend(mustParse(t, "zone:edge-eu-west"), "edge-eu-west") {
		t.Error("zone op should be sent to a peer in that zone")
	}
	if r.ShouldSend(mustParse(t, "zone:edge-eu-west"), "edge-us-east") {
		t.Error("zone op must not be sent to a peer in another zone")
	}
}

func TestAcceptIngress(t *testing.T) {
	r := NewRouter("edge-eu-west")

	if r.Accept(mustParse(t, "local")) {
		t.Error("a received local op must be dropped")
	}
	if !r.Accept(mustParse(t, "fleet")) {
		t.Error("fleet op should be accepted")
	}
	if !r.Accept(mustParse(t, "zone:edge-eu-west")) {
		t.Error("op for our own zone should be accepted")
	}
	if r.Accept(mustParse(t, "zone:edge-us-east")) {
		t.Error("op for an unsubscribed zone must be dropped")
	}
}

func TestExtraZoneSubscription(t *testing.T) {
	core := NewRouter("core", "edge-eu-west", "edge-us-east")
	if !core.Accept(mustParse(t, "zone:edge-us-east")) {
		t.Error("an aggregator subscribed to a zone should accept its ops")
	}
	if !core.Replicates(mustParse(t, "zone:edge-eu-west")) {
		t.Error("subscribed zone should be replicated")
	}
	if core.Replicates(mustParse(t, "zone:edge-ap-south")) {
		t.Error("unsubscribed zone should not be replicated")
	}
}
