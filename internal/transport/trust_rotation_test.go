package transport

import (
	"encoding/pem"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/identity"
)

// pem returns the test CA's own certificate as PEM, the form
// identity.TrustBundle consumes.
func (ca *testCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// TestTrustRotationOverlapWindow is the real-world proof this whole feature
// exists for. A real rotation proceeds in order: (1) every node's trust
// bundle is prepared to accept the new CA alongside the old one, well before
// (2) any node's own leaf certificate actually switches CAs -- otherwise a
// node presenting a freshly-issued new-CA cert would be rejected by peers
// that haven't yet learned to trust it. This test models exactly that: all
// three transports share the same rotation timeline (each holds its own
// TrustBundle seeded identically), while their own presented identity
// varies (old-CA-issued vs new-CA-issued), representing a fleet mid
// cert-rollout. During the overlap window every combination must connect;
// once the window elapses, only new-CA-issued identities may.
func TestTrustRotationOverlapWindow(t *testing.T) {
	log := zerolog.Nop()
	oldCA := newTestCA(t)
	newCA := newTestCA(t)

	serverID := oldCA.nodeIdentity(t, "node.server")   // hasn't rolled its own cert yet
	newClientID := newCA.nodeIdentity(t, "node.client") // already rolled

	now := time.Now()
	newBundle := func(t *testing.T) *identity.TrustBundle {
		t.Helper()
		b, err := identity.NewTrustBundle(oldCA.pem(), time.Minute)
		if err != nil {
			t.Fatalf("new trust bundle: %v", err)
		}
		b.SetClock(func() time.Time { return now })
		return b
	}
	serverBundle := newBundle(t)
	clientBundle := newBundle(t)

	server, err := NewWithTrustSource(serverID, serverBundle, testConfig(KEMClassical), nil, log)
	if err != nil {
		t.Fatalf("new server transport: %v", err)
	}
	client, err := NewWithTrustSource(newClientID, clientBundle, testConfig(KEMClassical), nil, log)
	if err != nil {
		t.Fatalf("new client transport: %v", err)
	}

	// Before rotation: the new-CA-issued client cannot connect to the
	// still-old-CA-only server (and vice versa would equally fail).
	if _, _, err := dialAndAccept(t, server, client); err == nil {
		t.Fatal("a new-CA client should be rejected before any trust bundle accepts the new CA")
	}

	// Stage the new CA on both sides (the trust-bundle-first step of a real
	// rotation) and refresh the live transports.
	for _, b := range []*identity.TrustBundle{serverBundle, clientBundle} {
		if err := b.PrepareNext(newCA.pem()); err != nil {
			t.Fatalf("prepare next: %v", err)
		}
	}
	if err := server.RefreshTrust(); err != nil {
		t.Fatalf("refresh server trust: %v", err)
	}
	if err := client.RefreshTrust(); err != nil {
		t.Fatalf("refresh client trust: %v", err)
	}

	// Within the overlap window: the server (still old-CA-issued) and the
	// client (already new-CA-issued) can now talk, since both trust both CAs.
	if _, _, err := dialAndAccept(t, server, client); err != nil {
		t.Fatalf("connection should succeed during the overlap window: %v", err)
	}

	// Advance past the overlap window and refresh again: the old CA is
	// retired. The server's own cert is still old-CA-issued, so it can no
	// longer even present a trusted identity to a peer that's completed
	// cutover -- proving the window actually closes rather than the union
	// persisting forever.
	now = now.Add(2 * time.Minute)
	if err := server.RefreshTrust(); err != nil {
		t.Fatalf("refresh server trust after window: %v", err)
	}
	if err := client.RefreshTrust(); err != nil {
		t.Fatalf("refresh client trust after window: %v", err)
	}
	if _, _, err := dialAndAccept(t, server, client); err == nil {
		t.Fatal("an old-CA-issued identity should be rejected once the overlap window has elapsed")
	}
}
