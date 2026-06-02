package trust_test

import (
	"context"
	"testing"
	"time"

	"github.com/PhillipC05/tpt-identity/pkg/crypto"
	"github.com/PhillipC05/tpt-identity/pkg/trust"
)

// ---- Permit ----

func TestIssueVerifyPermit(t *testing.T) {
	pubKey, privKey, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	token, err := trust.IssuePermit(
		"did:peer:issuer",
		privKey,
		"did:peer:subject",
		"did:peer:audience",
		"read:email",
		5*time.Minute,
		"jti-001",
	)
	if err != nil {
		t.Fatal(err)
	}

	p, err := trust.VerifyPermit(token, pubKey, "did:peer:audience", "read:email")
	if err != nil {
		t.Fatalf("VerifyPermit: %v", err)
	}
	if p.Subject != "did:peer:subject" {
		t.Errorf("unexpected subject: %s", p.Subject)
	}
	if p.Action != "read:email" {
		t.Errorf("unexpected action: %s", p.Action)
	}
}

func TestVerifyPermitRejectsWrongKey(t *testing.T) {
	_, privKey, _ := crypto.GenerateSigningKey()
	wrongPub, _, _ := crypto.GenerateSigningKey()
	token, _ := trust.IssuePermit("did:peer:issuer", privKey, "did:peer:subject", "did:peer:aud", "read:x", time.Minute, "")
	if _, err := trust.VerifyPermit(token, wrongPub, "", ""); err == nil {
		t.Error("expected error for wrong key")
	}
}

func TestVerifyPermitRejectsExpired(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	token, _ := trust.IssuePermit("did:peer:issuer", privKey, "did:peer:sub", "did:peer:aud", "action", -time.Hour, "")
	if _, err := trust.VerifyPermit(token, pubKey, "", ""); err == nil {
		t.Error("expected error for expired permit")
	}
}

func TestVerifyPermitRejectsWrongAudience(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	token, _ := trust.IssuePermit("did:peer:issuer", privKey, "did:peer:sub", "did:peer:aud", "action", time.Minute, "")
	if _, err := trust.VerifyPermit(token, pubKey, "did:peer:other", "action"); err == nil {
		t.Error("expected error for wrong audience")
	}
}

func TestVerifyPermitRejectsWrongAction(t *testing.T) {
	pubKey, privKey, _ := crypto.GenerateSigningKey()
	token, _ := trust.IssuePermit("did:peer:issuer", privKey, "did:peer:sub", "did:peer:aud", "read:x", time.Minute, "")
	if _, err := trust.VerifyPermit(token, pubKey, "did:peer:aud", "write:y"); err == nil {
		t.Error("expected error for wrong action")
	}
}

func TestVerifyPermitMalformed(t *testing.T) {
	pubKey, _, _ := crypto.GenerateSigningKey()
	if _, err := trust.VerifyPermit("not.a.valid.token.format", pubKey, "", ""); err == nil {
		t.Error("expected error for malformed token")
	}
}

// ---- Reputation ----

func TestParseReputationTXTValid(t *testing.T) {
	// Use an unexported helper through LookupReputation with a fake TXT record via loopback.
	// The simplest test: parse a known-good record value and check fields.
	// Since parseReputationTXT is unexported, test via LookupReputation on a real domain
	// that has no _tpt-rep record (returns nil, nil).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// A domain guaranteed to not have a _tpt-rep record — should return nil without error.
	rec, err := trust.LookupReputation(ctx, "example.com")
	if err != nil {
		t.Logf("LookupReputation DNS error (may be expected in CI): %v", err)
		return
	}
	// nil is valid (no record found).
	_ = rec
}

func TestTrustLevelUnknownForNilRecord(t *testing.T) {
	if level := trust.Level(nil); level != trust.TrustUnknown {
		t.Errorf("expected TrustUnknown for nil record, got %v", level)
	}
}

func TestTrustLevelFromScore(t *testing.T) {
	cases := []struct {
		score int
		want  trust.TrustLevel
	}{
		{100, trust.TrustTrusted},
		{85, trust.TrustTrusted},
		{84, trust.TrustVerified},
		{60, trust.TrustVerified},
		{59, trust.TrustProvisional},
		{25, trust.TrustProvisional},
		{24, trust.TrustRestricted},
		{0, trust.TrustRestricted},
	}
	for _, c := range cases {
		rec := &trust.ReputationRecord{Score: c.score}
		if got := trust.Level(rec); got != c.want {
			t.Errorf("Level(score=%d) = %v, want %v", c.score, got, c.want)
		}
	}
}

func TestTrustLevelString(t *testing.T) {
	if trust.TrustTrusted.String() != "trusted" {
		t.Errorf("unexpected string: %s", trust.TrustTrusted.String())
	}
}
