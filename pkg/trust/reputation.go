package trust

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ReputationRecord is the parsed content of a TPT reputation DNS TXT record.
// Convention: _tpt-rep.<domain> TXT "v=tpt1 score=85 tier=verified since=2024-01-01"
type ReputationRecord struct {
	// Domain is the queried domain.
	Domain string
	// Score is a 0–100 trust score published by the domain operator.
	Score int
	// Tier is a human-readable trust tier, e.g. "verified", "provisional", "restricted".
	Tier string
	// Since is the date the reputation record was established (YYYY-MM-DD).
	Since string
	// Raw is the original TXT record string.
	Raw string
}

// LookupReputation queries DNS TXT records for the TPT reputation of domain.
// The record lives at _tpt-rep.<domain> and must begin with "v=tpt1".
// Returns nil if no valid record exists (not an error — domain simply has no published reputation).
func LookupReputation(ctx context.Context, domain string) (*ReputationRecord, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}

	host := "_tpt-rep." + strings.TrimSuffix(domain, ".")
	records, err := net.DefaultResolver.LookupTXT(ctx, host)
	if err != nil {
		// NXDOMAIN / no record is not an error — just no reputation data.
		if isDNSNoRecord(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reputation: dns lookup %s: %w", host, err)
	}

	for _, r := range records {
		rec := parseReputationTXT(domain, r)
		if rec != nil {
			return rec, nil
		}
	}
	return nil, nil // no valid tpt-rep record found
}

// parseReputationTXT parses a single TXT record string into a ReputationRecord.
// Returns nil if the record is not a valid tpt-rep record.
func parseReputationTXT(domain, txt string) *ReputationRecord {
	fields := strings.Fields(txt)
	if len(fields) == 0 {
		return nil
	}
	// Must start with version tag.
	if fields[0] != "v=tpt1" {
		return nil
	}

	rec := &ReputationRecord{Domain: domain, Raw: txt, Score: -1}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "score":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
				rec.Score = n
			}
		case "tier":
			rec.Tier = v
		case "since":
			rec.Since = v
		}
	}
	return rec
}

// isDNSNoRecord reports whether a DNS error is a "no such record" (NXDOMAIN / NOERROR+empty).
func isDNSNoRecord(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "NXDOMAIN") ||
		strings.Contains(msg, "no answer")
}

// TrustLevel classifies a reputation record into a coarse trust level.
type TrustLevel int

const (
	TrustUnknown    TrustLevel = iota // no DNS record
	TrustRestricted                   // score 0–24
	TrustProvisional                  // score 25–59
	TrustVerified                     // score 60–84
	TrustTrusted                      // score 85–100
)

func (t TrustLevel) String() string {
	switch t {
	case TrustRestricted:
		return "restricted"
	case TrustProvisional:
		return "provisional"
	case TrustVerified:
		return "verified"
	case TrustTrusted:
		return "trusted"
	default:
		return "unknown"
	}
}

// Level derives the TrustLevel from a ReputationRecord. Nil record → TrustUnknown.
func Level(r *ReputationRecord) TrustLevel {
	if r == nil || r.Score < 0 {
		return TrustUnknown
	}
	switch {
	case r.Score >= 85:
		return TrustTrusted
	case r.Score >= 60:
		return TrustVerified
	case r.Score >= 25:
		return TrustProvisional
	default:
		return TrustRestricted
	}
}
