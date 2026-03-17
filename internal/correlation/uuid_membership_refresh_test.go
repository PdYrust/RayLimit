package correlation

import (
	"testing"
	"time"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

func testUUIDMembershipRefreshRuntime() discovery.SessionRuntime {
	return discovery.SessionRuntime{
		Source:   discovery.DiscoverySourceHostProcess,
		Provider: "xray-api",
		Name:     "edge-a",
		HostPID:  4242,
	}
}

func testUUIDMembershipRefreshSubject() UUIDAggregateSubject {
	return UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDMembershipRefreshRuntime(),
	}
}

func testUUIDMembershipRefreshSession(id string) discovery.Session {
	return discovery.Session{
		ID:      id,
		Runtime: testUUIDMembershipRefreshRuntime(),
		Policy: discovery.SessionPolicyIdentity{
			UUID: "user-a",
		},
		Client: discovery.SessionClient{
			IP: "203.0.113.10",
		},
	}
}

func testUUIDMembershipRefreshNow() time.Time {
	return time.Date(2026, time.March, 15, 14, 0, 0, 0, time.UTC)
}

func testUUIDMembershipRefreshPolicy() discovery.RuntimeEvidencePolicy {
	return discovery.RuntimeEvidencePolicy{FreshTTL: 30 * time.Second}
}

func testUUIDMembershipSnapshot(t *testing.T, observedAt time.Time, sessions ...discovery.Session) UUIDMembershipSnapshot {
	t.Helper()

	subject := testUUIDMembershipRefreshSubject()
	membership, err := NewUUIDAggregateMembership(subject, sessions)
	if err != nil {
		t.Fatalf("expected cached membership to build, got %v", err)
	}
	return UUIDMembershipSnapshot{
		Membership: membership,
		Evidence: discovery.RuntimeEvidenceSnapshot{
			Result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDMembershipRefreshRuntime(),
				Evidence: buildUUIDMembershipEvidence(sessions...),
			},
			ObservedAt: observedAt,
		},
	}
}

func buildUUIDMembershipEvidence(sessions ...discovery.Session) []discovery.SessionEvidence {
	evidence := make([]discovery.SessionEvidence, 0, len(sessions))
	for _, session := range sessions {
		evidence = append(evidence, discovery.SessionEvidence{
			Runtime:    session.Runtime,
			Session:    session,
			Confidence: discovery.SessionEvidenceConfidenceHigh,
		})
	}

	return evidence
}

func TestUUIDMembershipRefresherReusesFreshCachedMembership(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	cached := testUUIDMembershipSnapshot(t, now.Add(-10*time.Second), testUUIDMembershipRefreshSession("conn-1"))

	result, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Policy:  testUUIDMembershipRefreshPolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected cached membership reuse to succeed, got %v", err)
	}

	if result.Action != UUIDMembershipRefreshReuseCached || result.Freshness != discovery.RuntimeEvidenceFreshnessFresh || result.RefreshNeeded {
		t.Fatalf("expected fresh cached membership reuse, got %#v", result)
	}
	if result.Membership == nil || result.Membership.MemberCount() != 1 {
		t.Fatalf("expected cached membership to be preserved, got %#v", result)
	}
}

func TestUUIDMembershipRefresherRequiresRefreshForStaleCachedMembership(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	cached := testUUIDMembershipSnapshot(t, now.Add(-2*time.Minute), testUUIDMembershipRefreshSession("conn-1"))

	result, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Policy:  testUUIDMembershipRefreshPolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected stale cached membership refresh result to succeed, got %v", err)
	}

	if result.Action != UUIDMembershipRefreshRefreshRequired || result.Freshness != discovery.RuntimeEvidenceFreshnessStale || !result.RefreshNeeded {
		t.Fatalf("expected stale cached membership refresh requirement, got %#v", result)
	}
	if result.Membership == nil || result.Membership.MemberCount() != 1 {
		t.Fatalf("expected stale cached membership to remain available for context, got %#v", result)
	}
}

func TestUUIDMembershipRefresherRefreshesMembershipFromFreshEvidence(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	cached := testUUIDMembershipSnapshot(t, now.Add(-2*time.Minute), testUUIDMembershipRefreshSession("conn-1"))
	latest := discovery.RuntimeEvidenceSnapshot{
		Result: discovery.SessionEvidenceResult{
			Provider: "xray-api",
			Runtime:  testUUIDMembershipRefreshRuntime(),
			Evidence: buildUUIDMembershipEvidence(
				testUUIDMembershipRefreshSession("conn-1"),
				testUUIDMembershipRefreshSession("conn-2"),
			),
		},
		ObservedAt: now.Add(-5 * time.Second),
	}

	result, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Latest:  &latest,
		Policy:  testUUIDMembershipRefreshPolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected fresh membership refresh to succeed, got %v", err)
	}

	if result.Action != UUIDMembershipRefreshRefreshed || result.Freshness != discovery.RuntimeEvidenceFreshnessFresh || result.RefreshNeeded {
		t.Fatalf("expected refreshed fresh membership result, got %#v", result)
	}
	if result.Membership == nil || result.Membership.MemberCount() != 2 || !result.Changed {
		t.Fatalf("expected refreshed membership change to be visible, got %#v", result)
	}
}

func TestUUIDMembershipRefresherReportsPartialEvidence(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	latest := discovery.RuntimeEvidenceSnapshot{
		Result: discovery.SessionEvidenceResult{
			Provider: "xray-api",
			Runtime:  testUUIDMembershipRefreshRuntime(),
			Evidence: buildUUIDMembershipEvidence(testUUIDMembershipRefreshSession("conn-1")),
			Issues: []discovery.SessionEvidenceIssue{{
				Code:    discovery.SessionEvidenceIssueInsufficient,
				Message: "online user evidence is incomplete",
			}},
		},
		ObservedAt: now.Add(-5 * time.Second),
	}

	result, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Latest:  &latest,
		Policy:  testUUIDMembershipRefreshPolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected partial membership refresh to succeed, got %v", err)
	}

	if result.Action != UUIDMembershipRefreshEvidencePartial || result.Freshness != discovery.RuntimeEvidenceFreshnessPartial || !result.RefreshNeeded {
		t.Fatalf("expected partial membership refresh classification, got %#v", result)
	}
	if result.Membership == nil || result.Membership.MemberCount() != 1 {
		t.Fatalf("expected partial membership context to be preserved, got %#v", result)
	}
}

func TestUUIDMembershipRefresherReportsUnavailableEvidence(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	latest := discovery.RuntimeEvidenceSnapshot{
		Result: discovery.SessionEvidenceResult{
			Provider: "xray-api",
			Runtime:  testUUIDMembershipRefreshRuntime(),
			Issues: []discovery.SessionEvidenceIssue{{
				Code:    discovery.SessionEvidenceIssueUnavailable,
				Message: "runtime control socket is unreachable",
			}},
		},
		ObservedAt: now.Add(-5 * time.Second),
	}

	result, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Latest:  &latest,
		Policy:  testUUIDMembershipRefreshPolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected unavailable membership refresh to succeed, got %v", err)
	}

	if result.Action != UUIDMembershipRefreshEvidenceUnavailable || result.Freshness != discovery.RuntimeEvidenceFreshnessUnavailable || !result.RefreshNeeded {
		t.Fatalf("expected unavailable membership refresh classification, got %#v", result)
	}
	if result.Membership != nil {
		t.Fatalf("expected unavailable evidence to avoid reporting current membership, got %#v", result)
	}
}
