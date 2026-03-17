package correlation

import (
	"testing"
	"time"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

func testUUIDMembershipGracePolicy() discovery.RuntimeEvidenceChurnPolicy {
	return discovery.RuntimeEvidenceChurnPolicy{DisconnectGraceTTL: 20 * time.Second}
}

func TestUUIDMembershipGraceEvaluatorKeepsStableFreshMembership(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	cached := testUUIDMembershipSnapshot(t, now.Add(-5*time.Second), testUUIDMembershipRefreshSession("conn-1"))

	refresh, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Policy:  testUUIDMembershipRefreshPolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected fresh membership refresh to succeed, got %v", err)
	}

	result, err := (UUIDMembershipGraceEvaluator{}).Decide(UUIDMembershipGraceInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Refresh: refresh,
		Policy:  testUUIDMembershipGracePolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected stable uuid grace decision to succeed, got %v", err)
	}

	if result.Action != discovery.RuntimeEvidenceChurnActionStable {
		t.Fatalf("expected stable uuid grace action, got %#v", result)
	}
	if result.EffectiveMembership == nil || result.EffectiveMembership.MemberCount() != 1 {
		t.Fatalf("expected effective membership to stay current, got %#v", result)
	}
}

func TestUUIDMembershipGraceEvaluatorGraceRetainsBriefFreshDisconnect(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	cached := testUUIDMembershipSnapshot(t, now.Add(-5*time.Second), testUUIDMembershipRefreshSession("conn-1"))
	refreshPolicy := discovery.RuntimeEvidencePolicy{FreshTTL: 2 * time.Second}
	latest := discovery.RuntimeEvidenceSnapshot{
		Result: discovery.SessionEvidenceResult{
			Provider: "xray-api",
			Runtime:  testUUIDMembershipRefreshRuntime(),
		},
		ObservedAt: now.Add(-2 * time.Second),
	}

	refresh, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Latest:  &latest,
		Policy:  refreshPolicy,
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected fresh zero-member refresh to succeed, got %v", err)
	}

	result, err := (UUIDMembershipGraceEvaluator{}).Decide(UUIDMembershipGraceInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Refresh: refresh,
		Policy:  testUUIDMembershipGracePolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected grace-retained uuid decision to succeed, got %v", err)
	}

	if result.Action != discovery.RuntimeEvidenceChurnActionGraceRetained || result.GraceUntil == nil {
		t.Fatalf("expected grace-retained uuid decision, got %#v", result)
	}
	if result.EffectiveMembership == nil || result.EffectiveMembership.MemberCount() != 1 {
		t.Fatalf("expected cached membership to be retained through grace, got %#v", result)
	}
}

func TestUUIDMembershipGraceEvaluatorAllowsImmediateRemovalAfterGraceExpires(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	cached := testUUIDMembershipSnapshot(t, now.Add(-1*time.Minute), testUUIDMembershipRefreshSession("conn-1"))
	refreshPolicy := discovery.RuntimeEvidencePolicy{FreshTTL: 2 * time.Second}
	latest := discovery.RuntimeEvidenceSnapshot{
		Result: discovery.SessionEvidenceResult{
			Provider: "xray-api",
			Runtime:  testUUIDMembershipRefreshRuntime(),
		},
		ObservedAt: now.Add(-2 * time.Second),
	}

	refresh, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Latest:  &latest,
		Policy:  refreshPolicy,
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected fresh zero-member refresh to succeed, got %v", err)
	}

	result, err := (UUIDMembershipGraceEvaluator{}).Decide(UUIDMembershipGraceInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Refresh: refresh,
		Policy:  testUUIDMembershipGracePolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected immediate-remove uuid decision to succeed, got %v", err)
	}

	if result.Action != discovery.RuntimeEvidenceChurnActionImmediatelyRemovable {
		t.Fatalf("expected immediately-removable uuid decision, got %#v", result)
	}
	if result.EffectiveMembership != nil {
		t.Fatalf("expected immediate removal to avoid retaining membership, got %#v", result)
	}
}

func TestUUIDMembershipGraceEvaluatorRefreshRequiredForStaleMembershipEvidence(t *testing.T) {
	now := testUUIDMembershipRefreshNow()
	cached := testUUIDMembershipSnapshot(t, now.Add(-2*time.Minute), testUUIDMembershipRefreshSession("conn-1"))

	refresh, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Policy:  testUUIDMembershipRefreshPolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected stale cached membership refresh result to succeed, got %v", err)
	}

	result, err := (UUIDMembershipGraceEvaluator{}).Decide(UUIDMembershipGraceInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Cached:  &cached,
		Refresh: refresh,
		Policy:  testUUIDMembershipGracePolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected refresh-required uuid grace decision to succeed, got %v", err)
	}

	if result.Action != discovery.RuntimeEvidenceChurnActionRefreshRequired {
		t.Fatalf("expected refresh-required uuid grace action, got %#v", result)
	}
	if result.EffectiveMembership == nil || result.EffectiveMembership.MemberCount() != 1 {
		t.Fatalf("expected stale cached membership to remain available for context, got %#v", result)
	}
}

func TestUUIDMembershipGraceEvaluatorDefersOnPartialEvidence(t *testing.T) {
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
		ObservedAt: now.Add(-2 * time.Second),
	}

	refresh, err := (UUIDMembershipRefresher{}).Refresh(UUIDMembershipRefreshInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Latest:  &latest,
		Policy:  testUUIDMembershipRefreshPolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected partial membership refresh to succeed, got %v", err)
	}

	result, err := (UUIDMembershipGraceEvaluator{}).Decide(UUIDMembershipGraceInput{
		Subject: testUUIDMembershipRefreshSubject(),
		Refresh: refresh,
		Policy:  testUUIDMembershipGracePolicy(),
		Now:     now,
	})
	if err != nil {
		t.Fatalf("expected deferred uuid grace decision to succeed, got %v", err)
	}

	if result.Action != discovery.RuntimeEvidenceChurnActionDefer {
		t.Fatalf("expected deferred uuid grace action, got %#v", result)
	}
	if result.EffectiveMembership == nil || result.EffectiveMembership.MemberCount() != 1 {
		t.Fatalf("expected partial membership context to remain available, got %#v", result)
	}
}
