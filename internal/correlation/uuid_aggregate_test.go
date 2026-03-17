package correlation

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

func TestUUIDAggregateSubjectValidate(t *testing.T) {
	subject := UUIDAggregateSubject{
		UUID:    "User-A",
		Runtime: testUUIDRuntime(),
	}

	if err := subject.Validate(); err != nil {
		t.Fatalf("expected aggregate subject to validate, got %v", err)
	}
	if !strings.Contains(subject.Key(), "user-a") {
		t.Fatalf("expected aggregate subject key to normalize the uuid, got %q", subject.Key())
	}
}

func TestNewUUIDAggregateMembershipZeroMembers(t *testing.T) {
	membership, err := NewUUIDAggregateMembership(UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	}, nil)
	if err != nil {
		t.Fatalf("expected empty aggregate membership to validate, got %v", err)
	}

	if membership.MemberCount() != 0 {
		t.Fatalf("expected zero aggregate members, got %#v", membership)
	}
	if membership.Cardinality() != UUIDAggregateCardinalityZero {
		t.Fatalf("expected zero-member cardinality, got %#v", membership)
	}
}

func TestNewUUIDAggregateMembershipSingleMember(t *testing.T) {
	membership, err := NewUUIDAggregateMembership(UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	}, []discovery.Session{
		testUUIDSession("conn-1", "user-a"),
	})
	if err != nil {
		t.Fatalf("expected single-member aggregate membership to validate, got %v", err)
	}

	if membership.MemberCount() != 1 {
		t.Fatalf("expected one aggregate member, got %#v", membership)
	}
	if membership.Cardinality() != UUIDAggregateCardinalitySingle {
		t.Fatalf("expected single-member cardinality, got %#v", membership)
	}
	if !membership.HasMember("conn-1") {
		t.Fatalf("expected aggregate membership to include conn-1, got %#v", membership)
	}
}

func TestNewUUIDAggregateMembershipMultipleMembersIsDeterministic(t *testing.T) {
	membership, err := NewUUIDAggregateMembership(UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	}, []discovery.Session{
		testUUIDSession("conn-2", "user-a"),
		testUUIDSession("conn-1", "user-a"),
	})
	if err != nil {
		t.Fatalf("expected multi-member aggregate membership to validate, got %v", err)
	}

	if membership.MemberCount() != 2 {
		t.Fatalf("expected two aggregate members, got %#v", membership)
	}
	if membership.Cardinality() != UUIDAggregateCardinalityMultiple {
		t.Fatalf("expected multi-member cardinality, got %#v", membership)
	}
	if membership.Members[0].Session.ID != "conn-1" || membership.Members[1].Session.ID != "conn-2" {
		t.Fatalf("expected aggregate members to sort deterministically, got %#v", membership.Members)
	}
}

func TestNewUUIDAggregateMembershipRejectsRuntimeMismatch(t *testing.T) {
	session := testUUIDSession("conn-1", "user-a")
	session.Runtime.HostPID = 2002

	_, err := NewUUIDAggregateMembership(UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	}, []discovery.Session{session})
	if err == nil {
		t.Fatal("expected runtime mismatch to fail aggregate membership construction")
	}
	if !strings.Contains(err.Error(), "aggregate member runtime does not match") {
		t.Fatalf("unexpected runtime mismatch error: %v", err)
	}
}

func TestNewUUIDAggregateMembershipRejectsDuplicateMembers(t *testing.T) {
	_, err := NewUUIDAggregateMembership(UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	}, []discovery.Session{
		testUUIDSession("conn-1", "user-a"),
		testUUIDSession("conn-1", "user-a"),
	})
	if err == nil {
		t.Fatal("expected duplicate aggregate member construction to fail")
	}
	if !strings.Contains(err.Error(), "duplicate aggregate member") {
		t.Fatalf("unexpected duplicate aggregate member error: %v", err)
	}
}

func TestUUIDAggregateMembershipJoinAndLeave(t *testing.T) {
	membership, err := NewUUIDAggregateMembership(UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	}, []discovery.Session{
		testUUIDSession("conn-1", "user-a"),
	})
	if err != nil {
		t.Fatalf("expected initial aggregate membership to validate, got %v", err)
	}

	joined, changed, err := membership.Join(testUUIDSession("conn-2", "user-a"))
	if err != nil {
		t.Fatalf("expected aggregate join to succeed, got %v", err)
	}
	if !changed {
		t.Fatalf("expected aggregate join to report a change, got %#v", joined)
	}
	if joined.MemberCount() != 2 || joined.Cardinality() != UUIDAggregateCardinalityMultiple {
		t.Fatalf("unexpected aggregate membership after join: %#v", joined)
	}

	left, changed, err := joined.Leave("conn-1")
	if err != nil {
		t.Fatalf("expected aggregate leave to succeed, got %v", err)
	}
	if !changed {
		t.Fatalf("expected aggregate leave to report a change, got %#v", left)
	}
	if left.MemberCount() != 1 || left.Cardinality() != UUIDAggregateCardinalitySingle {
		t.Fatalf("unexpected aggregate membership after leave: %#v", left)
	}
	if left.HasMember("conn-1") {
		t.Fatalf("expected aggregate leave to remove conn-1, got %#v", left)
	}
}

func TestUUIDAggregateMembershipJoinRejectsMismatchedUUID(t *testing.T) {
	membership, err := NewUUIDAggregateMembership(UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	}, nil)
	if err != nil {
		t.Fatalf("expected empty aggregate membership to validate, got %v", err)
	}

	_, _, err = membership.Join(testUUIDSession("conn-1", "other-user"))
	if err == nil {
		t.Fatal("expected mismatched uuid join to fail")
	}
	if !strings.Contains(err.Error(), "aggregate member uuid does not match") {
		t.Fatalf("unexpected aggregate uuid mismatch error: %v", err)
	}
}

func TestUUIDAggregateMembershipLeaveRejectsBlankSessionID(t *testing.T) {
	membership, err := NewUUIDAggregateMembership(UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	}, nil)
	if err != nil {
		t.Fatalf("expected empty aggregate membership to validate, got %v", err)
	}

	_, _, err = membership.Leave("  ")
	if err == nil {
		t.Fatal("expected blank aggregate leave to fail")
	}
	if !strings.Contains(err.Error(), "aggregate leave requires a session id") {
		t.Fatalf("unexpected aggregate leave error: %v", err)
	}
}
