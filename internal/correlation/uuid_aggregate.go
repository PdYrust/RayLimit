package correlation

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

// UUIDAggregateCardinality describes how many live members currently belong to
// a runtime-local aggregate UUID subject.
type UUIDAggregateCardinality string

const (
	UUIDAggregateCardinalityZero     UUIDAggregateCardinality = "zero_members"
	UUIDAggregateCardinalitySingle   UUIDAggregateCardinality = "single_member"
	UUIDAggregateCardinalityMultiple UUIDAggregateCardinality = "multiple_members"
)

func (c UUIDAggregateCardinality) Valid() bool {
	switch c {
	case UUIDAggregateCardinalityZero, UUIDAggregateCardinalitySingle, UUIDAggregateCardinalityMultiple:
		return true
	default:
		return false
	}
}

// UUIDAggregateSubject identifies one runtime-local shared UUID aggregate cap.
type UUIDAggregateSubject struct {
	UUID    string                   `json:"uuid"`
	Runtime discovery.SessionRuntime `json:"runtime"`
}

func (s UUIDAggregateSubject) Validate() error {
	if normalizeUUID(s.UUID) == "" {
		return errors.New("aggregate uuid subject requires a uuid")
	}
	if err := s.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate runtime: %w", err)
	}

	return nil
}

func (s UUIDAggregateSubject) Key() string {
	return strings.Join([]string{
		string(s.Runtime.Source),
		strings.TrimSpace(s.Runtime.Provider),
		strings.TrimSpace(s.Runtime.Name),
		fmt.Sprintf("%d", s.Runtime.HostPID),
		strings.TrimSpace(s.Runtime.ContainerID),
		normalizeUUID(s.UUID),
	}, "|")
}

// UUIDAggregateMember represents one live session that currently belongs to a
// runtime-local aggregate UUID subject.
type UUIDAggregateMember struct {
	Session discovery.Session `json:"session"`
}

func (m UUIDAggregateMember) Validate() error {
	if err := m.Session.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate member session: %w", err)
	}
	if strings.TrimSpace(m.Session.ID) == "" {
		return errors.New("aggregate member requires a session id")
	}
	if m.Session.Policy.Key() == "" {
		return errors.New("aggregate member requires a policy uuid")
	}

	return nil
}

func (m UUIDAggregateMember) Key() string {
	return strings.Join([]string{
		string(m.Session.Runtime.Source),
		strings.TrimSpace(m.Session.Runtime.Provider),
		strings.TrimSpace(m.Session.Runtime.Name),
		fmt.Sprintf("%d", m.Session.Runtime.HostPID),
		strings.TrimSpace(m.Session.Runtime.ContainerID),
		strings.TrimSpace(m.Session.ID),
	}, "|")
}

// UUIDAggregateMembership captures the current live session membership for one
// runtime-local aggregate UUID subject.
type UUIDAggregateMembership struct {
	Subject UUIDAggregateSubject  `json:"subject"`
	Members []UUIDAggregateMember `json:"members,omitempty"`
}

func NewUUIDAggregateMembership(subject UUIDAggregateSubject, sessions []discovery.Session) (UUIDAggregateMembership, error) {
	if err := subject.Validate(); err != nil {
		return UUIDAggregateMembership{}, err
	}

	membership := UUIDAggregateMembership{
		Subject: subject,
		Members: make([]UUIDAggregateMember, 0, len(sessions)),
	}
	seen := make(map[string]struct{}, len(sessions))
	for index, session := range sessions {
		member := UUIDAggregateMember{Session: session}
		if err := member.Validate(); err != nil {
			return UUIDAggregateMembership{}, fmt.Errorf("invalid aggregate member at index %d: %w", index, err)
		}
		if err := ensureAggregateMembership(member, subject); err != nil {
			return UUIDAggregateMembership{}, fmt.Errorf("invalid aggregate member at index %d: %w", index, err)
		}

		key := member.Key()
		if _, ok := seen[key]; ok {
			return UUIDAggregateMembership{}, fmt.Errorf("duplicate aggregate member %q", strings.TrimSpace(member.Session.ID))
		}
		seen[key] = struct{}{}
		membership.Members = append(membership.Members, member)
	}

	sortAggregateMembers(membership.Members)
	if err := membership.Validate(); err != nil {
		return UUIDAggregateMembership{}, err
	}

	return membership, nil
}

func (m UUIDAggregateMembership) Validate() error {
	if err := m.Subject.Validate(); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(m.Members))
	for index, member := range m.Members {
		if err := member.Validate(); err != nil {
			return fmt.Errorf("invalid aggregate member at index %d: %w", index, err)
		}
		if err := ensureAggregateMembership(member, m.Subject); err != nil {
			return fmt.Errorf("invalid aggregate member at index %d: %w", index, err)
		}

		key := member.Key()
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate aggregate member %q", strings.TrimSpace(member.Session.ID))
		}
		seen[key] = struct{}{}
	}

	return nil
}

func (m UUIDAggregateMembership) MemberCount() int {
	return len(m.Members)
}

func (m UUIDAggregateMembership) Cardinality() UUIDAggregateCardinality {
	switch len(m.Members) {
	case 0:
		return UUIDAggregateCardinalityZero
	case 1:
		return UUIDAggregateCardinalitySingle
	default:
		return UUIDAggregateCardinalityMultiple
	}
}

func (m UUIDAggregateMembership) HasMember(sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return false
	}

	for _, member := range m.Members {
		if strings.TrimSpace(member.Session.ID) == sessionID {
			return true
		}
	}

	return false
}

func (m UUIDAggregateMembership) Join(session discovery.Session) (UUIDAggregateMembership, bool, error) {
	if err := m.Validate(); err != nil {
		return UUIDAggregateMembership{}, false, err
	}

	member := UUIDAggregateMember{Session: session}
	if err := member.Validate(); err != nil {
		return UUIDAggregateMembership{}, false, err
	}
	if err := ensureAggregateMembership(member, m.Subject); err != nil {
		return UUIDAggregateMembership{}, false, err
	}

	next := UUIDAggregateMembership{
		Subject: m.Subject,
		Members: append([]UUIDAggregateMember(nil), m.Members...),
	}
	key := member.Key()
	for index, existing := range next.Members {
		if existing.Key() != key {
			continue
		}
		if existing.Session == member.Session {
			return next, false, nil
		}
		next.Members[index] = member
		sortAggregateMembers(next.Members)
		if err := next.Validate(); err != nil {
			return UUIDAggregateMembership{}, false, err
		}
		return next, true, nil
	}

	next.Members = append(next.Members, member)
	sortAggregateMembers(next.Members)
	if err := next.Validate(); err != nil {
		return UUIDAggregateMembership{}, false, err
	}

	return next, true, nil
}

func (m UUIDAggregateMembership) Leave(sessionID string) (UUIDAggregateMembership, bool, error) {
	if err := m.Validate(); err != nil {
		return UUIDAggregateMembership{}, false, err
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return UUIDAggregateMembership{}, false, errors.New("aggregate leave requires a session id")
	}

	next := UUIDAggregateMembership{
		Subject: m.Subject,
		Members: make([]UUIDAggregateMember, 0, len(m.Members)),
	}
	removed := false
	for _, member := range m.Members {
		if strings.TrimSpace(member.Session.ID) == sessionID {
			removed = true
			continue
		}
		next.Members = append(next.Members, member)
	}
	if !removed {
		return m, false, nil
	}
	if err := next.Validate(); err != nil {
		return UUIDAggregateMembership{}, false, err
	}

	return next, true, nil
}

func ensureAggregateMembership(member UUIDAggregateMember, subject UUIDAggregateSubject) error {
	if !sameRuntime(member.Session.Runtime, subject.Runtime) {
		return errors.New("aggregate member runtime does not match the aggregate subject runtime")
	}
	if member.Session.Policy.Key() != normalizeUUID(subject.UUID) {
		return errors.New("aggregate member uuid does not match the aggregate subject uuid")
	}

	return nil
}

func sortAggregateMembers(members []UUIDAggregateMember) {
	sort.Slice(members, func(i, j int) bool {
		return members[i].Key() < members[j].Key()
	})
}
