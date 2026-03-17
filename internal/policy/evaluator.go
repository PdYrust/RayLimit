package policy

import (
	"fmt"
	"strings"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

// Evaluator reduces matching policies for a single runtime session.
type Evaluator struct{}

// Match describes a policy that matched a session during evaluation.
type Match struct {
	Index      int    `json:"index"`
	Policy     Policy `json:"policy"`
	Precedence int    `json:"precedence"`
	Winner     bool   `json:"winner,omitempty"`
}

// Evaluation captures the full outcome of policy evaluation for a session.
type Evaluation struct {
	Matches         []Match     `json:"matches,omitempty"`
	Winning         []Match     `json:"winning,omitempty"`
	NonWinning      []Match     `json:"non_winning,omitempty"`
	Selection       Selection   `json:"selection,omitempty"`
	EffectiveLimits LimitPolicy `json:"effective_limits,omitempty"`
	EffectiveReason string      `json:"effective_reason,omitempty"`
}

// Evaluate validates the supplied policies, matches them against the session,
// applies target-kind precedence, and computes the effective directional limits.
func (Evaluator) Evaluate(policies []Policy, session discovery.Session) (Evaluation, error) {
	matches, selection, winners, err := matchAndSelect(policies, session)
	if err != nil {
		return Evaluation{}, err
	}

	for index := range matches {
		_, matches[index].Winner = winners[matches[index].Index]
	}

	evaluation := Evaluation{
		Matches:    matches,
		Winning:    winningMatches(matches),
		NonWinning: nonWinningMatches(matches),
		Selection:  selection,
	}

	if !selection.Excluded() {
		evaluation.EffectiveLimits = mergeLimitPolicies(selection.Limits)
	}
	evaluation.EffectiveReason = effectiveReason(evaluation)

	return evaluation, nil
}

// HasMatch reports whether any policy matched the evaluated session.
func (e Evaluation) HasMatch() bool {
	return len(e.Matches) != 0
}

// Excluded reports whether the winning policies produce an exclusion result.
func (e Evaluation) Excluded() bool {
	return e.Selection.Excluded()
}

// WinningPolicies returns the matched policies that survived precedence resolution.
func (e Evaluation) WinningPolicies() []Match {
	if len(e.Winning) != 0 {
		return append([]Match(nil), e.Winning...)
	}

	winners := make([]Match, 0, len(e.Matches))
	for _, match := range e.Matches {
		if match.Winner {
			winners = append(winners, match)
		}
	}

	return winners
}

// NonWinningPolicies returns matched policies that lost due to precedence or
// same-precedence exclude resolution.
func (e Evaluation) NonWinningPolicies() []Match {
	if len(e.NonWinning) != 0 {
		return append([]Match(nil), e.NonWinning...)
	}

	nonWinning := make([]Match, 0, len(e.Matches))
	for _, match := range e.Matches {
		if match.Winner {
			continue
		}
		nonWinning = append(nonWinning, match)
	}

	return nonWinning
}

// HasCoexistence reports whether multiple matching rules or precedence
// resolution shaped the final effective result.
func (e Evaluation) HasCoexistence() bool {
	return len(e.Matches) > 1 || len(e.NonWinningPolicies()) != 0 || len(e.WinningPolicies()) > 1
}

func matchAndSelect(policies []Policy, session discovery.Session) ([]Match, Selection, map[int]struct{}, error) {
	matches := make([]Match, 0, len(policies))
	winnerIndexes := make(map[int]struct{})
	var selection Selection

	for index, policy := range policies {
		if err := policy.Validate(); err != nil {
			return nil, Selection{}, nil, fmt.Errorf("invalid policy at index %d: %w", index, err)
		}
		if !policy.Target.MatchesSession(session) {
			continue
		}

		match := Match{
			Index:      index,
			Policy:     policy,
			Precedence: policy.Target.Kind.Precedence(),
		}
		matches = append(matches, match)

		precedence := match.Precedence
		selectedPrecedence := selection.Kind.Precedence()
		if precedence > selectedPrecedence {
			selection = Selection{
				Kind:       policy.Target.Kind,
				Precedence: precedence,
			}
			clear(winnerIndexes)
		} else if precedence < selectedPrecedence {
			continue
		}

		switch policy.Effect.normalized() {
		case EffectExclude:
			if !selection.Excluded() {
				selection.Limits = nil
				clear(winnerIndexes)
			}

			selection.Excludes = append(selection.Excludes, policy)
			winnerIndexes[index] = struct{}{}
		case EffectLimit:
			if selection.Excluded() {
				continue
			}

			selection.Limits = append(selection.Limits, policy)
			winnerIndexes[index] = struct{}{}
		}
	}

	return matches, selection, winnerIndexes, nil
}

func winningMatches(matches []Match) []Match {
	winning := make([]Match, 0, len(matches))
	for _, match := range matches {
		if match.Winner {
			winning = append(winning, match)
		}
	}

	return winning
}

func nonWinningMatches(matches []Match) []Match {
	nonWinning := make([]Match, 0, len(matches))
	for _, match := range matches {
		if match.Winner {
			continue
		}
		nonWinning = append(nonWinning, match)
	}

	return nonWinning
}

func effectiveReason(e Evaluation) string {
	if len(e.Matches) == 0 {
		return "no policy matched the current session"
	}
	if e.Selection.Kind == "" {
		return "matching policies did not produce an effective limiter selection"
	}

	reason := fmt.Sprintf("%s precedence selected the effective rule set", e.Selection.Kind)
	if broader := broaderNonWinningKinds(e.Selection.Kind, e.NonWinningPolicies()); len(broader) != 0 {
		reason += fmt.Sprintf(" over matching %s rules", joinKindsForReason(broader))
	}

	parts := []string{reason}

	if e.Excluded() {
		suppressedSameKindLimits := countNonWinningKindMatches(e.Selection.Kind, e.NonWinningPolicies())
		if suppressedSameKindLimits != 0 {
			parts = append(
				parts,
				fmt.Sprintf(
					"exclude rules at the winning precedence suppressed %d matching %s limit %s",
					suppressedSameKindLimits,
					e.Selection.Kind,
					pluralizeRule(suppressedSameKindLimits),
				),
			)
		} else {
			parts = append(parts, "exclude rules at the winning precedence suppressed the effective limit")
		}
		return strings.Join(parts, "; ")
	}

	winners := e.WinningPolicies()
	switch len(winners) {
	case 0:
		parts = append(parts, "no winning limit match remained after precedence resolution")
	case 1:
		name := strings.TrimSpace(winners[0].Policy.Name)
		if name != "" {
			parts = append(parts, fmt.Sprintf("policy %q defines the effective limits", name))
		} else {
			parts = append(parts, "one winning limit match defines the effective limits")
		}
	default:
		parts = append(parts, fmt.Sprintf("%d winning %s matches merged; the tightest per-direction values became effective", len(winners), e.Selection.Kind))
	}

	return strings.Join(parts, "; ")
}

func broaderNonWinningKinds(winningKind TargetKind, matches []Match) []string {
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[TargetKind]struct{}, len(matches))
	kinds := make([]string, 0, len(matches))
	for _, kind := range TargetKindPrecedenceOrder() {
		if kind == winningKind {
			continue
		}
		for _, match := range matches {
			if match.Policy.Target.Kind != kind {
				continue
			}
			if _, ok := seen[kind]; ok {
				break
			}
			seen[kind] = struct{}{}
			kinds = append(kinds, string(kind))
			break
		}
	}

	return kinds
}

func countNonWinningKindMatches(kind TargetKind, matches []Match) int {
	count := 0
	for _, match := range matches {
		if match.Policy.Target.Kind == kind {
			count++
		}
	}

	return count
}

func joinKindsForReason(kinds []string) string {
	switch len(kinds) {
	case 0:
		return ""
	case 1:
		return kinds[0]
	case 2:
		return kinds[0] + " and " + kinds[1]
	default:
		return strings.Join(kinds[:len(kinds)-1], ", ") + ", and " + kinds[len(kinds)-1]
	}
}

func pluralizeRule(count int) string {
	if count == 1 {
		return "rule"
	}

	return "rules"
}

func mergeLimitPolicies(policies []Policy) LimitPolicy {
	var merged LimitPolicy

	for _, policy := range policies {
		merged.Upload = tighterRateLimit(merged.Upload, policy.Limits.Upload)
		merged.Download = tighterRateLimit(merged.Download, policy.Limits.Download)
	}

	return merged
}

func tighterRateLimit(current *RateLimit, candidate *RateLimit) *RateLimit {
	if candidate == nil {
		return current
	}
	if current == nil || candidate.BytesPerSecond < current.BytesPerSecond {
		copy := *candidate
		return &copy
	}

	return current
}
