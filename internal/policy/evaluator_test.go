package policy

import (
	"strings"
	"testing"
)

func TestEvaluatorEvaluateNoMatches(t *testing.T) {
	evaluation, err := (Evaluator{}).Evaluate([]Policy{
		{
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "blocked",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected evaluation without matches to succeed, got %v", err)
	}

	if evaluation.HasMatch() {
		t.Fatalf("expected no matches, got %#v", evaluation)
	}
	if len(evaluation.WinningPolicies()) != 0 {
		t.Fatalf("expected no winning policies, got %#v", evaluation.WinningPolicies())
	}
	if evaluation.Excluded() {
		t.Fatalf("expected unmatched evaluation to remain non-excluded, got %#v", evaluation)
	}
	if evaluation.EffectiveLimits.HasAny() {
		t.Fatalf("expected no effective limits, got %#v", evaluation.EffectiveLimits)
	}
}

func TestEvaluatorEvaluateSupportedTargetKinds(t *testing.T) {
	cases := []struct {
		name   string
		target Target
		kind   TargetKind
	}{
		{
			name: "uuid",
			target: Target{
				Kind:  TargetKindUUID,
				Value: "F47AC10B-58CC-4372-A567-0E02B2C3D479",
			},
			kind: TargetKindUUID,
		},
		{
			name: "ip",
			target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			kind: TargetKindIP,
		},
		{
			name: "inbound",
			target: Target{
				Kind:  TargetKindInbound,
				Value: "api-in",
			},
			kind: TargetKindInbound,
		},
		{
			name: "outbound",
			target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			kind: TargetKindOutbound,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			evaluation, err := (Evaluator{}).Evaluate([]Policy{
				{
					Name:   tt.name + "-limit",
					Target: tt.target,
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 2048},
					},
				},
			}, testSession())
			if err != nil {
				t.Fatalf("expected evaluation to succeed, got %v", err)
			}

			if !evaluation.HasMatch() {
				t.Fatalf("expected %s policy to match, got %#v", tt.name, evaluation)
			}
			if evaluation.Selection.Kind != tt.kind {
				t.Fatalf("expected winning kind %q, got %q", tt.kind, evaluation.Selection.Kind)
			}
			winners := evaluation.WinningPolicies()
			if len(winners) != 1 || !winners[0].Winner {
				t.Fatalf("expected one winning policy, got %#v", winners)
			}
			if evaluation.EffectiveLimits.Download == nil || evaluation.EffectiveLimits.Download.BytesPerSecond != 2048 {
				t.Fatalf("unexpected effective limits: %#v", evaluation.EffectiveLimits)
			}
		})
	}
}

func TestEvaluatorEvaluateMultipleMatchingLimitsMergeEffectiveDirections(t *testing.T) {
	policies := []Policy{
		{
			Name: "uuid-upload",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "uuid-upload-tighter",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "uuid-download",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 8192},
			},
		},
	}

	evaluation, err := (Evaluator{}).Evaluate(policies, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if len(evaluation.Matches) != 3 {
		t.Fatalf("expected all uuid policies to match, got %#v", evaluation.Matches)
	}
	if len(evaluation.WinningPolicies()) != 3 {
		t.Fatalf("expected all same-precedence limit policies to win, got %#v", evaluation.WinningPolicies())
	}
	if evaluation.EffectiveLimits.Upload == nil || evaluation.EffectiveLimits.Upload.BytesPerSecond != 2048 {
		t.Fatalf("expected tightest upload limit to win, got %#v", evaluation.EffectiveLimits)
	}
	if evaluation.EffectiveLimits.Download == nil || evaluation.EffectiveLimits.Download.BytesPerSecond != 8192 {
		t.Fatalf("expected download limit to remain selected, got %#v", evaluation.EffectiveLimits)
	}
}

func TestEvaluatorEvaluatePrecedenceSelectsNarrowerPolicy(t *testing.T) {
	policies := []Policy{
		{
			Name: "outbound-limit",
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name: "ip-limit",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "uuid-limit",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
	}

	evaluation, err := (Evaluator{}).Evaluate(policies, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if len(evaluation.Matches) != 3 {
		t.Fatalf("expected three matches, got %#v", evaluation.Matches)
	}
	if evaluation.Selection.Kind != TargetKindUUID {
		t.Fatalf("expected uuid precedence to win, got %q", evaluation.Selection.Kind)
	}
	if evaluation.Selection.Precedence != TargetKindUUID.Precedence() {
		t.Fatalf("expected uuid precedence metadata, got %#v", evaluation.Selection)
	}
	winners := evaluation.WinningPolicies()
	if len(winners) != 1 || winners[0].Policy.Name != "uuid-limit" {
		t.Fatalf("unexpected winning policies: %#v", winners)
	}
	if len(evaluation.NonWinningPolicies()) != 2 {
		t.Fatalf("expected two non-winning policies, got %#v", evaluation.NonWinningPolicies())
	}
	if !strings.Contains(evaluation.EffectiveReason, "uuid precedence selected the effective rule set") ||
		!strings.Contains(evaluation.EffectiveReason, "over matching ip and outbound rules") {
		t.Fatalf("unexpected effective reason: %#v", evaluation)
	}
	if evaluation.EffectiveLimits.Download == nil || evaluation.EffectiveLimits.Download.BytesPerSecond != 4096 {
		t.Fatalf("unexpected effective limits: %#v", evaluation.EffectiveLimits)
	}
}

func TestEvaluatorEvaluateExcludeWinsAtSamePrecedence(t *testing.T) {
	policies := []Policy{
		{
			Name: "uuid-limit",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name:   "uuid-exclude",
			Effect: EffectExclude,
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
		},
	}

	evaluation, err := (Evaluator{}).Evaluate(policies, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if !evaluation.Excluded() {
		t.Fatalf("expected evaluation to be excluded, got %#v", evaluation)
	}
	if evaluation.EffectiveLimits.HasAny() {
		t.Fatalf("expected exclusion to suppress effective limits, got %#v", evaluation.EffectiveLimits)
	}
	winners := evaluation.WinningPolicies()
	if len(winners) != 1 || winners[0].Policy.Name != "uuid-exclude" {
		t.Fatalf("unexpected winning policies: %#v", winners)
	}
}

func TestEvaluatorEvaluateConnectionTargetWinsOverBroaderPolicies(t *testing.T) {
	policies := []Policy{
		{
			Name: "uuid-limit",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "connection-limit",
			Target: Target{
				Kind:       TargetKindConnection,
				Connection: testConnectionRef(),
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
	}

	evaluation, err := (Evaluator{}).Evaluate(policies, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if evaluation.Selection.Kind != TargetKindConnection {
		t.Fatalf("expected connection precedence to win, got %q", evaluation.Selection.Kind)
	}
	winners := evaluation.WinningPolicies()
	if len(winners) != 1 || winners[0].Policy.Name != "connection-limit" {
		t.Fatalf("unexpected winning policies: %#v", winners)
	}
	if len(evaluation.NonWinningPolicies()) != 1 || evaluation.NonWinningPolicies()[0].Policy.Name != "uuid-limit" {
		t.Fatalf("expected uuid limit to remain visible as non-winning, got %#v", evaluation.NonWinningPolicies())
	}
	if evaluation.EffectiveLimits.Upload == nil || evaluation.EffectiveLimits.Upload.BytesPerSecond != 1024 {
		t.Fatalf("unexpected effective limits: %#v", evaluation.EffectiveLimits)
	}
}

func TestEvaluatorEvaluateIPTargetWinsOverInboundAndOutboundPolicies(t *testing.T) {
	policies := []Policy{
		{
			Name: "outbound-limit",
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name: "inbound-limit",
			Target: Target{
				Kind:  TargetKindInbound,
				Value: "api-in",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "ip-limit",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
	}

	evaluation, err := (Evaluator{}).Evaluate(policies, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if evaluation.Selection.Kind != TargetKindIP {
		t.Fatalf("expected ip precedence to win, got %q", evaluation.Selection.Kind)
	}
	winners := evaluation.WinningPolicies()
	if len(winners) != 1 || winners[0].Policy.Name != "ip-limit" {
		t.Fatalf("unexpected winning policies: %#v", winners)
	}
	if len(evaluation.NonWinningPolicies()) != 2 {
		t.Fatalf("expected two non-winning policies, got %#v", evaluation.NonWinningPolicies())
	}
	if !strings.Contains(evaluation.EffectiveReason, "ip precedence selected the effective rule set") ||
		!strings.Contains(evaluation.EffectiveReason, "over matching inbound and outbound rules") {
		t.Fatalf("unexpected effective reason: %#v", evaluation)
	}
	if evaluation.EffectiveLimits.Download == nil || evaluation.EffectiveLimits.Download.BytesPerSecond != 4096 {
		t.Fatalf("unexpected effective limits: %#v", evaluation.EffectiveLimits)
	}
}

func TestEvaluatorEvaluateInboundTargetWinsOverOutboundPolicy(t *testing.T) {
	policies := []Policy{
		{
			Name: "outbound-limit",
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name: "inbound-limit",
			Target: Target{
				Kind:  TargetKindInbound,
				Value: "api-in",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 2048},
			},
		},
	}

	evaluation, err := (Evaluator{}).Evaluate(policies, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if evaluation.Selection.Kind != TargetKindInbound {
		t.Fatalf("expected inbound precedence to win, got %q", evaluation.Selection.Kind)
	}
	winners := evaluation.WinningPolicies()
	if len(winners) != 1 || winners[0].Policy.Name != "inbound-limit" {
		t.Fatalf("unexpected winning policies: %#v", winners)
	}
	if len(evaluation.NonWinningPolicies()) != 1 || evaluation.NonWinningPolicies()[0].Policy.Name != "outbound-limit" {
		t.Fatalf("unexpected non-winning policies: %#v", evaluation.NonWinningPolicies())
	}
	if !strings.Contains(evaluation.EffectiveReason, "inbound precedence selected the effective rule set") ||
		!strings.Contains(evaluation.EffectiveReason, "over matching outbound rules") {
		t.Fatalf("unexpected effective reason: %#v", evaluation)
	}
}

func TestEvaluatorEvaluateMixedKindCoexistenceCases(t *testing.T) {
	cases := []struct {
		name            string
		policies        []Policy
		winningKind     TargetKind
		winningName     string
		nonWinningNames []string
	}{
		{
			name: "ip_over_inbound",
			policies: []Policy{
				{
					Name: "inbound-limit",
					Target: Target{
						Kind:  TargetKindInbound,
						Value: "api-in",
					},
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 1024},
					},
				},
				{
					Name: "ip-limit",
					Target: Target{
						Kind:  TargetKindIP,
						Value: "203.0.113.10",
					},
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 2048},
					},
				},
			},
			winningKind:     TargetKindIP,
			winningName:     "ip-limit",
			nonWinningNames: []string{"inbound-limit"},
		},
		{
			name: "uuid_over_inbound",
			policies: []Policy{
				{
					Name: "inbound-limit",
					Target: Target{
						Kind:  TargetKindInbound,
						Value: "api-in",
					},
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 1024},
					},
				},
				{
					Name: "uuid-limit",
					Target: Target{
						Kind:  TargetKindUUID,
						Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
					},
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 2048},
					},
				},
			},
			winningKind:     TargetKindUUID,
			winningName:     "uuid-limit",
			nonWinningNames: []string{"inbound-limit"},
		},
		{
			name: "uuid_over_outbound",
			policies: []Policy{
				{
					Name: "outbound-limit",
					Target: Target{
						Kind:  TargetKindOutbound,
						Value: "direct",
					},
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 1024},
					},
				},
				{
					Name: "uuid-limit",
					Target: Target{
						Kind:  TargetKindUUID,
						Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
					},
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 2048},
					},
				},
			},
			winningKind:     TargetKindUUID,
			winningName:     "uuid-limit",
			nonWinningNames: []string{"outbound-limit"},
		},
		{
			name: "uuid_over_ip",
			policies: []Policy{
				{
					Name: "ip-limit",
					Target: Target{
						Kind:  TargetKindIP,
						Value: "203.0.113.10",
					},
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 1024},
					},
				},
				{
					Name: "uuid-limit",
					Target: Target{
						Kind:  TargetKindUUID,
						Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
					},
					Limits: LimitPolicy{
						Download: &RateLimit{BytesPerSecond: 2048},
					},
				},
			},
			winningKind:     TargetKindUUID,
			winningName:     "uuid-limit",
			nonWinningNames: []string{"ip-limit"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			evaluation, err := (Evaluator{}).Evaluate(tt.policies, testSession())
			if err != nil {
				t.Fatalf("expected evaluation to succeed, got %v", err)
			}

			if evaluation.Selection.Kind != tt.winningKind {
				t.Fatalf("expected winning kind %q, got %#v", tt.winningKind, evaluation)
			}
			winners := evaluation.WinningPolicies()
			if len(winners) != 1 || winners[0].Policy.Name != tt.winningName {
				t.Fatalf("unexpected winners: %#v", winners)
			}
			nonWinning := evaluation.NonWinningPolicies()
			if len(nonWinning) != len(tt.nonWinningNames) {
				t.Fatalf("unexpected non-winning policies: %#v", nonWinning)
			}
			for index, expected := range tt.nonWinningNames {
				if nonWinning[index].Policy.Name != expected {
					t.Fatalf("unexpected non-winning policy order: %#v", nonWinning)
				}
			}
		})
	}
}

func TestEvaluatorEvaluateExcludeKeepsSameAndBroaderNonWinningMatchesVisible(t *testing.T) {
	policies := []Policy{
		{
			Name: "outbound-limit",
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name: "uuid-limit",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "ip-limit",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 3072},
			},
		},
		{
			Name:   "uuid-exclude",
			Effect: EffectExclude,
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
		},
	}

	evaluation, err := (Evaluator{}).Evaluate(policies, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if !evaluation.Excluded() {
		t.Fatalf("expected winning exclude evaluation, got %#v", evaluation)
	}
	winners := evaluation.WinningPolicies()
	if len(winners) != 1 || winners[0].Policy.Name != "uuid-exclude" {
		t.Fatalf("unexpected winning policies: %#v", winners)
	}
	if len(evaluation.NonWinningPolicies()) != 3 {
		t.Fatalf("expected three non-winning policies, got %#v", evaluation.NonWinningPolicies())
	}
	if !strings.Contains(evaluation.EffectiveReason, "uuid precedence selected the effective rule set over matching ip and outbound rules") ||
		!strings.Contains(evaluation.EffectiveReason, "exclude rules at the winning precedence suppressed 1 matching uuid limit rule") {
		t.Fatalf("unexpected effective reason: %#v", evaluation)
	}
}

func TestEvaluatorEvaluateSamePrecedenceWinningRulesMergeAndExplainEffectiveLimit(t *testing.T) {
	policies := []Policy{
		{
			Name: "uuid-upload",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "uuid-download",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 8192},
			},
		},
		{
			Name: "uuid-upload-tightest",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 2048},
			},
		},
	}

	evaluation, err := (Evaluator{}).Evaluate(policies, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if !evaluation.HasCoexistence() {
		t.Fatalf("expected same-precedence winners to count as coexistence, got %#v", evaluation)
	}
	if len(evaluation.WinningPolicies()) != 3 {
		t.Fatalf("expected three winning uuid rules, got %#v", evaluation.WinningPolicies())
	}
	if len(evaluation.NonWinningPolicies()) != 0 {
		t.Fatalf("expected no non-winning rules, got %#v", evaluation.NonWinningPolicies())
	}
	if !strings.Contains(evaluation.EffectiveReason, "3 winning uuid matches merged") {
		t.Fatalf("unexpected effective reason: %#v", evaluation)
	}
}

func TestEvaluatorEvaluateRejectsInvalidPolicyDefinitions(t *testing.T) {
	_, err := (Evaluator{}).Evaluate([]Policy{
		{
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Target: Target{
				Kind: TargetKindConnection,
				Connection: &ConnectionRef{
					SessionID: "conn-1",
				},
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 2048},
			},
		},
	}, testSession())
	if err == nil {
		t.Fatal("expected invalid policy definitions to fail evaluation")
	}
}
