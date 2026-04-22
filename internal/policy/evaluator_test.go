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

	if evaluation.HasMatch() || evaluation.Excluded() || evaluation.EffectiveLimits.HasAny() {
		t.Fatalf("expected unmatched evaluation to remain empty, got %#v", evaluation)
	}
}

func TestEvaluatorEvaluateSupportedTargetKinds(t *testing.T) {
	cases := []struct {
		name   string
		target Target
		kind   TargetKind
	}{
		{
			name: "ip",
			target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			kind: TargetKindIP,
		},
		{
			name: "ip-all",
			target: Target{
				Kind: TargetKindIP,
				All:  true,
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
			if evaluation.EffectiveLimits.Download == nil || evaluation.EffectiveLimits.Download.BytesPerSecond != 2048 {
				t.Fatalf("unexpected effective limits: %#v", evaluation.EffectiveLimits)
			}
		})
	}
}

func TestEvaluatorEvaluateMultipleMatchingLimitsMergeEffectiveDirections(t *testing.T) {
	evaluation, err := (Evaluator{}).Evaluate([]Policy{
		{
			Name: "ip-upload",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "ip-upload-tighter",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "ip-download",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 8192},
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
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
	evaluation, err := (Evaluator{}).Evaluate([]Policy{
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
	}, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if evaluation.Selection.Kind != TargetKindIP {
		t.Fatalf("expected ip precedence to win, got %q", evaluation.Selection.Kind)
	}
	if !strings.Contains(evaluation.EffectiveReason, "ip precedence selected the effective rule set") ||
		!strings.Contains(evaluation.EffectiveReason, "over matching inbound and outbound rules") {
		t.Fatalf("unexpected effective reason: %#v", evaluation)
	}
}

func TestEvaluatorEvaluateExcludeWinsAtSamePrecedence(t *testing.T) {
	evaluation, err := (Evaluator{}).Evaluate([]Policy{
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
		{
			Name:   "ip-exclude",
			Effect: EffectExclude,
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if !evaluation.Excluded() {
		t.Fatalf("expected evaluation to be excluded, got %#v", evaluation)
	}
	winners := evaluation.WinningPolicies()
	if len(winners) != 1 || winners[0].Policy.Name != "ip-exclude" {
		t.Fatalf("unexpected winning policies: %#v", winners)
	}
}

func TestEvaluatorEvaluateSpecificIPOverrideBeatsBaselineAll(t *testing.T) {
	evaluation, err := (Evaluator{}).Evaluate([]Policy{
		{
			Name: "ip-all-limit",
			Target: Target{
				Kind: TargetKindIP,
				All:  true,
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 8192},
			},
		},
		{
			Name: "ip-override",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if evaluation.Selection.Kind != TargetKindIP || evaluation.Selection.Target.All {
		t.Fatalf("expected specific ip override to win, got %#v", evaluation)
	}
	if evaluation.EffectiveLimits.Download == nil || evaluation.EffectiveLimits.Download.BytesPerSecond != 4096 {
		t.Fatalf("expected specific ip limit to become effective, got %#v", evaluation.EffectiveLimits)
	}
	if !strings.Contains(evaluation.EffectiveReason, "shared --ip all baseline") {
		t.Fatalf("expected effective reason to mention the baseline, got %#v", evaluation)
	}
	if len(evaluation.NonWinningPolicies()) != 1 || evaluation.NonWinningPolicies()[0].Policy.Target.NormalizedIPAggregation() != IPAggregationModeShared {
		t.Fatalf("expected matching ip all baseline to normalize to shared aggregation, got %#v", evaluation.NonWinningPolicies())
	}
}

func TestEvaluatorEvaluateSpecificIPUnlimitedBeatsBaselineAll(t *testing.T) {
	evaluation, err := (Evaluator{}).Evaluate([]Policy{
		{
			Name: "ip-all-limit",
			Target: Target{
				Kind: TargetKindIP,
				All:  true,
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 8192},
			},
		},
		{
			Name:   "ip-unlimited",
			Effect: EffectExclude,
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if !evaluation.Excluded() || evaluation.Selection.Target.All {
		t.Fatalf("expected specific ip unlimited exception to win, got %#v", evaluation)
	}
	if len(evaluation.WinningPolicies()) != 1 || evaluation.WinningPolicies()[0].Policy.Name != "ip-unlimited" {
		t.Fatalf("unexpected winning unlimited evaluation: %#v", evaluation)
	}
}

func TestEvaluatorEvaluateMultipleSpecificIPOverridesMergeAboveBaselineAll(t *testing.T) {
	evaluation, err := (Evaluator{}).Evaluate([]Policy{
		{
			Name: "ip-all-limit",
			Target: Target{
				Kind: TargetKindIP,
				All:  true,
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 8192},
			},
		},
		{
			Name: "ip-override-download",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "ip-override-upload",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "ip-override-download-tighter",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if evaluation.Selection.Target.All {
		t.Fatalf("expected specific ip override set to win, got %#v", evaluation)
	}
	if len(evaluation.WinningPolicies()) != 3 {
		t.Fatalf("expected all specific ip overrides to remain winning policies, got %#v", evaluation.WinningPolicies())
	}
	if evaluation.EffectiveLimits.Upload == nil || evaluation.EffectiveLimits.Upload.BytesPerSecond != 2048 {
		t.Fatalf("expected specific upload override to remain effective, got %#v", evaluation.EffectiveLimits)
	}
	if evaluation.EffectiveLimits.Download == nil || evaluation.EffectiveLimits.Download.BytesPerSecond != 1024 {
		t.Fatalf("expected tightest specific download override to remain effective, got %#v", evaluation.EffectiveLimits)
	}
}

func TestEvaluatorEvaluateCanonicalEquivalentSpecificIPOverrideBeatsBaselineAll(t *testing.T) {
	evaluation, err := (Evaluator{}).Evaluate([]Policy{
		{
			Name: "ip-all-limit",
			Target: Target{
				Kind: TargetKindIP,
				All:  true,
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 8192},
			},
		},
		{
			Name: "ip-override",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "::ffff:203.0.113.10",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 4096},
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected evaluation to succeed, got %v", err)
	}

	if evaluation.Selection.Target.All {
		t.Fatalf("expected canonical-equivalent specific ip override to win, got %#v", evaluation)
	}
	if evaluation.EffectiveLimits.Upload == nil || evaluation.EffectiveLimits.Upload.BytesPerSecond != 4096 {
		t.Fatalf("expected canonical-equivalent specific override to become effective, got %#v", evaluation.EffectiveLimits)
	}
}
