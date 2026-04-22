package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/ipaddr"
	"github.com/PdYrust/RayLimit/internal/policy"
)

type limitTargetSelection struct {
	IP       string
	Inbound  string
	Outbound string

	IPAggregation policy.IPAggregationMode
}

func (s limitTargetSelection) Validate() error {
	kind, value, count := s.selected()
	aggregation := strings.TrimSpace(string(s.IPAggregation))
	switch count {
	case 0:
		return errors.New("select one limit target with --ip, --inbound, or --outbound")
	case 1:
	default:
		return errors.New("select exactly one limit target with --ip, --inbound, or --outbound")
	}
	if aggregation != "" {
		if !s.IPAggregation.Valid() {
			return fmt.Errorf("invalid --ip-aggregation value %q", s.IPAggregation)
		}
		if kind != policy.TargetKindIP || !strings.EqualFold(value, "all") {
			return errors.New("--ip-aggregation is only valid with --ip all")
		}
	}

	switch kind {
	case policy.TargetKindIP:
		if strings.EqualFold(value, "all") {
			return nil
		}
		if _, err := ipaddr.Normalize(value); err != nil {
			return fmt.Errorf("invalid IP address %q for --ip", value)
		}
	case policy.TargetKindInbound, policy.TargetKindOutbound:
	default:
		return fmt.Errorf("unsupported target kind %q", kind)
	}

	return nil
}

func (s limitTargetSelection) Kind() policy.TargetKind {
	kind, _, _ := s.selected()
	return kind
}

func (s limitTargetSelection) Value() string {
	_, value, _ := s.selected()
	return value
}

func (s limitTargetSelection) apply(session *discovery.Session) {
	value := s.Value()

	switch s.Kind() {
	case policy.TargetKindIP:
		if !strings.EqualFold(value, "all") {
			session.Client.IP = value
		}
	case policy.TargetKindInbound:
		session.Route.InboundTag = value
	case policy.TargetKindOutbound:
		session.Route.OutboundTag = value
	}
}

func (s limitTargetSelection) NormalizedIPAggregation() policy.IPAggregationMode {
	if s.Kind() != policy.TargetKindIP || !strings.EqualFold(s.Value(), "all") {
		return ""
	}

	if strings.TrimSpace(string(s.IPAggregation)) == "" {
		return policy.IPAggregationModeShared
	}

	return s.IPAggregation
}

func (s limitTargetSelection) policyTarget() (policy.Target, error) {
	target := policy.Target{Kind: s.Kind()}
	if target.Kind == policy.TargetKindIP && strings.EqualFold(s.Value(), "all") {
		target.All = true
		target.IPAggregation = s.NormalizedIPAggregation()
	} else {
		target.Value = s.Value()
	}

	if err := target.Validate(); err != nil {
		return policy.Target{}, err
	}

	return target, nil
}

func (s limitTargetSelection) selected() (policy.TargetKind, string, int) {
	selections := []struct {
		kind  policy.TargetKind
		value string
	}{
		{kind: policy.TargetKindIP, value: strings.TrimSpace(s.IP)},
		{kind: policy.TargetKindInbound, value: strings.TrimSpace(s.Inbound)},
		{kind: policy.TargetKindOutbound, value: strings.TrimSpace(s.Outbound)},
	}

	var selectedKind policy.TargetKind
	var selectedValue string
	count := 0

	for _, selection := range selections {
		if selection.value == "" {
			continue
		}
		if selection.kind == policy.TargetKindIP {
			if strings.EqualFold(selection.value, "all") {
				selection.value = "all"
			} else if normalized, err := ipaddr.Normalize(selection.value); err == nil {
				selection.value = normalized
			}
		}

		selectedKind = selection.kind
		selectedValue = selection.value
		count++
	}

	return selectedKind, selectedValue, count
}
