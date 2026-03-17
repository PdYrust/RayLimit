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
	Connection string
	UUID       string
	IP         string
	Inbound    string
	Outbound   string
}

func (s limitTargetSelection) Validate() error {
	kind, value, count := s.selected()
	switch count {
	case 0:
		return errors.New("select one limit target with --connection, --uuid, --ip, --inbound, or --outbound")
	case 1:
	default:
		return errors.New("select exactly one limit target with --connection, --uuid, --ip, --inbound, or --outbound")
	}

	switch kind {
	case policy.TargetKindIP:
		if _, err := ipaddr.Normalize(value); err != nil {
			return fmt.Errorf("invalid IP address %q for --ip", value)
		}
	case policy.TargetKindConnection, policy.TargetKindUUID, policy.TargetKindInbound, policy.TargetKindOutbound:
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
	case policy.TargetKindConnection:
		session.ID = value
	case policy.TargetKindUUID:
		session.Policy.UUID = value
	case policy.TargetKindIP:
		session.Client.IP = value
	case policy.TargetKindInbound:
		session.Route.InboundTag = value
	case policy.TargetKindOutbound:
		session.Route.OutboundTag = value
	}
}

func (s limitTargetSelection) policyTarget(runtime discovery.SessionRuntime) (policy.Target, error) {
	target := policy.Target{Kind: s.Kind()}

	if target.Kind == policy.TargetKindConnection {
		target.Connection = &policy.ConnectionRef{
			SessionID: s.Value(),
			Runtime:   &runtime,
		}
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
		{kind: policy.TargetKindConnection, value: strings.TrimSpace(s.Connection)},
		{kind: policy.TargetKindUUID, value: strings.TrimSpace(s.UUID)},
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
			if normalized, err := ipaddr.Normalize(selection.value); err == nil {
				selection.value = normalized
			}
		}

		selectedKind = selection.kind
		selectedValue = selection.value
		count++
	}

	return selectedKind, selectedValue, count
}
