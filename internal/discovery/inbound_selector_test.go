package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInboundMarkSelectorDeriverDerivesConcreteTCPSelector(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 8443
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewInboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "api-in")
	if err != nil {
		t.Fatalf("expected inbound selector derivation to succeed, got %v", err)
	}

	if result.Selector == nil {
		t.Fatalf("expected concrete selector, got %#v", result)
	}
	if result.Selector.Network != "tcp" || result.Selector.ListenAddress != "127.0.0.1" || result.Selector.Port != 8443 {
		t.Fatalf("unexpected selector payload %#v", result.Selector)
	}
	if got := strings.Join(result.Selector.Expression, " "); got != "ip daddr 127.0.0.1 tcp dport 8443" {
		t.Fatalf("unexpected selector expression %q", got)
	}
}

func TestInboundMarkSelectorDeriverDefaultsMissingNetworkToTCP(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "::1",
      "port": 9443,
      "streamSettings": {}
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewInboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "api-in")
	if err != nil {
		t.Fatalf("expected inbound selector derivation to succeed, got %v", err)
	}

	if result.Selector == nil {
		t.Fatalf("expected concrete selector, got %#v", result)
	}
	if got := strings.Join(result.Selector.Expression, " "); got != "ip6 daddr ::1 tcp dport 9443" {
		t.Fatalf("unexpected selector expression %q", got)
	}
}

func TestInboundMarkSelectorDeriverRejectsWildcardListener(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "0.0.0.0",
      "port": 8443
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewInboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "api-in")
	if err != nil {
		t.Fatalf("expected inbound selector derivation to succeed, got %v", err)
	}

	if result.Selector != nil {
		t.Fatalf("expected wildcard listener to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Reason, "wildcard-bound") {
		t.Fatalf("expected wildcard-bound reason, got %#v", result)
	}
}

func TestInboundMarkSelectorDeriverRejectsNonTCPTransport(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 8443,
      "streamSettings": {
        "network": "ws"
      }
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewInboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "api-in")
	if err != nil {
		t.Fatalf("expected inbound selector derivation to succeed, got %v", err)
	}

	if result.Selector != nil {
		t.Fatalf("expected non-tcp listener to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Reason, "requires tcp") {
		t.Fatalf("expected non-tcp reason, got %#v", result)
	}
}

func TestInboundMarkSelectorDeriverRejectsAmbiguousConcreteListeners(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 8443
    },
    {
      "tag": "api-in",
      "listen": "::1",
      "port": 8443
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewInboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "api-in")
	if err != nil {
		t.Fatalf("expected inbound selector derivation to succeed, got %v", err)
	}

	if result.Selector != nil {
		t.Fatalf("expected ambiguous listeners to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Reason, "ambiguous") {
		t.Fatalf("expected ambiguous reason, got %#v", result)
	}
}
