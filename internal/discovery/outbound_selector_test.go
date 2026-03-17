package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutboundMarkSelectorDeriverDerivesConcreteSocketMarkSelector(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "outbounds": [
    {
      "tag": "proxy-out",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": {
          "mark": 513
        }
      }
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewOutboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "proxy-out")
	if err != nil {
		t.Fatalf("expected outbound selector derivation to succeed, got %v", err)
	}

	if result.Selector == nil {
		t.Fatalf("expected concrete selector, got %#v", result)
	}
	if result.Selector.SocketMark != 513 {
		t.Fatalf("unexpected socket mark %#v", result.Selector)
	}
	if got := strings.Join(result.Selector.Expression, " "); got != "meta mark 0x201" {
		t.Fatalf("unexpected selector expression %q", got)
	}
}

func TestOutboundMarkSelectorDeriverRejectsMissingSocketMark(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "outbounds": [
    {
      "tag": "proxy-out",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": {
          "mark": 0
        }
      }
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewOutboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "proxy-out")
	if err != nil {
		t.Fatalf("expected outbound selector derivation to succeed, got %v", err)
	}

	if result.Selector != nil {
		t.Fatalf("expected missing mark to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Reason, "streamSettings.sockopt.mark is missing or zero") {
		t.Fatalf("expected missing-mark reason, got %#v", result)
	}
}

func TestOutboundMarkSelectorDeriverRejectsDialerProxyIndirection(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "outbounds": [
    {
      "tag": "proxy-out",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": {
          "mark": 513,
          "dialerProxy": "transport-out"
        }
      }
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewOutboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "proxy-out")
	if err != nil {
		t.Fatalf("expected outbound selector derivation to succeed, got %v", err)
	}

	if result.Selector != nil {
		t.Fatalf("expected dialer proxy to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Reason, "dialerProxy") {
		t.Fatalf("expected dialer-proxy reason, got %#v", result)
	}
}

func TestOutboundMarkSelectorDeriverRejectsSharedSocketMark(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "outbounds": [
    {
      "tag": "proxy-out",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": {
          "mark": 513
        }
      }
    },
    {
      "tag": "backup-out",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": {
          "mark": 513
        }
      }
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewOutboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "proxy-out")
	if err != nil {
		t.Fatalf("expected outbound selector derivation to succeed, got %v", err)
	}

	if result.Selector != nil {
		t.Fatalf("expected shared mark to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Reason, "is shared across readable outbound config") {
		t.Fatalf("expected shared-mark reason, got %#v", result)
	}
}

func TestOutboundMarkSelectorDeriverRejectsAmbiguousConcreteMarks(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "outbounds": [
    {
      "tag": "proxy-out",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": {
          "mark": 513
        }
      }
    },
    {
      "tag": "proxy-out",
      "protocol": "freedom",
      "streamSettings": {
        "sockopt": {
          "mark": 514
        }
      }
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := NewOutboundMarkSelectorDeriver().Derive(context.Background(), RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}, "proxy-out")
	if err != nil {
		t.Fatalf("expected outbound selector derivation to succeed, got %v", err)
	}

	if result.Selector != nil {
		t.Fatalf("expected ambiguous marks to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Reason, "ambiguous") {
		t.Fatalf("expected ambiguous reason, got %#v", result)
	}
}
