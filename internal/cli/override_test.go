package cli

import (
	"reflect"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/tc"
)

func TestSplitGlobalOverrides(t *testing.T) {
	overrides, remaining, err := splitGlobalOverrides([]string{
		"--xray-binary", "/opt/xray/xray-linux-amd64",
		"--container-cli=podman",
		"--tc-binary", "/sbin/tc",
		"discover", "--format", "json",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if overrides.xrayBinary != "/opt/xray/xray-linux-amd64" {
		t.Fatalf("unexpected xray binary override: %q", overrides.xrayBinary)
	}
	if overrides.containerCLI != "podman" {
		t.Fatalf("unexpected container CLI override: %q", overrides.containerCLI)
	}
	if overrides.tcBinary != "/sbin/tc" {
		t.Fatalf("unexpected tc binary override: %q", overrides.tcBinary)
	}
	if !reflect.DeepEqual(remaining, []string{"discover", "--format", "json"}) {
		t.Fatalf("unexpected remaining args: %#v", remaining)
	}
}

func TestSplitGlobalOverridesStopsAtSubcommand(t *testing.T) {
	overrides, remaining, err := splitGlobalOverrides([]string{"discover", "--container-cli", "podman"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if overrides != (cliOverrides{}) {
		t.Fatalf("expected no overrides before the subcommand, got %#v", overrides)
	}
	if !reflect.DeepEqual(remaining, []string{"discover", "--container-cli", "podman"}) {
		t.Fatalf("unexpected remaining args: %#v", remaining)
	}
}

func TestSplitGlobalOverridesRequiresValue(t *testing.T) {
	if _, _, err := splitGlobalOverrides([]string{"--xray-binary"}); err == nil {
		t.Fatal("expected an error when a global override flag is missing its value")
	}
}

func TestResolveOverridesEnvFallback(t *testing.T) {
	t.Setenv("RAYLIMIT_XRAY_BINARY", "/opt/xray/xray")
	t.Setenv("RAYLIMIT_CONTAINER_CLI", "nerdctl")
	t.Setenv("RAYLIMIT_TC_BINARY", "/usr/sbin/tc")

	resolved := resolveOverrides(cliOverrides{})
	if resolved.xrayBinary != "/opt/xray/xray" {
		t.Fatalf("expected env xray binary, got %q", resolved.xrayBinary)
	}
	if resolved.containerCLI != "nerdctl" {
		t.Fatalf("expected env container CLI, got %q", resolved.containerCLI)
	}
	if resolved.tcBinary != "/usr/sbin/tc" {
		t.Fatalf("expected env tc binary, got %q", resolved.tcBinary)
	}
}

func TestResolveOverridesFlagWinsOverEnv(t *testing.T) {
	t.Setenv("RAYLIMIT_XRAY_BINARY", "/env/xray")

	resolved := resolveOverrides(cliOverrides{xrayBinary: "/flag/xray"})
	if resolved.xrayBinary != "/flag/xray" {
		t.Fatalf("expected the flag value to win, got %q", resolved.xrayBinary)
	}
}

func TestNewAppWithOverridesWiresSessionProvider(t *testing.T) {
	app := newAppWithOverrides(cliOverrides{
		xrayBinary:   "/opt/xray/xray-linux-amd64",
		containerCLI: "podman",
	})

	provider, ok := app.sessionEvidenceProvider().(discovery.XraySessionEvidenceProvider)
	if !ok {
		t.Fatalf("expected a default XraySessionEvidenceProvider, got %T", app.sessionEvidenceProvider())
	}
	if provider.XrayBinaryOverride != "/opt/xray/xray-linux-amd64" {
		t.Fatalf("expected xray binary override to be wired, got %q", provider.XrayBinaryOverride)
	}
	if provider.ContainerCLI != "podman" {
		t.Fatalf("expected container CLI override to be wired, got %q", provider.ContainerCLI)
	}
}

func TestNewAppWithOverridesWiresPlannerTCBinary(t *testing.T) {
	app := newAppWithOverrides(cliOverrides{tcBinary: "/sbin/tc"})

	planner, ok := app.planner().(tc.Planner)
	if !ok {
		t.Fatalf("expected a default tc.Planner, got %T", app.planner())
	}
	if planner.Binary != "/sbin/tc" {
		t.Fatalf("expected tc binary override to be wired, got %q", planner.Binary)
	}
}

func TestSplitGlobalOverridesParsesNftBinary(t *testing.T) {
	overrides, remaining, err := splitGlobalOverrides([]string{
		"--nft-binary", "/usr/local/sbin/nft",
		"limit", "--pid", "4242",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if overrides.nftBinary != "/usr/local/sbin/nft" {
		t.Fatalf("unexpected nft binary override: %q", overrides.nftBinary)
	}
	if !reflect.DeepEqual(remaining, []string{"limit", "--pid", "4242"}) {
		t.Fatalf("unexpected remaining args: %#v", remaining)
	}
}

// Case 1: a --nft-binary flag value reaches the mark-attachment nft binary path
// via the constructed NftablesInspector.
func TestNewAppWithOverridesWiresNftablesInspectorBinary(t *testing.T) {
	app := newAppWithOverrides(cliOverrides{nftBinary: "/usr/local/sbin/nft"})

	inspector, ok := app.nftablesInspector().(tc.NftablesInspector)
	if !ok {
		t.Fatalf("expected a default tc.NftablesInspector, got %T", app.nftablesInspector())
	}
	if inspector.Binary != "/usr/local/sbin/nft" {
		t.Fatalf("expected nft binary override to be wired, got %q", inspector.Binary)
	}
}

// Case 2: RAYLIMIT_NFT_BINARY is honored when no flag is supplied.
func TestResolveOverridesNftBinaryEnvFallback(t *testing.T) {
	t.Setenv("RAYLIMIT_NFT_BINARY", "/usr/local/sbin/nft")

	resolved := resolveOverrides(cliOverrides{})
	if resolved.nftBinary != "/usr/local/sbin/nft" {
		t.Fatalf("expected env nft binary, got %q", resolved.nftBinary)
	}
}

// Case 3: the flag wins when both the flag and the env var are set.
func TestResolveOverridesNftBinaryFlagWinsOverEnv(t *testing.T) {
	t.Setenv("RAYLIMIT_NFT_BINARY", "/env/nft")

	resolved := resolveOverrides(cliOverrides{nftBinary: "/flag/nft"})
	if resolved.nftBinary != "/flag/nft" {
		t.Fatalf("expected the flag value to win, got %q", resolved.nftBinary)
	}
}

// Case 4: with neither flag nor env set, the inspector carries no override so
// the tc layer falls back to the default nft binary (backwards-compatible).
func TestNewAppWithoutNftOverrideUsesDefaultBinary(t *testing.T) {
	app := newAppWithOverrides(cliOverrides{})

	inspector, ok := app.nftablesInspector().(tc.NftablesInspector)
	if !ok {
		t.Fatalf("expected a default tc.NftablesInspector, got %T", app.nftablesInspector())
	}
	if inspector.Binary != "" {
		t.Fatalf("expected no nft binary override, got %q", inspector.Binary)
	}
}
