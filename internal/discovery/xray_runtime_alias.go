package discovery

import "strings"

// xrayRuntimeAliases is the extensible allowlist of known Xray-family binary
// name prefixes, compared case-insensitively against a normalized basename.
//
// A match is a prefix match, which naturally handles OS/arch-suffixed release
// binaries (xray-linux-amd64, xray-darwin-arm64, xray-windows-4.0-amd64.exe),
// fork binaries (sanaei-linux-amd64), and the 15-character truncation that
// Linux applies to a process /proc/<pid>/comm field (xray-linux-amd6).
//
// To support an additional fork, add its lowercase basename prefix here.
// "xray-core" and "sanaei-core" are listed explicitly for documentation even
// though the shorter "xray" / "sanaei" prefixes already cover them.
var xrayRuntimeAliases = []string{"xray", "xray-core", "sanaei", "sanaei-core"}

// xrayImageMarkers is the extensible set of case-insensitive substrings that
// make a Docker image repository base suggestive of an Xray-family runtime
// (for example a fork image named "my-xray-fork"). A substring match is weaker
// evidence than an alias prefix match and yields medium detection confidence.
var xrayImageMarkers = []string{"xray", "sanaei"}

// normalizeBinaryBasename reduces a path or name to a lowercase basename with a
// trailing ".exe" suffix removed, suitable for alias comparison.
func normalizeBinaryBasename(name string) string {
	base := strings.ToLower(strings.TrimSpace(basenameOrEmpty(strings.TrimSpace(name))))
	return strings.TrimSuffix(base, ".exe")
}

// matchesXrayFamilyBinary reports whether a binary path or name belongs to the
// Xray family by prefix-matching its normalized basename against
// xrayRuntimeAliases. The comparison is case-insensitive and ignores a ".exe"
// suffix.
func matchesXrayFamilyBinary(name string) bool {
	base := normalizeBinaryBasename(name)
	if base == "" {
		return false
	}

	for _, alias := range xrayRuntimeAliases {
		if strings.HasPrefix(base, alias) {
			return true
		}
	}

	return false
}

// sanaeiRuntimeAliases is the subset of xrayRuntimeAliases that identifies the
// Sanaei Xray fork specifically, as opposed to vanilla xray/xray-core. It is
// kept here alongside the family allowlist so fork-name knowledge lives in one
// place.
var sanaeiRuntimeAliases = []string{"sanaei", "sanaei-core"}

// matchesSanaeiForkBinary reports whether a binary path or name belongs to the
// Sanaei Xray fork by prefix-matching its normalized basename against
// sanaeiRuntimeAliases. Vanilla xray/xray-core binaries do NOT match, and an
// empty name does not match. The comparison reuses the same normalization as
// matchesXrayFamilyBinary (case-insensitive, ".exe" stripped, basename only).
func matchesSanaeiForkBinary(name string) bool {
	base := normalizeBinaryBasename(name)
	if base == "" {
		return false
	}

	for _, alias := range sanaeiRuntimeAliases {
		if strings.HasPrefix(base, alias) {
			return true
		}
	}

	return false
}

// containsXrayFamilyMarker reports whether a name contains a known Xray-family
// substring marker (case-insensitive). It is intentionally permissive and is
// used only for weak, image-name-based evidence.
func containsXrayFamilyMarker(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}

	for _, marker := range xrayImageMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}
