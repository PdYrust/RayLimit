package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// InboundMarkSelector captures one concrete nftables selector that can mark
// traffic for a specific Xray inbound listener.
type InboundMarkSelector struct {
	Tag           string
	Network       string
	ListenAddress string
	Port          int
	Expression    []string
	Description   string
}

func (s InboundMarkSelector) Validate() error {
	if strings.TrimSpace(s.Tag) == "" {
		return errors.New("inbound selector tag is required")
	}
	if strings.TrimSpace(s.Network) == "" {
		return errors.New("inbound selector network is required")
	}
	if strings.TrimSpace(s.ListenAddress) == "" {
		return errors.New("inbound selector listen address is required")
	}
	if s.Port <= 0 || s.Port > 65535 {
		return errors.New("inbound selector port must be between 1 and 65535")
	}
	if len(s.Expression) == 0 {
		return errors.New("inbound selector expression is required")
	}
	for index, token := range s.Expression {
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf("inbound selector expression token at index %d is blank", index)
		}
	}

	return nil
}

func (s InboundMarkSelector) key() string {
	return strings.Join([]string{
		strings.TrimSpace(s.Network),
		strings.TrimSpace(s.ListenAddress),
		strconv.Itoa(s.Port),
		strings.Join(s.Expression, " "),
	}, "|")
}

// InboundMarkSelectorResult reports whether a concrete selector could be
// derived conservatively from readable runtime-local Xray configuration.
type InboundMarkSelectorResult struct {
	Selector *InboundMarkSelector
	Reason   string
}

// InboundMarkSelectorDeriver reads runtime-local Xray config hints and derives
// one concrete inbound listener selector when that mapping is trustworthy.
type InboundMarkSelectorDeriver struct {
	readFile fileReadFunc
	readDir  dirReadFunc
	statPath pathStatFunc
}

type inboundMarkSelectorState struct {
	sawReadableConfig bool
	foundMatchingTag  bool
	permissionDenied  []string
	missingPaths      []string
	incompletePaths   []string
	candidates        []InboundMarkSelector
	matchIssues       []string
}

// NewInboundMarkSelectorDeriver returns the default selector deriver.
func NewInboundMarkSelectorDeriver() InboundMarkSelectorDeriver {
	return InboundMarkSelectorDeriver{
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statPath: os.Stat,
	}
}

// Derive returns one concrete inbound selector when readable configuration
// proves an unambiguous TCP listener with a concrete local address.
func (d InboundMarkSelectorDeriver) Derive(ctx context.Context, target RuntimeTarget, inboundTag string) (InboundMarkSelectorResult, error) {
	d = d.withDefaults()

	tag := strings.TrimSpace(inboundTag)
	if tag == "" {
		return InboundMarkSelectorResult{}, errors.New("inbound tag is required")
	}
	if err := ctx.Err(); err != nil {
		return InboundMarkSelectorResult{}, err
	}

	configPaths := inspectionConfigPaths(target)
	if len(configPaths) == 0 {
		return InboundMarkSelectorResult{
			Reason: fmt.Sprintf("concrete inbound attachment requires readable Xray configuration hints; no config path hint is available for inbound tag %q", tag),
		}, nil
	}

	state := inboundMarkSelectorState{}
	for _, configPath := range uniqueConfigPaths(configPaths) {
		if err := ctx.Err(); err != nil {
			return InboundMarkSelectorResult{}, err
		}
		if err := d.inspectPath(ctx, configPath, tag, &state); err != nil {
			return InboundMarkSelectorResult{}, err
		}
	}

	return buildInboundMarkSelectorResult(tag, state), nil
}

func (d InboundMarkSelectorDeriver) withDefaults() InboundMarkSelectorDeriver {
	if d.readFile == nil {
		d.readFile = os.ReadFile
	}
	if d.readDir == nil {
		d.readDir = os.ReadDir
	}
	if d.statPath == nil {
		d.statPath = os.Stat
	}

	return d
}

func (d InboundMarkSelectorDeriver) inspectPath(ctx context.Context, path string, inboundTag string, state *inboundMarkSelectorState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	info, err := d.statPath(path)
	if err != nil {
		recordInboundSelectorPathIssue(state, path, err)
		return nil
	}
	if info.IsDir() {
		return d.inspectDir(ctx, path, inboundTag, state)
	}

	return d.inspectFile(ctx, path, inboundTag, state)
}

func (d InboundMarkSelectorDeriver) inspectDir(ctx context.Context, dirPath string, inboundTag string, state *inboundMarkSelectorState) error {
	entries, err := d.readDir(dirPath)
	if err != nil {
		recordInboundSelectorPathIssue(state, dirPath, err)
		return nil
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		names = append(names, entry.Name())
	}
	if len(names) == 0 {
		state.incompletePaths = appendUniqueString(state.incompletePaths, dirPath)
		return nil
	}

	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := d.inspectFile(ctx, filepath.Join(dirPath, name), inboundTag, state); err != nil {
			return err
		}
	}

	return nil
}

func (d InboundMarkSelectorDeriver) inspectFile(ctx context.Context, filePath string, inboundTag string, state *inboundMarkSelectorState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := d.readFile(filePath)
	if err != nil {
		recordInboundSelectorPathIssue(state, filePath, err)
		return nil
	}

	var document xrayConfigDocument
	if err := json.Unmarshal(data, &document); err != nil {
		state.incompletePaths = appendUniqueString(state.incompletePaths, filePath)
		return nil
	}
	state.sawReadableConfig = true

	for _, inbound := range document.Inbounds {
		if strings.TrimSpace(inbound.Tag) != inboundTag {
			continue
		}

		state.foundMatchingTag = true
		candidate, reason, ok := inboundMarkSelectorCandidate(inbound)
		if !ok {
			if reason != "" {
				state.matchIssues = appendUniqueString(state.matchIssues, fmt.Sprintf("%s: %s", filePath, reason))
			}
			continue
		}
		state.candidates = appendUniqueInboundMarkSelector(state.candidates, candidate)
	}

	return nil
}

func buildInboundMarkSelectorResult(inboundTag string, state inboundMarkSelectorState) InboundMarkSelectorResult {
	switch len(state.candidates) {
	case 1:
		selector := state.candidates[0]
		return InboundMarkSelectorResult{Selector: &selector}
	case 0:
	default:
		listeners := make([]string, 0, len(state.candidates))
		for _, candidate := range state.candidates {
			listeners = append(listeners, fmt.Sprintf("%s/%s:%d", candidate.Network, candidate.ListenAddress, candidate.Port))
		}
		sort.Strings(listeners)
		return InboundMarkSelectorResult{
			Reason: fmt.Sprintf(
				"concrete inbound attachment for tag %q is ambiguous because readable Xray config hints expose multiple concrete TCP listeners: %s",
				inboundTag,
				strings.Join(listeners, ", "),
			),
		}
	}

	if len(state.permissionDenied) != 0 {
		return InboundMarkSelectorResult{
			Reason: fmt.Sprintf(
				"concrete inbound attachment for tag %q requires readable Xray config hints, but access was denied for %s",
				inboundTag,
				summarizeAPICapabilityPaths(state.permissionDenied),
			),
		}
	}
	if len(state.matchIssues) != 0 {
		issues := append([]string(nil), state.matchIssues...)
		sort.Strings(issues)
		return InboundMarkSelectorResult{
			Reason: fmt.Sprintf("concrete inbound attachment for tag %q is unavailable: %s", inboundTag, issues[0]),
		}
	}
	if state.foundMatchingTag {
		return InboundMarkSelectorResult{
			Reason: fmt.Sprintf("concrete inbound attachment for tag %q could not be derived from readable Xray config hints", inboundTag),
		}
	}
	if state.sawReadableConfig {
		return InboundMarkSelectorResult{
			Reason: fmt.Sprintf("no inbound tagged %q was found in readable Xray config hints", inboundTag),
		}
	}
	if len(state.missingPaths) != 0 {
		return InboundMarkSelectorResult{
			Reason: fmt.Sprintf(
				"concrete inbound attachment for tag %q requires readable Xray config hints, but config paths were missing: %s",
				inboundTag,
				summarizeAPICapabilityPaths(state.missingPaths),
			),
		}
	}
	if len(state.incompletePaths) != 0 {
		return InboundMarkSelectorResult{
			Reason: fmt.Sprintf(
				"concrete inbound attachment for tag %q requires readable Xray config hints, but config parsing was incomplete for %s",
				inboundTag,
				summarizeAPICapabilityPaths(state.incompletePaths),
			),
		}
	}

	return InboundMarkSelectorResult{
		Reason: fmt.Sprintf("concrete inbound attachment for tag %q requires readable Xray config hints", inboundTag),
	}
}

func inboundMarkSelectorCandidate(inbound xrayInboundEntry) (InboundMarkSelector, string, bool) {
	network := xrayInboundTransportNetwork(inbound)
	if network != "tcp" {
		return InboundMarkSelector{}, fmt.Sprintf("transport network %q is not supported; concrete inbound attachment currently requires tcp", network), false
	}
	if inbound.Port <= 0 || inbound.Port > 65535 {
		return InboundMarkSelector{}, "listener port is missing or invalid", false
	}

	addr, reason, ok := parseConcreteInboundListenAddress(inbound.Listen)
	if !ok {
		return InboundMarkSelector{}, reason, false
	}

	expression := []string{"tcp", "dport", strconv.Itoa(inbound.Port)}
	if addr.Is4() {
		expression = append([]string{"ip", "daddr", addr.String()}, expression...)
	} else {
		expression = append([]string{"ip6", "daddr", addr.String()}, expression...)
	}

	candidate := InboundMarkSelector{
		Tag:           strings.TrimSpace(inbound.Tag),
		Network:       network,
		ListenAddress: addr.String(),
		Port:          inbound.Port,
		Expression:    expression,
		Description: fmt.Sprintf(
			"tcp listener %s:%d for inbound tag %q",
			addr.String(),
			inbound.Port,
			strings.TrimSpace(inbound.Tag),
		),
	}
	if err := candidate.Validate(); err != nil {
		return InboundMarkSelector{}, err.Error(), false
	}

	return candidate, "", true
}

func xrayInboundTransportNetwork(inbound xrayInboundEntry) string {
	if inbound.StreamSettings == nil {
		return "tcp"
	}

	network := strings.ToLower(strings.TrimSpace(inbound.StreamSettings.Network))
	if network == "" {
		return "tcp"
	}

	return network
}

func parseConcreteInboundListenAddress(value string) (netip.Addr, string, bool) {
	listen := strings.TrimSpace(value)
	if listen == "" {
		return netip.Addr{}, "listener address is unspecified; concrete inbound attachment currently requires one concrete local ip address", false
	}
	if strings.HasPrefix(listen, "unix://") || strings.HasPrefix(listen, "/") {
		return netip.Addr{}, "unix listener paths are not supported for concrete inbound attachment", false
	}

	if strings.HasPrefix(listen, "[") && strings.HasSuffix(listen, "]") {
		listen = strings.TrimPrefix(strings.TrimSuffix(listen, "]"), "[")
	}

	addr, err := netip.ParseAddr(listen)
	if err != nil {
		return netip.Addr{}, fmt.Sprintf("listener address %q is not a concrete ip address", value), false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}, fmt.Sprintf("listener address %q is wildcard-bound; concrete inbound attachment currently requires one concrete local ip address", value), false
	}

	return addr, "", true
}

func appendUniqueInboundMarkSelector(values []InboundMarkSelector, selector InboundMarkSelector) []InboundMarkSelector {
	key := selector.key()
	for _, existing := range values {
		if existing.key() == key {
			return values
		}
	}

	return append(values, selector)
}

func recordInboundSelectorPathIssue(state *inboundMarkSelectorState, path string, err error) {
	switch {
	case errors.Is(err, os.ErrPermission), os.IsPermission(err):
		state.permissionDenied = appendUniqueString(state.permissionDenied, path)
	case errors.Is(err, os.ErrNotExist), os.IsNotExist(err):
		state.missingPaths = appendUniqueString(state.missingPaths, path)
	default:
		state.incompletePaths = appendUniqueString(state.incompletePaths, path)
	}
}
