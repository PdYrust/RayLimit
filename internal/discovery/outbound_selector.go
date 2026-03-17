package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OutboundMarkSelector captures one concrete outbound socket-mark selector that
// can drive mark-backed classification for a specific Xray outbound tag.
type OutboundMarkSelector struct {
	Tag         string   `json:"tag"`
	SocketMark  uint32   `json:"socket_mark"`
	Expression  []string `json:"expression,omitempty"`
	Description string   `json:"description,omitempty"`
}

func (s OutboundMarkSelector) Validate() error {
	if strings.TrimSpace(s.Tag) == "" {
		return errors.New("outbound selector tag is required")
	}
	if s.SocketMark == 0 {
		return errors.New("outbound selector socket mark is required")
	}
	if len(s.Expression) == 0 {
		return errors.New("outbound selector expression is required")
	}
	for index, token := range s.Expression {
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf("outbound selector expression token at index %d is blank", index)
		}
	}

	return nil
}

func (s OutboundMarkSelector) key() string {
	return strings.Join([]string{
		strings.TrimSpace(s.Tag),
		fmt.Sprintf("0x%x", s.SocketMark),
		strings.Join(s.Expression, " "),
	}, "|")
}

// OutboundMarkSelectorResult reports whether one concrete outbound socket-mark
// selector could be derived conservatively from readable runtime-local Xray
// configuration.
type OutboundMarkSelectorResult struct {
	Selector *OutboundMarkSelector
	Reason   string
}

// OutboundMarkSelectorDeriver reads runtime-local Xray config hints and derives
// one concrete outbound selector only when the selected outbound tag owns one
// unique non-zero socket mark without outbound chaining indirection.
type OutboundMarkSelectorDeriver struct {
	readFile fileReadFunc
	readDir  dirReadFunc
	statPath pathStatFunc
}

type outboundMarkSelectorState struct {
	sawReadableConfig bool
	foundMatchingTag  bool
	permissionDenied  []string
	missingPaths      []string
	incompletePaths   []string
	matchIssues       []string
	candidates        []OutboundMarkSelector
	markOwners        map[uint32][]string
}

// NewOutboundMarkSelectorDeriver returns the default outbound selector deriver.
func NewOutboundMarkSelectorDeriver() OutboundMarkSelectorDeriver {
	return OutboundMarkSelectorDeriver{
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statPath: os.Stat,
	}
}

// Derive returns one concrete outbound selector when readable configuration
// proves that the selected outbound tag owns one unique non-zero socket mark.
func (d OutboundMarkSelectorDeriver) Derive(ctx context.Context, target RuntimeTarget, outboundTag string) (OutboundMarkSelectorResult, error) {
	d = d.withDefaults()

	tag := strings.TrimSpace(outboundTag)
	if tag == "" {
		return OutboundMarkSelectorResult{}, errors.New("outbound tag is required")
	}
	if err := ctx.Err(); err != nil {
		return OutboundMarkSelectorResult{}, err
	}

	configPaths := inspectionConfigPaths(target)
	if len(configPaths) == 0 {
		return OutboundMarkSelectorResult{
			Reason: fmt.Sprintf("concrete outbound attachment for tag %q requires readable Xray config hints; no config path hint is available for outbound tag %q", tag, tag),
		}, nil
	}

	state := outboundMarkSelectorState{
		markOwners: make(map[uint32][]string),
	}
	for _, configPath := range uniqueConfigPaths(configPaths) {
		if err := ctx.Err(); err != nil {
			return OutboundMarkSelectorResult{}, err
		}
		if err := d.inspectPath(ctx, configPath, tag, &state); err != nil {
			return OutboundMarkSelectorResult{}, err
		}
	}

	return buildOutboundMarkSelectorResult(tag, state), nil
}

func (d OutboundMarkSelectorDeriver) withDefaults() OutboundMarkSelectorDeriver {
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

func (d OutboundMarkSelectorDeriver) inspectPath(ctx context.Context, path string, outboundTag string, state *outboundMarkSelectorState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	info, err := d.statPath(path)
	if err != nil {
		recordOutboundSelectorPathIssue(state, path, err)
		return nil
	}
	if info.IsDir() {
		return d.inspectDir(ctx, path, outboundTag, state)
	}

	return d.inspectFile(ctx, path, outboundTag, state)
}

func (d OutboundMarkSelectorDeriver) inspectDir(ctx context.Context, dirPath string, outboundTag string, state *outboundMarkSelectorState) error {
	entries, err := d.readDir(dirPath)
	if err != nil {
		recordOutboundSelectorPathIssue(state, dirPath, err)
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
		if err := d.inspectFile(ctx, filepath.Join(dirPath, name), outboundTag, state); err != nil {
			return err
		}
	}

	return nil
}

func (d OutboundMarkSelectorDeriver) inspectFile(ctx context.Context, filePath string, outboundTag string, state *outboundMarkSelectorState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := d.readFile(filePath)
	if err != nil {
		recordOutboundSelectorPathIssue(state, filePath, err)
		return nil
	}

	var document xrayConfigDocument
	if err := json.Unmarshal(data, &document); err != nil {
		state.incompletePaths = appendUniqueString(state.incompletePaths, filePath)
		return nil
	}
	state.sawReadableConfig = true

	for _, outbound := range document.Outbounds {
		if concreteMark, ok := outboundConcreteSocketMark(outbound); ok {
			tag := strings.TrimSpace(outbound.Tag)
			state.markOwners[concreteMark] = appendUniqueString(state.markOwners[concreteMark], tag)
		}

		if strings.TrimSpace(outbound.Tag) != outboundTag {
			continue
		}

		state.foundMatchingTag = true
		candidate, reason, ok := outboundMarkSelectorCandidate(outbound)
		if !ok {
			if reason != "" {
				state.matchIssues = appendUniqueString(state.matchIssues, fmt.Sprintf("%s: %s", filePath, reason))
			}
			continue
		}
		state.candidates = appendUniqueOutboundMarkSelector(state.candidates, candidate)
	}

	return nil
}

func buildOutboundMarkSelectorResult(outboundTag string, state outboundMarkSelectorState) OutboundMarkSelectorResult {
	switch len(state.candidates) {
	case 1:
		selector := state.candidates[0]
		if owners := markOwnersForSelector(state.markOwners, selector); len(owners) > 1 {
			return OutboundMarkSelectorResult{
				Reason: fmt.Sprintf(
					"concrete outbound attachment for tag %q is unavailable because socket mark 0x%x is shared across readable outbound config: %s",
					outboundTag,
					selector.SocketMark,
					strings.Join(owners, ", "),
				),
			}
		}
		return OutboundMarkSelectorResult{Selector: &selector}
	case 0:
	default:
		socketMarks := make([]string, 0, len(state.candidates))
		for _, candidate := range state.candidates {
			socketMarks = append(socketMarks, fmt.Sprintf("0x%x", candidate.SocketMark))
		}
		sort.Strings(socketMarks)
		return OutboundMarkSelectorResult{
			Reason: fmt.Sprintf(
				"concrete outbound attachment for tag %q is ambiguous because readable Xray config hints expose multiple concrete socket marks: %s",
				outboundTag,
				strings.Join(socketMarks, ", "),
			),
		}
	}

	if len(state.permissionDenied) != 0 {
		return OutboundMarkSelectorResult{
			Reason: fmt.Sprintf(
				"concrete outbound attachment for tag %q requires readable Xray config hints, but access was denied for %s",
				outboundTag,
				summarizeAPICapabilityPaths(state.permissionDenied),
			),
		}
	}
	if len(state.matchIssues) != 0 {
		issues := append([]string(nil), state.matchIssues...)
		sort.Strings(issues)
		return OutboundMarkSelectorResult{
			Reason: fmt.Sprintf("concrete outbound attachment for tag %q is unavailable: %s", outboundTag, issues[0]),
		}
	}
	if state.foundMatchingTag {
		return OutboundMarkSelectorResult{
			Reason: fmt.Sprintf("concrete outbound attachment for tag %q could not be derived from readable Xray config hints", outboundTag),
		}
	}
	if state.sawReadableConfig {
		return OutboundMarkSelectorResult{
			Reason: fmt.Sprintf("no outbound tagged %q was found in readable Xray config hints", outboundTag),
		}
	}
	if len(state.missingPaths) != 0 {
		return OutboundMarkSelectorResult{
			Reason: fmt.Sprintf(
				"concrete outbound attachment for tag %q requires readable Xray config hints, but config paths were missing: %s",
				outboundTag,
				summarizeAPICapabilityPaths(state.missingPaths),
			),
		}
	}
	if len(state.incompletePaths) != 0 {
		return OutboundMarkSelectorResult{
			Reason: fmt.Sprintf(
				"concrete outbound attachment for tag %q requires readable Xray config hints, but config parsing was incomplete for %s",
				outboundTag,
				summarizeAPICapabilityPaths(state.incompletePaths),
			),
		}
	}

	return OutboundMarkSelectorResult{
		Reason: fmt.Sprintf("concrete outbound attachment for tag %q requires readable Xray config hints", outboundTag),
	}
}

func outboundMarkSelectorCandidate(outbound xrayOutboundEntry) (OutboundMarkSelector, string, bool) {
	tag := strings.TrimSpace(outbound.Tag)
	if tag == "" {
		return OutboundMarkSelector{}, "outbound tag is blank", false
	}
	if outbound.ProxySettings != nil && strings.TrimSpace(outbound.ProxySettings.Tag) != "" {
		return OutboundMarkSelector{}, fmt.Sprintf("proxySettings.tag %q delegates transport to another outbound; concrete outbound attachment currently requires the selected outbound tag to own its marked system dial path", strings.TrimSpace(outbound.ProxySettings.Tag)), false
	}
	if outbound.StreamSettings == nil || outbound.StreamSettings.SocketSettings == nil {
		return OutboundMarkSelector{}, "streamSettings.sockopt.mark is missing or zero; concrete outbound attachment currently requires one unique non-zero outbound socket mark", false
	}
	if strings.TrimSpace(outbound.StreamSettings.SocketSettings.DialerProxy) != "" {
		return OutboundMarkSelector{}, fmt.Sprintf("streamSettings.sockopt.dialerProxy %q delegates transport to another outbound; concrete outbound attachment currently requires the selected outbound tag to own its marked system dial path", strings.TrimSpace(outbound.StreamSettings.SocketSettings.DialerProxy)), false
	}
	if outbound.StreamSettings.SocketSettings.Mark <= 0 {
		return OutboundMarkSelector{}, "streamSettings.sockopt.mark is missing or zero; concrete outbound attachment currently requires one unique non-zero outbound socket mark", false
	}

	socketMark := uint32(outbound.StreamSettings.SocketSettings.Mark)
	selector := OutboundMarkSelector{
		Tag:        tag,
		SocketMark: socketMark,
		Expression: []string{"meta", "mark", fmt.Sprintf("0x%x", socketMark)},
		Description: fmt.Sprintf(
			"configured outbound socket mark 0x%x for outbound tag %q",
			socketMark,
			tag,
		),
	}
	if err := selector.Validate(); err != nil {
		return OutboundMarkSelector{}, err.Error(), false
	}

	return selector, "", true
}

func outboundConcreteSocketMark(outbound xrayOutboundEntry) (uint32, bool) {
	if outbound.ProxySettings != nil && strings.TrimSpace(outbound.ProxySettings.Tag) != "" {
		return 0, false
	}
	if outbound.StreamSettings == nil || outbound.StreamSettings.SocketSettings == nil {
		return 0, false
	}
	if strings.TrimSpace(outbound.StreamSettings.SocketSettings.DialerProxy) != "" {
		return 0, false
	}
	if outbound.StreamSettings.SocketSettings.Mark <= 0 {
		return 0, false
	}

	return uint32(outbound.StreamSettings.SocketSettings.Mark), true
}

func markOwnersForSelector(markOwners map[uint32][]string, selector OutboundMarkSelector) []string {
	owners := append([]string(nil), markOwners[selector.SocketMark]...)
	sort.Strings(owners)
	return owners
}

func appendUniqueOutboundMarkSelector(values []OutboundMarkSelector, selector OutboundMarkSelector) []OutboundMarkSelector {
	key := selector.key()
	for _, existing := range values {
		if existing.key() == key {
			return values
		}
	}

	return append(values, selector)
}

func recordOutboundSelectorPathIssue(state *outboundMarkSelectorState, path string, err error) {
	switch {
	case errors.Is(err, os.ErrPermission), os.IsPermission(err):
		state.permissionDenied = appendUniqueString(state.permissionDenied, path)
	case errors.Is(err, os.ErrNotExist), os.IsNotExist(err):
		state.missingPaths = appendUniqueString(state.missingPaths, path)
	default:
		state.incompletePaths = appendUniqueString(state.incompletePaths, path)
	}
}
