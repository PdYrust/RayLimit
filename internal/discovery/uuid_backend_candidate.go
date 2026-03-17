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

// UUIDNonIPBackendStatus reports whether RayLimit found a sharper non-IP UUID
// backend path beyond raw attachable client-IP evidence.
type UUIDNonIPBackendStatus string

const (
	UUIDNonIPBackendStatusUnavailable UUIDNonIPBackendStatus = "unavailable"
	UUIDNonIPBackendStatusCandidate   UUIDNonIPBackendStatus = "candidate"
)

func (s UUIDNonIPBackendStatus) Valid() bool {
	switch s {
	case UUIDNonIPBackendStatusUnavailable, UUIDNonIPBackendStatusCandidate:
		return true
	default:
		return false
	}
}

// UUIDNonIPBackendKind identifies the next safe backend family RayLimit can
// pursue when UUID aggregates cannot be attached directly by client IP.
type UUIDNonIPBackendKind string

const (
	UUIDNonIPBackendKindRoutingStatsPortClassifier UUIDNonIPBackendKind = "routing_stats_port_classifier"
)

func (k UUIDNonIPBackendKind) Valid() bool {
	switch k {
	case "", UUIDNonIPBackendKindRoutingStatsPortClassifier:
		return true
	default:
		return false
	}
}

// UUIDNonIPBackendCandidate summarizes whether readable runtime-local Xray
// config exposes the next safe non-IP UUID backend candidate.
type UUIDNonIPBackendCandidate struct {
	Status       UUIDNonIPBackendStatus `json:"status,omitempty"`
	Kind         UUIDNonIPBackendKind   `json:"kind,omitempty"`
	OutboundTags []string               `json:"outbound_tags,omitempty"`
	Reason       string                 `json:"reason,omitempty"`
}

func (c UUIDNonIPBackendCandidate) Validate() error {
	if !c.Status.Valid() {
		return fmt.Errorf("invalid uuid non-ip backend status %q", c.Status)
	}
	if !c.Kind.Valid() {
		return fmt.Errorf("invalid uuid non-ip backend kind %q", c.Kind)
	}
	if c.Status == UUIDNonIPBackendStatusCandidate && c.Kind == "" {
		return errors.New("uuid non-ip backend candidate kind is required when a candidate exists")
	}
	if c.Status == UUIDNonIPBackendStatusUnavailable && c.Kind != "" {
		return errors.New("uuid non-ip backend kind must be empty when no candidate is available")
	}
	seen := make(map[string]struct{}, len(c.OutboundTags))
	for index, tag := range c.OutboundTags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			return fmt.Errorf("uuid non-ip backend outbound tag at index %d is blank", index)
		}
		if _, ok := seen[tag]; ok {
			return fmt.Errorf("duplicate uuid non-ip backend outbound tag %q", tag)
		}
		seen[tag] = struct{}{}
	}
	if strings.TrimSpace(c.Reason) == "" {
		return errors.New("uuid non-ip backend reason is required")
	}

	return nil
}

type uuidNonIPBackendState struct {
	sawReadableConfig bool
	routingService    bool
	exactUserRules    int
	outboundTags      []string
	permissionDenied  []string
	missingPaths      []string
	incompletePaths   []string
}

// UUIDNonIPBackendCandidateDeriver inspects runtime-local Xray config hints to
// determine whether the next safe UUID backend candidate is available.
//
// The current first-pass candidate is a live RoutingService-backed
// source/local-port classifier bridge. It is safe because it depends on exact
// Xray user routing rather than falling back to shared client IP identity.
type UUIDNonIPBackendCandidateDeriver struct {
	readFile fileReadFunc
	readDir  dirReadFunc
	statPath pathStatFunc
}

// NewUUIDNonIPBackendCandidateDeriver returns the default UUID non-IP backend
// candidate deriver.
func NewUUIDNonIPBackendCandidateDeriver() UUIDNonIPBackendCandidateDeriver {
	return UUIDNonIPBackendCandidateDeriver{
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statPath: os.Stat,
	}
}

// Derive reports whether readable runtime-local Xray config exposes the next
// safe non-IP UUID backend candidate for the selected UUID.
func (d UUIDNonIPBackendCandidateDeriver) Derive(ctx context.Context, target RuntimeTarget, uuid string) (UUIDNonIPBackendCandidate, error) {
	d = d.withDefaults()

	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return UUIDNonIPBackendCandidate{}, errors.New("uuid is required")
	}
	if err := ctx.Err(); err != nil {
		return UUIDNonIPBackendCandidate{}, err
	}

	configPaths := inspectionConfigPaths(target)
	if len(configPaths) == 0 {
		result := UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusUnavailable,
			Reason: fmt.Sprintf("no readable Xray config path hint is available for UUID %q, so the next safe non-IP backend cannot be evaluated", uuid),
		}
		return result, result.Validate()
	}

	state := uuidNonIPBackendState{}
	for _, configPath := range uniqueConfigPaths(configPaths) {
		if err := ctx.Err(); err != nil {
			return UUIDNonIPBackendCandidate{}, err
		}
		if err := d.inspectPath(ctx, configPath, uuid, &state); err != nil {
			return UUIDNonIPBackendCandidate{}, err
		}
	}

	result := buildUUIDNonIPBackendCandidate(uuid, state)
	if err := result.Validate(); err != nil {
		return UUIDNonIPBackendCandidate{}, err
	}

	return result, nil
}

func (d UUIDNonIPBackendCandidateDeriver) withDefaults() UUIDNonIPBackendCandidateDeriver {
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

func (d UUIDNonIPBackendCandidateDeriver) inspectPath(ctx context.Context, path string, uuid string, state *uuidNonIPBackendState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	info, err := d.statPath(path)
	if err != nil {
		recordUUIDNonIPBackendPathIssue(state, path, err)
		return nil
	}
	if info.IsDir() {
		return d.inspectDir(ctx, path, uuid, state)
	}

	return d.inspectFile(ctx, path, uuid, state)
}

func (d UUIDNonIPBackendCandidateDeriver) inspectDir(ctx context.Context, dirPath string, uuid string, state *uuidNonIPBackendState) error {
	entries, err := d.readDir(dirPath)
	if err != nil {
		recordUUIDNonIPBackendPathIssue(state, dirPath, err)
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
		if err := d.inspectFile(ctx, filepath.Join(dirPath, name), uuid, state); err != nil {
			return err
		}
	}

	return nil
}

func (d UUIDNonIPBackendCandidateDeriver) inspectFile(ctx context.Context, filePath string, uuid string, state *uuidNonIPBackendState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := d.readFile(filePath)
	if err != nil {
		recordUUIDNonIPBackendPathIssue(state, filePath, err)
		return nil
	}

	var document xrayConfigDocument
	if err := json.Unmarshal(data, &document); err != nil {
		state.incompletePaths = appendUniqueString(state.incompletePaths, filePath)
		return nil
	}
	state.sawReadableConfig = true

	if document.API != nil {
		for _, service := range document.API.Services {
			if strings.TrimSpace(service) == "RoutingService" {
				state.routingService = true
				break
			}
		}
	}

	if document.Routing == nil {
		return nil
	}

	for _, rule := range document.Routing.Rules {
		outboundTag := strings.TrimSpace(rule.OutboundTag)
		if outboundTag == "" {
			continue
		}
		if !xrayRoutingRuleMatchesExactUser(rule, uuid) {
			continue
		}

		state.exactUserRules++
		state.outboundTags = appendUniqueString(state.outboundTags, outboundTag)
	}

	return nil
}

func xrayRoutingRuleMatchesExactUser(rule xrayRoutingRule, uuid string) bool {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return false
	}
	for _, user := range rule.Users {
		if strings.TrimSpace(user) == uuid {
			return true
		}
	}
	return false
}

func buildUUIDNonIPBackendCandidate(uuid string, state uuidNonIPBackendState) UUIDNonIPBackendCandidate {
	switch {
	case state.exactUserRules > 0 && state.routingService:
		outboundTags := append([]string(nil), state.outboundTags...)
		sort.Strings(outboundTags)
		return UUIDNonIPBackendCandidate{
			Status:       UUIDNonIPBackendStatusCandidate,
			Kind:         UUIDNonIPBackendKindRoutingStatsPortClassifier,
			OutboundTags: outboundTags,
			Reason: fmt.Sprintf(
				"readable Xray config enables RoutingService and exact user routing for UUID %q; live routing contexts can already drive the concrete local-socket and client-socket UUID backends, and the next broader exact-user-safe step is a remote-socket classifier that combines local and target tuple evidence without falling back to shared client IP",
				uuid,
			),
		}
	case state.exactUserRules > 0:
		return UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusUnavailable,
			Reason: fmt.Sprintf(
				"readable Xray config routes UUID %q exactly, but RoutingService is not enabled under api.services; the current concrete non-IP UUID backends and any broader exact-user remote-socket classifier all require live routing contexts before they can classify shared-IP or tunneled traffic safely",
				uuid,
			),
		}
	case len(state.permissionDenied) != 0:
		return UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusUnavailable,
			Reason: fmt.Sprintf(
				"the next safe non-IP UUID backend could not be evaluated for UUID %q because access to Xray config hints was denied for %s",
				uuid,
				summarizeAPICapabilityPaths(state.permissionDenied),
			),
		}
	case len(state.missingPaths) != 0:
		return UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusUnavailable,
			Reason: fmt.Sprintf(
				"the next safe non-IP UUID backend could not be evaluated for UUID %q because Xray config paths were missing: %s",
				uuid,
				summarizeAPICapabilityPaths(state.missingPaths),
			),
		}
	case len(state.incompletePaths) != 0:
		return UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusUnavailable,
			Reason: fmt.Sprintf(
				"the next safe non-IP UUID backend could not be evaluated for UUID %q because Xray config parsing was incomplete for %s",
				uuid,
				summarizeAPICapabilityPaths(state.incompletePaths),
			),
		}
	case state.sawReadableConfig:
		return UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusUnavailable,
			Reason: fmt.Sprintf(
				"no exact readable Xray user-routing rule matched UUID %q, so the next safe non-IP UUID backend is not yet provable from current config hints",
				uuid,
			),
		}
	default:
		return UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusUnavailable,
			Reason: fmt.Sprintf(
				"the next safe non-IP UUID backend could not be evaluated for UUID %q because no readable Xray config hint was available",
				uuid,
			),
		}
	}
}

func recordUUIDNonIPBackendPathIssue(state *uuidNonIPBackendState, path string, err error) {
	switch {
	case errors.Is(err, os.ErrPermission), os.IsPermission(err):
		state.permissionDenied = appendUniqueString(state.permissionDenied, path)
	case errors.Is(err, os.ErrNotExist), os.IsNotExist(err):
		state.missingPaths = appendUniqueString(state.missingPaths, path)
	default:
		state.incompletePaths = appendUniqueString(state.incompletePaths, path)
	}
}
