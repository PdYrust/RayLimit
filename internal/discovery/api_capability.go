package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fileReadFunc func(path string) ([]byte, error)
type dirReadFunc func(path string) ([]os.DirEntry, error)
type pathStatFunc func(path string) (os.FileInfo, error)

// APICapabilityDetector inspects local runtime metadata for conservative API capability hints.
type APICapabilityDetector struct {
	readFile      fileReadFunc
	readDir       dirReadFunc
	statPath      pathStatFunc
	inspectDocker dockerInspectFunc
}

type apiCapabilityState struct {
	sawReadableConfig bool
	hadConfigIssues   bool
	apiServices       bool
	apiTags           map[string]struct{}
	endpointsByTag    map[string][]APIEndpoint
	directAPIInbound  bool
	routedAPIInbound  bool
	permissionDenied  []string
	missingPaths      []string
	incompletePaths   []string
}

type xrayConfigDocument struct {
	API       *xrayAPIConfig      `json:"api"`
	Inbounds  []xrayInboundEntry  `json:"inbounds"`
	Outbounds []xrayOutboundEntry `json:"outbounds"`
	Routing   *xrayRoutingConfig  `json:"routing"`
}

type xrayAPIConfig struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type xrayInboundEntry struct {
	Tag            string            `json:"tag"`
	Listen         string            `json:"listen"`
	Port           int               `json:"port"`
	Protocol       string            `json:"protocol"`
	StreamSettings *xrayStreamConfig `json:"streamSettings"`
}

type xrayStreamConfig struct {
	Network        string            `json:"network"`
	SocketSettings *xraySocketConfig `json:"sockopt"`
}

type xraySocketConfig struct {
	Mark        int32  `json:"mark"`
	DialerProxy string `json:"dialerProxy"`
}

type xrayProxyConfig struct {
	Tag string `json:"tag"`
}

type xrayOutboundEntry struct {
	Tag            string            `json:"tag"`
	Protocol       string            `json:"protocol"`
	StreamSettings *xrayStreamConfig `json:"streamSettings"`
	ProxySettings  *xrayProxyConfig  `json:"proxySettings"`
}

type xrayRoutingConfig struct {
	Rules []xrayRoutingRule `json:"rules"`
}

type xrayRoutingRule struct {
	Type        string   `json:"type"`
	Users       []string `json:"user"`
	InboundTags []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

// NewAPICapabilityDetector returns the default API capability detector.
func NewAPICapabilityDetector() APICapabilityDetector {
	return APICapabilityDetector{
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statPath: os.Stat,
	}
}

// EnrichTargets annotates runtime targets with conservative API capability hints.
func (d APICapabilityDetector) EnrichTargets(ctx context.Context, targets []RuntimeTarget) ([]RuntimeTarget, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	enriched := make([]RuntimeTarget, len(targets))
	for index, target := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		updated, err := d.EnrichTarget(ctx, target)
		if err != nil {
			return nil, err
		}

		enriched[index] = updated
	}

	return enriched, nil
}

// EnrichTarget annotates a single runtime target with conservative API capability hints.
func (d APICapabilityDetector) EnrichTarget(ctx context.Context, target RuntimeTarget) (RuntimeTarget, error) {
	d = d.withDefaults()

	if err := ctx.Err(); err != nil {
		return RuntimeTarget{}, err
	}

	if target.APICapability == nil {
		if len(target.APIEndpoints) > 0 {
			target.APICapability = &APICapability{
				Status: APICapabilityStatusLikelyConfigured,
				Reason: "Existing runtime metadata already includes API endpoint hints.",
			}
		} else {
			configPaths := inspectionConfigPaths(target)
			if len(configPaths) == 0 {
				target.APICapability = &APICapability{
					Status:     APICapabilityStatusUnknown,
					Reason:     "API capability is unknown because no Xray configuration hint is available.",
					Limitation: APICapabilityLimitationMissingConfigHint,
				}
			} else {
				state, err := d.inspectConfigPaths(ctx, configPaths)
				if err != nil {
					return RuntimeTarget{}, err
				}

				target.APICapability = &APICapability{
					Status:     buildAPICapabilityStatus(state),
					Reason:     buildAPICapabilityReason(state),
					Limitation: buildAPICapabilityLimitation(state),
				}

				if len(target.APIEndpoints) == 0 {
					target.APIEndpoints = collectAPIEndpoints(state)
				}
			}
		}
	}

	if len(target.ReachableAPIEndpoints) == 0 && len(target.APIEndpoints) != 0 {
		reachable, err := d.resolveReachableAPIEndpoints(ctx, target)
		if err != nil {
			return RuntimeTarget{}, err
		}
		target.ReachableAPIEndpoints = reachable
	}

	return target, nil
}

func (d APICapabilityDetector) inspectConfigPaths(ctx context.Context, configPaths []string) (apiCapabilityState, error) {
	d = d.withDefaults()

	state := apiCapabilityState{
		apiTags:        make(map[string]struct{}),
		endpointsByTag: make(map[string][]APIEndpoint),
	}

	for _, configPath := range uniqueConfigPaths(configPaths) {
		if err := ctx.Err(); err != nil {
			return apiCapabilityState{}, err
		}

		if err := d.inspectConfigPath(ctx, configPath, &state); err != nil {
			return apiCapabilityState{}, err
		}
	}

	return state, nil
}

func (d APICapabilityDetector) inspectConfigPath(ctx context.Context, configPath string, state *apiCapabilityState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	info, err := d.statPath(configPath)
	if err != nil {
		state.hadConfigIssues = true
		recordAPICapabilityPathIssue(state, configPath, err)
		return nil
	}

	if info.IsDir() {
		return d.inspectConfigDir(ctx, configPath, state)
	}

	return d.inspectConfigFile(ctx, configPath, state)
}

func (d APICapabilityDetector) inspectConfigDir(ctx context.Context, dirPath string, state *apiCapabilityState) error {
	entries, err := d.readDir(dirPath)
	if err != nil {
		state.hadConfigIssues = true
		recordAPICapabilityPathIssue(state, dirPath, err)
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
		state.hadConfigIssues = true
		state.incompletePaths = appendUniqueString(state.incompletePaths, dirPath)
		return nil
	}

	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := d.inspectConfigFile(ctx, filepath.Join(dirPath, name), state); err != nil {
			return err
		}
	}

	return nil
}

func (d APICapabilityDetector) inspectConfigFile(ctx context.Context, filePath string, state *apiCapabilityState) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := d.readFile(filePath)
	if err != nil {
		state.hadConfigIssues = true
		recordAPICapabilityPathIssue(state, filePath, err)
		return nil
	}

	var document xrayConfigDocument
	if err := json.Unmarshal(data, &document); err != nil {
		state.hadConfigIssues = true
		state.incompletePaths = appendUniqueString(state.incompletePaths, filePath)
		return nil
	}

	state.sawReadableConfig = true

	if document.API != nil && len(document.API.Services) > 0 {
		state.apiServices = true

		if tag := strings.TrimSpace(document.API.Tag); tag != "" {
			state.apiTags[tag] = struct{}{}
		}
	}

	for _, inbound := range document.Inbounds {
		tag := strings.TrimSpace(inbound.Tag)
		if tag == "" {
			continue
		}

		endpoint, ok := apiEndpointFromInbound(inbound)
		if !ok {
			continue
		}

		state.endpointsByTag[tag] = appendUniqueAPIEndpoint(state.endpointsByTag[tag], endpoint)
		if _, ok := state.apiTags[tag]; ok {
			state.directAPIInbound = true
		}
	}

	if document.Routing != nil {
		for _, rule := range document.Routing.Rules {
			outboundTag := strings.TrimSpace(rule.OutboundTag)
			if outboundTag == "" {
				continue
			}
			if _, ok := state.apiTags[outboundTag]; !ok {
				continue
			}

			for _, inboundTag := range rule.InboundTags {
				inboundTag = strings.TrimSpace(inboundTag)
				if inboundTag == "" {
					continue
				}

				endpoints := state.endpointsByTag[inboundTag]
				for _, endpoint := range endpoints {
					state.endpointsByTag[outboundTag] = appendUniqueAPIEndpoint(state.endpointsByTag[outboundTag], endpoint)
					state.routedAPIInbound = true
				}
			}
		}
	}

	return nil
}

func (d APICapabilityDetector) withDefaults() APICapabilityDetector {
	if d.readFile == nil {
		d.readFile = os.ReadFile
	}
	if d.readDir == nil {
		d.readDir = os.ReadDir
	}
	if d.statPath == nil {
		d.statPath = os.Stat
	}
	if d.inspectDocker == nil {
		d.inspectDocker = inspectDockerContainers
	}

	return d
}

func (d APICapabilityDetector) resolveReachableAPIEndpoints(ctx context.Context, target RuntimeTarget) ([]APIEndpoint, error) {
	containerID := targetContainerID(target)
	if containerID == "" || len(target.APIEndpoints) == 0 {
		return nil, nil
	}

	inspected, err := d.inspectDocker(ctx, []string{containerID})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}

	details, ok := inspected[containerID]
	if !ok {
		return nil, nil
	}

	return mapAPIEndpointsToPublishedPorts(target.APIEndpoints, details.Ports), nil
}

func targetContainerID(target RuntimeTarget) string {
	if target.HostProcess != nil {
		return strings.TrimSpace(target.HostProcess.ContainerID)
	}
	if target.DockerContainer != nil {
		return strings.TrimSpace(target.DockerContainer.ID)
	}

	return ""
}

func mapAPIEndpointsToPublishedPorts(endpoints []APIEndpoint, ports []dockerPortBinding) []APIEndpoint {
	if len(endpoints) == 0 || len(ports) == 0 {
		return nil
	}

	reachable := make([]APIEndpoint, 0)
	for _, endpoint := range endpoints {
		if endpoint.Network != EndpointNetworkTCP || endpoint.Port == 0 {
			continue
		}

		for _, binding := range ports {
			if binding.Protocol != "tcp" || binding.ContainerPort != endpoint.Port {
				continue
			}

			reachable = appendUniqueAPIEndpoint(reachable, APIEndpoint{
				Name:    endpoint.Name,
				Network: EndpointNetworkTCP,
				Address: normalizePublishedHost(binding.HostIP),
				Port:    binding.HostPort,
				TLS:     endpoint.TLS,
			})
		}
	}

	if len(reachable) == 0 {
		return nil
	}

	return reachable
}

func normalizePublishedHost(host string) string {
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return "127.0.0.1"
	default:
		return host
	}
}

func inspectionConfigPaths(target RuntimeTarget) []string {
	if target.HostProcess != nil {
		if len(target.HostProcess.ResolvedConfigPaths) != 0 {
			return cloneStrings(target.HostProcess.ResolvedConfigPaths)
		}
		return cloneStrings(target.HostProcess.ConfigPaths)
	}

	if target.DockerContainer != nil {
		return cloneStrings(target.DockerContainer.ConfigPaths)
	}

	return nil
}

func buildAPICapabilityStatus(state apiCapabilityState) APICapabilityStatus {
	if state.apiServices {
		return APICapabilityStatusLikelyConfigured
	}
	if state.sawReadableConfig && !state.hadConfigIssues {
		return APICapabilityStatusNotEvident
	}

	return APICapabilityStatusUnknown
}

func buildAPICapabilityLimitation(state apiCapabilityState) APICapabilityLimitation {
	switch buildAPICapabilityStatus(state) {
	case APICapabilityStatusLikelyConfigured, APICapabilityStatusNotEvident:
		return ""
	default:
		if len(state.permissionDenied) != 0 {
			return APICapabilityLimitationPermissionDenied
		}
		if len(state.missingPaths) != 0 {
			return APICapabilityLimitationMissingConfigPath
		}
		if state.sawReadableConfig || state.hadConfigIssues {
			return APICapabilityLimitationIncompleteConfig
		}
		return APICapabilityLimitationMissingConfigHint
	}
}

func buildAPICapabilityReason(state apiCapabilityState) string {
	switch buildAPICapabilityStatus(state) {
	case APICapabilityStatusLikelyConfigured:
		if len(collectAPIEndpoints(state)) > 0 {
			if state.routedAPIInbound && !state.directAPIInbound {
				return "Readable configuration hints define Xray API services and a routing-assisted API inbound."
			}
			return "Readable configuration hints define Xray API services and a matching inbound."
		}
		return "Readable configuration hints define Xray API services, but no API inbound was evident."
	case APICapabilityStatusNotEvident:
		return "No Xray API capability was evident in readable configuration hints."
	default:
		switch buildAPICapabilityLimitation(state) {
		case APICapabilityLimitationPermissionDenied:
			return buildAPICapabilityPermissionDeniedReason(state)
		case APICapabilityLimitationMissingConfigPath:
			return buildAPICapabilityMissingPathReason(state)
		case APICapabilityLimitationIncompleteConfig:
			return buildAPICapabilityIncompleteReason(state)
		default:
			return "API capability is unknown because no Xray configuration hint is available."
		}
	}
}

func buildAPICapabilityPermissionDeniedReason(state apiCapabilityState) string {
	message := "API capability is unknown because access to Xray configuration hints was denied"
	if paths := summarizeAPICapabilityPaths(state.permissionDenied); paths != "" {
		message += " for " + paths
	}
	if len(state.incompletePaths) != 0 || state.sawReadableConfig {
		message += "; remaining configuration hints were incomplete or only partially readable"
	}
	message += ". Run RayLimit as root or make the configuration readable."

	return message
}

func buildAPICapabilityIncompleteReason(state apiCapabilityState) string {
	message := "API capability is unknown because configuration hints were incomplete."
	if paths := summarizeAPICapabilityPaths(state.incompletePaths); paths != "" {
		message = "API capability is unknown because configuration hints were incomplete for " + paths + "."
	}

	return message
}

func buildAPICapabilityMissingPathReason(state apiCapabilityState) string {
	message := "API capability is unknown because Xray configuration hints pointed to missing paths."
	if paths := summarizeAPICapabilityPaths(state.missingPaths); paths != "" {
		message = "API capability is unknown because Xray configuration hints pointed to missing paths: " + paths + "."
	}
	if len(state.incompletePaths) != 0 || state.sawReadableConfig {
		message += " Remaining configuration hints were incomplete or only partially readable."
	}

	return message
}

func collectAPIEndpoints(state apiCapabilityState) []APIEndpoint {
	if len(state.apiTags) == 0 {
		return nil
	}

	endpoints := make([]APIEndpoint, 0)
	tags := make([]string, 0, len(state.apiTags))
	for tag := range state.apiTags {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	for _, tag := range tags {
		for _, endpoint := range state.endpointsByTag[tag] {
			endpoints = appendUniqueAPIEndpoint(endpoints, endpoint)
		}
	}

	if len(endpoints) == 0 {
		return nil
	}

	return endpoints
}

func uniqueConfigPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(paths))
	unique := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}

		seen[path] = struct{}{}
		unique = append(unique, path)
	}

	if len(unique) == 0 {
		return nil
	}

	return unique
}

func apiEndpointFromInbound(inbound xrayInboundEntry) (APIEndpoint, bool) {
	tag := strings.TrimSpace(inbound.Tag)
	if tag == "" {
		return APIEndpoint{}, false
	}

	listen := strings.TrimSpace(inbound.Listen)
	switch {
	case strings.HasPrefix(listen, "unix://"):
		path := strings.TrimPrefix(listen, "unix://")
		if path == "" {
			return APIEndpoint{}, false
		}

		return APIEndpoint{
			Name:    tag,
			Network: EndpointNetworkUnix,
			Path:    path,
		}, true
	case strings.HasPrefix(listen, "/"):
		return APIEndpoint{
			Name:    tag,
			Network: EndpointNetworkUnix,
			Path:    listen,
		}, true
	case inbound.Port > 0:
		return APIEndpoint{
			Name:    tag,
			Network: EndpointNetworkTCP,
			Address: listen,
			Port:    inbound.Port,
		}, true
	default:
		return APIEndpoint{}, false
	}
}

func appendUniqueAPIEndpoint(endpoints []APIEndpoint, endpoint APIEndpoint) []APIEndpoint {
	for _, existing := range endpoints {
		if existing.Name == endpoint.Name &&
			existing.Network == endpoint.Network &&
			existing.Address == endpoint.Address &&
			existing.Port == endpoint.Port &&
			existing.Path == endpoint.Path &&
			existing.TLS == endpoint.TLS {
			return endpoints
		}
	}

	return append(endpoints, endpoint)
}

func recordAPICapabilityPathIssue(state *apiCapabilityState, path string, err error) {
	switch {
	case errors.Is(err, os.ErrPermission), os.IsPermission(err):
		state.permissionDenied = appendUniqueString(state.permissionDenied, path)
	case errors.Is(err, os.ErrNotExist), os.IsNotExist(err):
		state.missingPaths = appendUniqueString(state.missingPaths, path)
	default:
		state.incompletePaths = appendUniqueString(state.incompletePaths, path)
	}
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}

	for _, existing := range values {
		if existing == value {
			return values
		}
	}

	return append(values, value)
}

func summarizeAPICapabilityPaths(paths []string) string {
	if len(paths) == 0 {
		return ""
	}

	ordered := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		ordered = append(ordered, path)
	}
	if len(ordered) == 0 {
		return ""
	}

	sort.Strings(ordered)
	return strings.Join(ordered, ", ")
}
