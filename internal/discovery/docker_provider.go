package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/PdYrust/RayLimit/internal/privilege"
)

type dockerListFunc func(ctx context.Context) ([]dockerContainerSummary, error)
type dockerInspectFunc func(ctx context.Context, ids []string) (map[string]dockerContainerInspect, error)

// defaultContainerCLI is the container runtime CLI used when no override is
// configured. It can be overridden (for example to "podman" or "nerdctl") so
// non-Docker container engines are supported.
const defaultContainerCLI = "docker"

// dockerExecCommandContext and dockerLookPath are package variables so tests can
// substitute container CLI process execution and resolution.
var (
	dockerExecCommandContext = exec.CommandContext
	dockerLookPath           = exec.LookPath
)

// normalizeContainerCLI returns the configured container CLI name, falling back
// to the default when unset.
func normalizeContainerCLI(cli string) string {
	cli = strings.TrimSpace(cli)
	if cli == "" {
		return defaultContainerCLI
	}

	return cli
}

type dockerContainerSummary struct {
	ID      string
	Name    string
	Image   string
	Command string
	State   string
	Status  string
}

type dockerPSLine struct {
	ID      string `json:"ID"`
	Image   string `json:"Image"`
	Names   string `json:"Names"`
	Command string `json:"Command"`
	State   string `json:"State"`
	Status  string `json:"Status"`
}

type dockerContainerInspect struct {
	ID     string
	Path   string
	Args   []string
	Labels map[string]string
	Mounts []dockerMount
	Ports  []dockerPortBinding
}

type dockerMount struct {
	Source      string
	Destination string
	Type        string
}

type dockerPortBinding struct {
	ContainerPort int
	Protocol      string
	HostIP        string
	HostPort      int
}

type dockerInspectLine struct {
	ID     string   `json:"Id"`
	Path   string   `json:"Path"`
	Args   []string `json:"Args"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Type        string `json:"Type"`
	} `json:"Mounts"`
}

// DockerProvider discovers Xray candidates from local Docker containers.
type DockerProvider struct {
	containerCLI      string
	listContainers    dockerListFunc
	inspectContainers dockerInspectFunc
}

// NewDockerProviderWithCLI returns a Docker discovery provider that invokes the
// given container CLI (for example "podman" or "nerdctl"). An empty name uses
// the default ("docker").
func NewDockerProviderWithCLI(cli string) DockerProvider {
	cli = normalizeContainerCLI(cli)

	return DockerProvider{
		containerCLI: cli,
		listContainers: func(ctx context.Context) ([]dockerContainerSummary, error) {
			return listDockerContainers(ctx, cli)
		},
		inspectContainers: func(ctx context.Context, ids []string) (map[string]dockerContainerInspect, error) {
			return inspectDockerContainers(ctx, ids, cli)
		},
	}
}

func (p DockerProvider) Name() string {
	return "docker"
}

func (p DockerProvider) Source() DiscoverySource {
	return DiscoverySourceDockerContainer
}

func (p DockerProvider) Discover(ctx context.Context, _ Request) (ProviderResult, error) {
	listContainers := p.listContainers
	if listContainers == nil {
		cli := normalizeContainerCLI(p.containerCLI)
		listContainers = func(ctx context.Context) ([]dockerContainerSummary, error) {
			return listDockerContainers(ctx, cli)
		}
	}
	inspectContainers := p.inspectContainers
	if inspectContainers == nil {
		cli := normalizeContainerCLI(p.containerCLI)
		inspectContainers = func(ctx context.Context, ids []string) (map[string]dockerContainerInspect, error) {
			return inspectDockerContainers(ctx, ids, cli)
		}
	}

	containers, err := listContainers(ctx)
	if err != nil {
		var providerErr ProviderError
		if errors.As(err, &providerErr) {
			return ProviderResult{
				Issues: []ProviderError{providerErr},
			}, nil
		}

		return ProviderResult{}, err
	}

	sort.Slice(containers, func(i, j int) bool {
		left := firstNonEmpty(containers[i].Name, containers[i].ID)
		right := firstNonEmpty(containers[j].Name, containers[j].ID)
		if left == right {
			return containers[i].ID < containers[j].ID
		}

		return left < right
	})

	inspected := make(map[string]dockerContainerInspect)
	var inspectIssue *ProviderError
	if details, err := inspectContainers(ctx, dockerContainerIDs(containers)); err != nil {
		if issue, ok := dockerInspectIssue(err); ok {
			inspectIssue = &issue
		} else {
			issue := dockerMetadataPartialIssue(err)
			inspectIssue = &issue
		}
	} else {
		inspected = details
	}

	targets := make([]RuntimeTarget, 0, len(containers))
	scanned := 0
	for _, container := range containers {
		if !dockerContainerEvaluable(container) {
			continue
		}
		scanned++

		target, ok := targetFromDockerContainer(container, inspected[container.ID])
		if !ok {
			continue
		}

		targets = append(targets, target)
	}

	result := ProviderResult{Targets: targets}
	if inspectIssue != nil {
		result.Issues = append(result.Issues, *inspectIssue)
	}
	if len(targets) == 0 && scanned > 0 {
		result.Issues = append(result.Issues, dockerNoMatchesIssue(scanned, len(targets)))
	}

	return result, nil
}

func listDockerContainers(ctx context.Context, cli string) ([]dockerContainerSummary, error) {
	cli = normalizeContainerCLI(cli)
	if _, err := dockerLookPath(cli); err != nil {
		return nil, containerCLINotInstalledIssue(cli, err)
	}

	cmd := dockerExecCommandContext(
		ctx,
		cli,
		"ps",
		"--no-trunc",
		"--format",
		"{{json .}}",
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if issue, ok := classifyDockerCommandError(stderr.String(), err); ok {
			return nil, issue
		}

		return nil, fmt.Errorf("list docker containers: %w", err)
	}

	return parseDockerPSOutput(stdout.Bytes()), nil
}

func inspectDockerContainers(ctx context.Context, ids []string, cli string) (map[string]dockerContainerInspect, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	cli = normalizeContainerCLI(cli)
	if _, err := dockerLookPath(cli); err != nil {
		return nil, containerCLINotInstalledIssue(cli, err)
	}

	args := append([]string{"inspect"}, ids...)
	cmd := dockerExecCommandContext(ctx, cli, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if issue, ok := classifyDockerCommandError(stderr.String(), err); ok {
			return nil, issue
		}
		return nil, fmt.Errorf("inspect docker containers: %w", err)
	}

	var parsed []dockerInspectLine
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return nil, fmt.Errorf("decode docker inspect output: %w", err)
	}

	inspected := make(map[string]dockerContainerInspect, len(parsed))
	for _, line := range parsed {
		if id := strings.TrimSpace(line.ID); id != "" {
			inspected[id] = dockerInspectFromLine(line)
		}
	}

	return inspected, nil
}

func parseDockerPSOutput(data []byte) []dockerContainerSummary {
	lines := bytes.Split(data, []byte{'\n'})
	containers := make([]dockerContainerSummary, 0, len(lines))

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var parsed dockerPSLine
		if err := json.Unmarshal(line, &parsed); err != nil {
			continue
		}

		containers = append(containers, dockerContainerSummary{
			ID:      strings.TrimSpace(parsed.ID),
			Name:    strings.TrimSpace(parsed.Names),
			Image:   strings.TrimSpace(parsed.Image),
			Command: normalizeDockerCommand(parsed.Command),
			State:   strings.TrimSpace(parsed.State),
			Status:  strings.TrimSpace(parsed.Status),
		})
	}

	return containers
}

func dockerInspectFromLine(line dockerInspectLine) dockerContainerInspect {
	inspect := dockerContainerInspect{
		ID:     strings.TrimSpace(line.ID),
		Path:   strings.TrimSpace(line.Path),
		Args:   cloneStrings(line.Args),
		Labels: cloneStringMap(line.Config.Labels),
		Mounts: make([]dockerMount, 0, len(line.Mounts)),
		Ports:  parseDockerPortBindings(line.NetworkSettings.Ports),
	}

	for _, mount := range line.Mounts {
		inspect.Mounts = append(inspect.Mounts, dockerMount{
			Source:      strings.TrimSpace(mount.Source),
			Destination: strings.TrimSpace(mount.Destination),
			Type:        strings.TrimSpace(mount.Type),
		})
	}

	return inspect
}

func parseDockerPortBindings(ports map[string][]struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}) []dockerPortBinding {
	if len(ports) == 0 {
		return nil
	}

	parsed := make([]dockerPortBinding, 0, len(ports))
	for containerPortSpec, bindings := range ports {
		containerPort, protocol, ok := parseDockerPortSpec(containerPortSpec)
		if !ok {
			continue
		}

		for _, binding := range bindings {
			hostPort := strings.TrimSpace(binding.HostPort)
			if hostPort == "" {
				continue
			}

			value, err := strconv.Atoi(hostPort)
			if err != nil || value <= 0 || value > 65535 {
				continue
			}

			parsed = append(parsed, dockerPortBinding{
				ContainerPort: containerPort,
				Protocol:      protocol,
				HostIP:        strings.TrimSpace(binding.HostIP),
				HostPort:      value,
			})
		}
	}

	sort.Slice(parsed, func(i, j int) bool {
		left := parsed[i]
		right := parsed[j]
		if left.ContainerPort != right.ContainerPort {
			return left.ContainerPort < right.ContainerPort
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.HostIP != right.HostIP {
			return left.HostIP < right.HostIP
		}
		return left.HostPort < right.HostPort
	})

	if len(parsed) == 0 {
		return nil
	}

	return parsed
}

func parseDockerPortSpec(value string) (int, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, "", false
	}

	portString, protocol, ok := strings.Cut(value, "/")
	if !ok {
		return 0, "", false
	}

	port, err := strconv.Atoi(strings.TrimSpace(portString))
	if err != nil || port <= 0 || port > 65535 {
		return 0, "", false
	}

	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return 0, "", false
	}

	return port, protocol, true
}

func dockerContainerIDs(containers []dockerContainerSummary) []string {
	if len(containers) == 0 {
		return nil
	}

	ids := make([]string, 0, len(containers))
	for _, container := range containers {
		if id := strings.TrimSpace(container.ID); id != "" {
			ids = append(ids, id)
		}
	}

	return ids
}

func targetFromDockerContainer(container dockerContainerSummary, inspect dockerContainerInspect) (RuntimeTarget, bool) {
	if !dockerContainerEvaluable(container) {
		return RuntimeTarget{}, false
	}

	evidence, ok := detectXrayContainerEvidence(container, inspect)
	if !ok {
		return RuntimeTarget{}, false
	}

	commandLine := dockerCommandLine(container.Command)
	if inspectedCommandLine := inspect.commandLine(); len(inspectedCommandLine) != 0 {
		commandLine = inspectedCommandLine
	}
	binary := chooseDockerBinary(commandLine)
	target := RuntimeTarget{
		Source: DiscoverySourceDockerContainer,
		Identity: RuntimeIdentity{
			Name:   firstNonEmpty(container.Name, dockerImageRepositoryBase(container.Image), shortContainerID(container.ID)),
			Binary: binary,
		},
		DockerContainer: &DockerContainerCandidate{
			ID:          container.ID,
			Name:        container.Name,
			Image:       container.Image,
			CommandLine: commandLine,
			State:       container.State,
			Status:      container.Status,
			Labels:      cloneStringMap(inspect.Labels),
			ConfigPaths: dockerConfigPaths(commandLine, inspect.Mounts, binary),
		},
		Evidence: &evidence,
	}

	return target, true
}

func detectXrayContainer(container dockerContainerSummary) (DetectionEvidence, bool) {
	reasons := make([]string, 0, 2)
	confidence := DetectionConfidence("")

	if matchesDockerImage(container.Image) {
		repoBase := dockerImageRepositoryBase(container.Image)
		if matchesXrayFamilyBinary(repoBase) {
			reasons = append(reasons, fmt.Sprintf("container image %q matched xray family", repoBase))
			confidence = DetectionConfidenceHigh
		} else {
			reasons = append(reasons, fmt.Sprintf("container image %q contained an xray family marker", repoBase))
			confidence = DetectionConfidenceMedium
		}
	}

	if matchesDockerCommand(container.Command) {
		commandLine := dockerCommandLine(container.Command)
		reasons = append(reasons, fmt.Sprintf("container command %q matched xray family", normalizeBinaryBasename(commandLine[0])))
		confidence = DetectionConfidenceHigh
	}

	if len(reasons) == 0 {
		return DetectionEvidence{}, false
	}

	if confidence == "" {
		confidence = DetectionConfidenceMedium
	}

	return DetectionEvidence{
		Confidence: confidence,
		Reasons:    reasons,
	}, true
}

// xrayDefaultAPIPorts lists in-container ports that strongly suggest an Xray
// API listener. It is a slice so additional ports can be allowed later.
var xrayDefaultAPIPorts = []int{10085}

// detectXrayContainerEvidence combines the image/command signals with the
// richer container-inspect signals (labels and published API ports). Image and
// command matches are High, label matches are Medium, and port matches are Low;
// when multiple signals fire the highest confidence wins and all reasons are
// retained.
func detectXrayContainerEvidence(container dockerContainerSummary, inspect dockerContainerInspect) (DetectionEvidence, bool) {
	reasons := make([]string, 0, 4)
	confidence := DetectionConfidence("")

	if base, ok := detectXrayContainer(container); ok {
		reasons = append(reasons, base.Reasons...)
		confidence = higherDetectionConfidence(confidence, base.Confidence)
	}

	if reason, ok := detectXrayLabelSignal(inspect.Labels); ok {
		reasons = append(reasons, reason)
		confidence = higherDetectionConfidence(confidence, DetectionConfidenceMedium)
	}

	if reason, ok := detectXrayPortSignal(inspect.Ports); ok {
		reasons = append(reasons, reason)
		confidence = higherDetectionConfidence(confidence, DetectionConfidenceLow)
	}

	if len(reasons) == 0 {
		return DetectionEvidence{}, false
	}

	return DetectionEvidence{
		Confidence: confidence,
		Reasons:    reasons,
	}, true
}

// detectXrayLabelSignal reports the first container label whose value looks like
// an Xray-family runtime. Short identifier labels are prefix-matched; the
// descriptive image-title label is matched by substring.
func detectXrayLabelSignal(labels map[string]string) (string, bool) {
	if len(labels) == 0 {
		return "", false
	}

	rules := []struct {
		key       string
		substring bool
	}{
		{key: "app"},
		{key: "com.docker.compose.service", substring: true},
		{key: "org.opencontainers.image.title", substring: true},
	}

	for _, rule := range rules {
		value := strings.TrimSpace(labels[rule.key])
		if value == "" {
			continue
		}
		matched := matchesXrayFamilyBinary(value)
		if !matched && rule.substring {
			matched = containsXrayFamilyMarker(value)
		}
		if matched {
			return fmt.Sprintf("container label %s=%q matched xray family", rule.key, value), true
		}
	}

	return "", false
}

// detectXrayPortSignal reports whether a container publishes a known Xray API
// port (in-container or host side).
func detectXrayPortSignal(ports []dockerPortBinding) (string, bool) {
	for _, binding := range ports {
		if isXrayAPIPort(binding.ContainerPort) || isXrayAPIPort(binding.HostPort) {
			return fmt.Sprintf("container published Xray API port %d", binding.ContainerPort), true
		}
	}

	return "", false
}

func isXrayAPIPort(port int) bool {
	for _, candidate := range xrayDefaultAPIPorts {
		if port == candidate {
			return true
		}
	}

	return false
}

func detectionConfidenceRank(confidence DetectionConfidence) int {
	switch confidence {
	case DetectionConfidenceHigh:
		return 3
	case DetectionConfidenceMedium:
		return 2
	case DetectionConfidenceLow:
		return 1
	default:
		return 0
	}
}

func higherDetectionConfidence(current, candidate DetectionConfidence) DetectionConfidence {
	if detectionConfidenceRank(candidate) > detectionConfidenceRank(current) {
		return candidate
	}

	return current
}

// dockerContainerEvaluable reports whether a container should be evaluated for
// Xray detection (it has an ID and is not in a non-running state).
func dockerContainerEvaluable(container dockerContainerSummary) bool {
	if strings.TrimSpace(container.ID) == "" {
		return false
	}
	if container.State != "" && !strings.EqualFold(container.State, "running") {
		return false
	}

	return true
}

func (i dockerContainerInspect) commandLine() []string {
	if strings.TrimSpace(i.Path) == "" {
		return nil
	}

	commandLine := make([]string, 0, len(i.Args)+1)
	commandLine = append(commandLine, i.Path)
	commandLine = append(commandLine, i.Args...)
	return commandLine
}

func dockerConfigPaths(commandLine []string, mounts []dockerMount, binary string) []string {
	if len(mounts) == 0 {
		return nil
	}

	candidates := extractConfigPaths(commandLine)
	if len(candidates) == 0 {
		candidates = append(candidates, dockerDefaultConfigHints(binary)...)
	}

	paths := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if mapped, ok := mapDockerPathToHost(candidate, mounts); ok {
			if _, exists := seen[mapped]; exists {
				continue
			}
			seen[mapped] = struct{}{}
			paths = append(paths, mapped)
		}
	}

	if len(paths) == 0 {
		return nil
	}

	return paths
}

// dockerDefaultConfigHints derives candidate config paths from the detected
// binary name. The OS/arch release suffix and ".exe" are stripped to form the
// config directory, so "sanaei-linux-amd64" yields "/etc/sanaei/config.json".
// For vanilla "xray" (or an unknown binary) the hints are the historical
// /etc/xray and /usr/local/etc/xray paths.
func dockerDefaultConfigHints(binary string) []string {
	dir := dockerConfigDirName(binary)

	return []string{
		"/etc/" + dir + "/config.json",
		"/etc/" + dir,
		"/usr/local/etc/" + dir + "/config.json",
		"/usr/local/etc/" + dir,
	}
}

// dockerConfigDirName reduces a binary name to the config directory segment by
// taking its basename, dropping a ".exe" suffix, and trimming the
// "-<os>-<arch>[...]" release suffix. An empty result falls back to "xray".
func dockerConfigDirName(binary string) string {
	name := strings.TrimSpace(basenameOrEmpty(strings.TrimSpace(binary)))
	name = strings.TrimSuffix(name, ".exe")
	for _, marker := range []string{"-linux", "-darwin", "-windows"} {
		if index := strings.Index(name, marker); index > 0 {
			name = name[:index]
			break
		}
	}
	if name == "" {
		return "xray"
	}

	return name
}

func mapDockerPathToHost(containerPath string, mounts []dockerMount) (string, bool) {
	containerPath = filepath.Clean(strings.TrimSpace(containerPath))
	if containerPath == "" || containerPath == "." {
		return "", false
	}

	for _, mount := range mounts {
		destination := filepath.Clean(strings.TrimSpace(mount.Destination))
		source := filepath.Clean(strings.TrimSpace(mount.Source))
		if destination == "" || destination == "." || source == "" || source == "." {
			continue
		}

		if containerPath == destination {
			return source, true
		}
		if !strings.HasPrefix(containerPath, destination+string(filepath.Separator)) {
			continue
		}

		relative, err := filepath.Rel(destination, containerPath)
		if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
			continue
		}
		return filepath.Join(source, relative), true
	}

	return "", false
}

// matchesDockerImage reports whether a container image repository base looks
// like an Xray-family image. It uses a permissive case-insensitive substring
// match so fork images such as "my-xray-fork" are still surfaced; callers that
// need to distinguish a definitive family match apply matchesXrayFamilyBinary
// to the repository base directly.
func matchesDockerImage(image string) bool {
	return containsXrayFamilyMarker(dockerImageRepositoryBase(image))
}

// matchesDockerCommand reports whether a container command's entrypoint
// basename is an Xray-family binary using the shared prefix matcher.
func matchesDockerCommand(command string) bool {
	commandLine := dockerCommandLine(command)
	if len(commandLine) == 0 {
		return false
	}

	return matchesXrayFamilyBinary(commandLine[0])
}

func dockerImageRepositoryBase(image string) string {
	if image == "" {
		return ""
	}

	name := image
	if cut, _, ok := strings.Cut(name, "@"); ok {
		name = cut
	}

	lastSlash := strings.LastIndexByte(name, '/')
	lastColon := strings.LastIndexByte(name, ':')
	if lastColon > lastSlash {
		name = name[:lastColon]
	}

	return basenameOrEmpty(name)
}

func dockerCommandLine(command string) []string {
	command = normalizeDockerCommand(command)
	if command == "" {
		return nil
	}

	return strings.Fields(command)
}

func normalizeDockerCommand(command string) string {
	command = strings.TrimSpace(command)
	if len(command) >= 2 && command[0] == '"' && command[len(command)-1] == '"' {
		command = strings.Trim(command, `"`)
	}

	return strings.TrimSpace(command)
}

// chooseDockerBinary returns the runtime binary basename from the container's
// command line, or an empty string when the command line is unavailable. It
// deliberately does not guess a literal "xray" from the image: an unknown
// binary is left empty so a later runtime-config override can resolve it.
func chooseDockerBinary(commandLine []string) string {
	if len(commandLine) > 0 {
		if binary := basenameOrEmpty(commandLine[0]); binary != "" {
			return binary
		}
	}

	return ""
}

func shortContainerID(id string) string {
	if len(id) <= 12 {
		return id
	}

	return id[:12]
}

func isDockerUnavailableMessage(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "cannot connect to the docker daemon") ||
		strings.Contains(lower, "is the docker daemon running") ||
		strings.Contains(lower, "error during connect") ||
		strings.Contains(lower, "no such file or directory")
}

func classifyDockerCommandError(message string, err error) (ProviderError, bool) {
	switch {
	case isDockerPermissionDeniedMessage(message):
		return dockerPermissionDeniedIssue(err), true
	case isDockerUnavailableMessage(message):
		return dockerUnavailableIssue(err), true
	default:
		return ProviderError{}, false
	}
}

func dockerInspectIssue(err error) (ProviderError, bool) {
	var issue ProviderError
	if errors.As(err, &issue) {
		switch issue.Code {
		case ProviderErrorCodeNotInstalled, ProviderErrorCodeUnavailable, ProviderErrorCodePermissionDenied:
			issue.Code = ProviderErrorCodePartialAccess
			issue.Message = "Docker inspect metadata was unavailable for one or more container candidates."
			return issue, true
		}
	}

	return ProviderError{}, false
}

func dockerMetadataPartialIssue(err error) ProviderError {
	return ProviderError{
		Code:       ProviderErrorCodePartialAccess,
		Message:    "Docker inspect metadata was unavailable for one or more container candidates.",
		Hint:       "Verify Docker inspect access if container config hints are required.",
		Restricted: true,
		Err:        err,
	}
}

func isDockerPermissionDeniedMessage(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "permission denied while trying to connect to the docker") ||
		(strings.Contains(lower, "permission denied") &&
			(strings.Contains(lower, "docker.sock") ||
				strings.Contains(lower, "docker daemon") ||
				strings.Contains(lower, "docker api")))
}

// containerCLINotInstalledIssue reports that the configured container CLI was
// not found on PATH, naming the CLI so podman/nerdctl users get an accurate
// message.
func containerCLINotInstalledIssue(cli string, err error) ProviderError {
	cli = normalizeContainerCLI(cli)
	return ProviderError{
		Code:    ProviderErrorCodeNotInstalled,
		Message: fmt.Sprintf("%s CLI was not found.", cli),
		Hint:    fmt.Sprintf("Install %s if container discovery is required.", cli),
		Err:     err,
	}
}

// dockerNoMatchesIssue reports that running containers were scanned for Xray
// detection but none matched any signal.
func dockerNoMatchesIssue(scanned, matched int) ProviderError {
	return ProviderError{
		Code: ProviderErrorCodeNoMatches,
		Message: fmt.Sprintf(
			"Scanned %d running %s; %d matched Xray detection signals (image, command, labels, or API port).",
			scanned,
			pluralize(scanned, "container", "containers"),
			matched,
		),
		Hint: "If an Xray fork is running, override detection with --xray-binary or --container-cli, or publish the API port.",
	}
}

func dockerUnavailableIssue(err error) ProviderError {
	return ProviderError{
		Code:    ProviderErrorCodeUnavailable,
		Message: "Docker daemon is unavailable.",
		Hint:    "Start Docker or check the active Docker context.",
		Err:     err,
	}
}

func dockerPermissionDeniedIssue(err error) ProviderError {
	hint := "Verify access to the active Docker context and Docker socket."
	if !privilege.Current().IsRoot {
		hint = "Run RayLimit as root or add the current user to the docker group."
	}

	return ProviderError{
		Code:       ProviderErrorCodePermissionDenied,
		Message:    "Docker access was denied.",
		Hint:       hint,
		Restricted: true,
		Err:        err,
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}

	return cloned
}
