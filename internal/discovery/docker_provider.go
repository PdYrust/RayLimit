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
	listContainers    dockerListFunc
	inspectContainers dockerInspectFunc
}

// NewDockerProvider returns the default Docker discovery provider.
func NewDockerProvider() DockerProvider {
	return DockerProvider{
		listContainers:    listDockerContainers,
		inspectContainers: inspectDockerContainers,
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
		listContainers = listDockerContainers
	}
	inspectContainers := p.inspectContainers
	if inspectContainers == nil {
		inspectContainers = inspectDockerContainers
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
	for _, container := range containers {
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

	return result, nil
}

func listDockerContainers(ctx context.Context) ([]dockerContainerSummary, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, dockerNotInstalledIssue(err)
	}

	cmd := exec.CommandContext(
		ctx,
		"docker",
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

func inspectDockerContainers(ctx context.Context, ids []string) (map[string]dockerContainerInspect, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, dockerNotInstalledIssue(err)
	}

	args := append([]string{"inspect"}, ids...)
	cmd := exec.CommandContext(ctx, "docker", args...)

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
	if strings.TrimSpace(container.ID) == "" {
		return RuntimeTarget{}, false
	}
	if container.State != "" && !strings.EqualFold(container.State, "running") {
		return RuntimeTarget{}, false
	}

	evidence, ok := detectXrayContainer(container)
	if !ok {
		return RuntimeTarget{}, false
	}

	commandLine := dockerCommandLine(container.Command)
	if inspectedCommandLine := inspect.commandLine(); len(inspectedCommandLine) != 0 {
		commandLine = inspectedCommandLine
	}
	target := RuntimeTarget{
		Source: DiscoverySourceDockerContainer,
		Identity: RuntimeIdentity{
			Name:   firstNonEmpty(container.Name, dockerImageRepositoryBase(container.Image), shortContainerID(container.ID)),
			Binary: chooseDockerBinary(container, commandLine),
		},
		DockerContainer: &DockerContainerCandidate{
			ID:          container.ID,
			Name:        container.Name,
			Image:       container.Image,
			CommandLine: commandLine,
			State:       container.State,
			Status:      container.Status,
			Labels:      cloneStringMap(inspect.Labels),
			ConfigPaths: dockerConfigPaths(commandLine, inspect.Mounts),
		},
		Evidence: &evidence,
	}

	return target, true
}

func detectXrayContainer(container dockerContainerSummary) (DetectionEvidence, bool) {
	reasons := make([]string, 0, 2)
	confidence := DetectionConfidence("")

	if matchesDockerImage(container.Image) {
		reasons = append(reasons, "container image matched xray")
		confidence = DetectionConfidenceHigh
	}

	if matchesDockerCommand(container.Command) {
		reasons = append(reasons, "container command matched xray")
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

func (i dockerContainerInspect) commandLine() []string {
	if strings.TrimSpace(i.Path) == "" {
		return nil
	}

	commandLine := make([]string, 0, len(i.Args)+1)
	commandLine = append(commandLine, i.Path)
	commandLine = append(commandLine, i.Args...)
	return commandLine
}

func dockerConfigPaths(commandLine []string, mounts []dockerMount) []string {
	if len(mounts) == 0 {
		return nil
	}

	candidates := extractConfigPaths(commandLine)
	if len(candidates) == 0 {
		candidates = append(candidates, dockerDefaultConfigHints()...)
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

func dockerDefaultConfigHints() []string {
	return []string{
		"/etc/xray/config.json",
		"/etc/xray",
		"/usr/local/etc/xray/config.json",
		"/usr/local/etc/xray",
	}
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

func matchesDockerImage(image string) bool {
	switch dockerImageRepositoryBase(image) {
	case "xray", "xray-core":
		return true
	default:
		return false
	}
}

func matchesDockerCommand(command string) bool {
	commandLine := dockerCommandLine(command)
	if len(commandLine) == 0 {
		return false
	}

	return basenameOrEmpty(commandLine[0]) == "xray"
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

func chooseDockerBinary(container dockerContainerSummary, commandLine []string) string {
	if len(commandLine) > 0 {
		if binary := basenameOrEmpty(commandLine[0]); binary != "" {
			return binary
		}
	}

	switch dockerImageRepositoryBase(container.Image) {
	case "xray", "xray-core":
		return "xray"
	default:
		return ""
	}
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

func dockerNotInstalledIssue(err error) ProviderError {
	return ProviderError{
		Code:    ProviderErrorCodeNotInstalled,
		Message: "Docker CLI was not found.",
		Hint:    "Install Docker if container discovery is required.",
		Err:     err,
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
