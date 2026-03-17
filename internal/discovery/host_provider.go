package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/PdYrust/RayLimit/internal/privilege"
)

const defaultProcRoot = "/proc"

// HostProvider discovers Xray candidates from the local host process table.
type HostProvider struct {
	procRoot string
}

// NewHostProvider returns the default host process discovery provider.
func NewHostProvider() HostProvider {
	return HostProvider{procRoot: defaultProcRoot}
}

// NewDefaultService returns the default discovery service used by the CLI.
func NewDefaultService() Service {
	return NewService(NewHostProvider(), NewDockerProvider())
}

func (p HostProvider) Name() string {
	return "host"
}

func (p HostProvider) Source() DiscoverySource {
	return DiscoverySourceHostProcess
}

func (p HostProvider) Discover(ctx context.Context, _ Request) (ProviderResult, error) {
	procRoot := p.procRoot
	if procRoot == "" {
		procRoot = defaultProcRoot
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return ProviderResult{}, fmt.Errorf("read process table: %w", err)
	}

	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return ProviderResult{}, err
		}

		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		pids = append(pids, pid)
	}

	sort.Ints(pids)

	targets := make([]RuntimeTarget, 0, len(pids))
	limitedEntries := 0
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return ProviderResult{}, err
		}

		snapshot := readProcessSnapshot(procRoot, pid)
		if snapshot.MetadataLimited {
			limitedEntries++
		}

		target, ok := targetFromProcessSnapshot(procRoot, snapshot)
		if !ok {
			continue
		}

		targets = append(targets, target)
	}

	result := ProviderResult{Targets: targets}
	if limitedEntries > 0 {
		result.Issues = append(result.Issues, hostMetadataAccessIssue(limitedEntries))
	}

	return result, nil
}

type processSnapshot struct {
	PID              int
	ProcessName      string
	ExecutablePath   string
	CommandLine      []string
	WorkingDirectory string
	ContainerID      string
	MetadataLimited  bool
}

func readProcessSnapshot(procRoot string, pid int) processSnapshot {
	processRoot := filepath.Join(procRoot, strconv.Itoa(pid))
	snapshot := processSnapshot{PID: pid}

	if data, err := os.ReadFile(filepath.Join(processRoot, "comm")); err == nil {
		snapshot.ProcessName = strings.TrimSpace(string(data))
	} else if markMetadataLimit(err) {
		snapshot.MetadataLimited = true
	}

	if data, err := os.ReadFile(filepath.Join(processRoot, "cmdline")); err == nil {
		snapshot.CommandLine = parseCommandLine(data)
	} else if markMetadataLimit(err) {
		snapshot.MetadataLimited = true
	}

	if target, err := os.Readlink(filepath.Join(processRoot, "exe")); err == nil {
		snapshot.ExecutablePath = target
	} else if markMetadataLimit(err) {
		snapshot.MetadataLimited = true
	}

	if target, err := os.Readlink(filepath.Join(processRoot, "cwd")); err == nil {
		snapshot.WorkingDirectory = target
	} else if markMetadataLimit(err) {
		snapshot.MetadataLimited = true
	}

	if data, err := os.ReadFile(filepath.Join(processRoot, "cgroup")); err == nil {
		snapshot.ContainerID = extractDockerContainerID(string(data))
	} else if markMetadataLimit(err) {
		snapshot.MetadataLimited = true
	}

	return snapshot
}

func markMetadataLimit(err error) bool {
	return err != nil && !errors.Is(err, os.ErrNotExist)
}

func hostMetadataAccessIssue(entryCount int) ProviderError {
	status := privilege.Current()
	hint := "Review procfs or ptrace restrictions for fuller host process visibility."
	if !status.IsRoot {
		hint = "Run RayLimit as root for fuller host process visibility."
	}

	return ProviderError{
		Code:       ProviderErrorCodePartialAccess,
		Message:    fmt.Sprintf("Host process metadata was partially unreadable for %d process %s.", entryCount, pluralize(entryCount, "entry", "entries")),
		Hint:       hint,
		Restricted: true,
	}
}

func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}

	return plural
}

func targetFromProcessSnapshot(procRoot string, snapshot processSnapshot) (RuntimeTarget, bool) {
	evidence, ok := detectXrayProcess(snapshot)
	if !ok {
		return RuntimeTarget{}, false
	}

	configPaths := extractConfigPaths(snapshot.CommandLine)

	target := RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{
			Name:   chooseProcessName(snapshot),
			Binary: chooseBinaryName(snapshot),
		},
		HostProcess: &HostProcessCandidate{
			PID:              snapshot.PID,
			ExecutablePath:   snapshot.ExecutablePath,
			CommandLine:      cloneStrings(snapshot.CommandLine),
			WorkingDirectory: snapshot.WorkingDirectory,
			ContainerID:      snapshot.ContainerID,
			ConfigPaths:      configPaths,
			ResolvedConfigPaths: resolveHostProcessConfigPaths(
				procRoot,
				snapshot,
				configPaths,
			),
		},
		Evidence: &evidence,
	}

	return target, true
}

func resolveHostProcessConfigPaths(procRoot string, snapshot processSnapshot, configPaths []string) []string {
	if len(configPaths) == 0 || snapshot.PID == 0 {
		return nil
	}
	if strings.TrimSpace(procRoot) == "" {
		procRoot = defaultProcRoot
	}

	processRoot := filepath.Join(procRoot, strconv.Itoa(snapshot.PID))
	resolved := make([]string, 0, len(configPaths))
	seen := make(map[string]struct{}, len(configPaths))

	appendResolved := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}

		seen[path] = struct{}{}
		resolved = append(resolved, path)
	}

	for _, configPath := range configPaths {
		configPath = filepath.Clean(strings.TrimSpace(configPath))
		if configPath == "" || configPath == "." {
			continue
		}

		if filepath.IsAbs(configPath) {
			appendResolved(filepath.Join(processRoot, "root", strings.TrimPrefix(configPath, string(filepath.Separator))))
			continue
		}

		if snapshot.WorkingDirectory != "" {
			appendResolved(filepath.Join(snapshot.WorkingDirectory, configPath))
			continue
		}

		appendResolved(filepath.Join(processRoot, "cwd", configPath))
	}

	if len(resolved) == 0 {
		return nil
	}

	return resolved
}

func detectXrayProcess(snapshot processSnapshot) (DetectionEvidence, bool) {
	reasons := make([]string, 0, 3)
	confidence := DetectionConfidence("")

	if matchesExactBinaryName(snapshot.ExecutablePath) {
		reasons = append(reasons, "executable name matched xray")
		confidence = DetectionConfidenceHigh
	}

	if len(snapshot.CommandLine) > 0 && matchesExactBinaryName(snapshot.CommandLine[0]) {
		reasons = append(reasons, "command name matched xray")
		confidence = DetectionConfidenceHigh
	}

	if snapshot.ProcessName == "xray" {
		reasons = append(reasons, "process name matched xray")
		if confidence == "" {
			confidence = DetectionConfidenceMedium
		}
	}

	if len(reasons) == 0 {
		return DetectionEvidence{}, false
	}

	return DetectionEvidence{
		Confidence: confidence,
		Reasons:    reasons,
	}, true
}

func matchesExactBinaryName(value string) bool {
	return basenameOrEmpty(value) == "xray"
}

func chooseProcessName(snapshot processSnapshot) string {
	return firstNonEmpty(snapshot.ProcessName, basenameOrEmpty(snapshot.ExecutablePath), basenameOrEmpty(firstCommand(snapshot.CommandLine)))
}

func chooseBinaryName(snapshot processSnapshot) string {
	return firstNonEmpty(basenameOrEmpty(snapshot.ExecutablePath), basenameOrEmpty(firstCommand(snapshot.CommandLine)), snapshot.ProcessName)
}

func firstCommand(commandLine []string) string {
	if len(commandLine) == 0 {
		return ""
	}

	return commandLine[0]
}

func parseCommandLine(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	parts := bytes.Split(data, []byte{0})
	commandLine := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}

		commandLine = append(commandLine, string(part))
	}

	if len(commandLine) == 0 {
		return nil
	}

	return commandLine
}

func extractConfigPaths(commandLine []string) []string {
	if len(commandLine) == 0 {
		return nil
	}

	paths := make([]string, 0)
	seen := make(map[string]struct{})

	appendPath := func(path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}

		seen[path] = struct{}{}
		paths = append(paths, path)
	}

	for index := 0; index < len(commandLine); index++ {
		argument := commandLine[index]

		switch {
		case argument == "-config" || argument == "-c" || argument == "-confdir":
			if index+1 < len(commandLine) {
				appendPath(commandLine[index+1])
				index++
			}
		case strings.HasPrefix(argument, "-config="):
			appendPath(strings.TrimPrefix(argument, "-config="))
		case strings.HasPrefix(argument, "-c="):
			appendPath(strings.TrimPrefix(argument, "-c="))
		case strings.HasPrefix(argument, "-confdir="):
			appendPath(strings.TrimPrefix(argument, "-confdir="))
		}
	}

	if len(paths) == 0 {
		return nil
	}

	return paths
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func extractDockerContainerID(cgroup string) string {
	lines := strings.Split(cgroup, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}

		id := dockerContainerIDFromPath(fields[2])
		if id != "" {
			return id
		}
	}

	return ""
}

func dockerContainerIDFromPath(path string) string {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '.' || r == '-' || r == '_'
	}) {
		part = strings.TrimSpace(part)
		if len(part) != 64 {
			continue
		}
		if isLowerHexString(part) {
			return part
		}
	}

	return ""
}

func isLowerHexString(value string) bool {
	if value == "" {
		return false
	}

	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}

	return true
}

func basenameOrEmpty(value string) string {
	if value == "" {
		return ""
	}

	return filepath.Base(value)
}
