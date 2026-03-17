package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/PdYrust/RayLimit/internal/buildinfo"
	"github.com/PdYrust/RayLimit/internal/discovery"
)

type inspectSelection struct {
	Source    discovery.DiscoverySource
	Name      string
	PID       int
	Container string
	All       bool
}

func (s inspectSelection) Active() bool {
	return s.Source != "" || s.Name != "" || s.PID != 0 || s.Container != ""
}

func (s inspectSelection) Validate() error {
	if s.Source != "" && !s.Source.Valid() {
		return fmt.Errorf("unsupported discovery source %q", s.Source)
	}
	if s.PID < 0 {
		return fmt.Errorf("pid must be greater than zero when provided")
	}
	if s.PID == 0 && strings.TrimSpace(s.Container) == "" && strings.TrimSpace(s.Name) == "" {
		return nil
	}
	if s.PID != 0 && s.Container != "" {
		return fmt.Errorf("cannot combine --pid and --container")
	}
	if s.Source == discovery.DiscoverySourceDockerContainer && s.PID != 0 {
		return fmt.Errorf("--pid cannot be used with --source=%s", s.Source)
	}
	if s.Source == discovery.DiscoverySourceHostProcess && s.Container != "" {
		return fmt.Errorf("--container cannot be used with --source=%s", s.Source)
	}

	return nil
}

func (s inspectSelection) matches(target discovery.RuntimeTarget) bool {
	if s.Source != "" && target.Source != s.Source {
		return false
	}
	if s.Name != "" && target.Identity.Name != s.Name {
		return false
	}
	if s.PID != 0 {
		if target.HostProcess == nil || target.HostProcess.PID != s.PID {
			return false
		}
	}
	if s.Container != "" {
		if target.DockerContainer == nil {
			return false
		}

		selector := strings.TrimSpace(s.Container)
		if selector == "" {
			return false
		}

		id := target.DockerContainer.ID
		name := target.DockerContainer.Name
		if name != selector && id != selector && !strings.HasPrefix(id, selector) {
			return false
		}
	}

	return true
}

func (a App) newInspectCommand() command {
	cmd := command{
		name:        "inspect",
		summary:     "Inspect runtime metadata and API hints",
		usage:       buildinfo.BinaryName + " inspect [--format text|json] [--source host_process|docker_container] [--name <name>] [--pid <pid>] [--container <id-or-name>] [--all]",
		description: "Inspect discovered Xray runtime metadata and API capability hints using local discovery results only.",
	}

	cmd.help = func(w io.Writer) {
		writeInspectHelp(w, cmd)
	}

	cmd.run = func(args []string, streams commandIO) int {
		return a.runInspect(args, streams, cmd)
	}

	return cmd
}

func (a App) runInspect(args []string, streams commandIO, cmd command) int {
	flags := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	outputFormat := string(discovery.OutputFormatText)
	source := ""
	name := ""
	container := ""
	pid := 0
	all := false

	flags.StringVar(&outputFormat, "format", outputFormat, "output format")
	flags.StringVar(&source, "source", source, "discovery source")
	flags.StringVar(&name, "name", name, "runtime name")
	flags.IntVar(&pid, "pid", pid, "host process ID")
	flags.StringVar(&container, "container", container, "docker container name or ID prefix")
	flags.BoolVar(&all, "all", all, "inspect all matching targets")

	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			writeCommandHelp(streams.stdout, cmd)
			return exitCodeSuccess
		}

		return writeCommandUsageError(streams.stderr, cmd, err.Error())
	}

	if flags.NArg() != 0 {
		return writeCommandUsageError(streams.stderr, cmd, "unexpected arguments: %v", flags.Args())
	}

	format := discovery.OutputFormat(outputFormat)
	if !format.Valid() {
		return writeCommandUsageError(streams.stderr, cmd, "unsupported output format %q", outputFormat)
	}

	selection := inspectSelection{
		Source:    discovery.DiscoverySource(source),
		Name:      strings.TrimSpace(name),
		PID:       pid,
		Container: strings.TrimSpace(container),
		All:       all,
	}
	if err := selection.Validate(); err != nil {
		return writeCommandUsageError(streams.stderr, cmd, err.Error())
	}

	result, err := a.discovery.Discover(context.Background(), discovery.Request{})
	if err != nil {
		streams.diag.Errorf(logPhaseDiscovery, "inspection failed during discovery: %s", err)
		return exitCodeFailure
	}

	selectedTargets := filterInspectionTargets(result.Targets, selection)
	inspection := discovery.Result{
		Targets:        selectedTargets,
		ProviderErrors: result.ProviderErrors,
	}

	if len(selectedTargets) == 0 {
		if err := discovery.WriteInspection(streams.stdout, format, inspection, selection.Active()); err != nil {
			streams.diag.Errorf(logPhaseOutput, "failed to render inspection result: %s", err)
			return exitCodeFailure
		}

		if result.HasFatalErrors() {
			return exitCodeFailure
		}
		if selection.Active() {
			return exitCodeFailure
		}

		return exitCodeSuccess
	}

	if len(selectedTargets) > 1 && !selection.All {
		streams.diag.Errorw(
			logPhaseSelection,
			"multiple runtime targets matched; refine the selection or use --all",
			intLogField("count", len(selectedTargets)),
		)
		return exitCodeFailure
	}

	if len(selectedTargets) > 0 {
		enrichedTargets, err := discovery.NewAPICapabilityDetector().EnrichTargets(context.Background(), selectedTargets)
		if err != nil {
			streams.diag.Errorf(logPhaseDiscovery, "inspection failed during API capability detection: %s", err)
			return exitCodeFailure
		}

		inspection.Targets = enrichedTargets
	}

	if err := discovery.WriteInspection(streams.stdout, format, inspection, selection.Active()); err != nil {
		streams.diag.Errorf(logPhaseOutput, "failed to render inspection result: %s", err)
		return exitCodeFailure
	}

	if result.HasFatalErrors() {
		return exitCodeFailure
	}

	return exitCodeSuccess
}

func filterInspectionTargets(targets []discovery.RuntimeTarget, selection inspectSelection) []discovery.RuntimeTarget {
	if len(targets) == 0 {
		return nil
	}
	if !selection.Active() {
		return cloneTargets(targets)
	}

	filtered := make([]discovery.RuntimeTarget, 0, len(targets))
	for _, target := range targets {
		if selection.matches(target) {
			filtered = append(filtered, target)
		}
	}

	if len(filtered) == 0 {
		return nil
	}

	return filtered
}

func cloneTargets(targets []discovery.RuntimeTarget) []discovery.RuntimeTarget {
	cloned := make([]discovery.RuntimeTarget, len(targets))
	copy(cloned, targets)
	return cloned
}

func writeInspectHelp(w io.Writer, cmd command) {
	_, _ = fmt.Fprintf(w, "Usage:\n  %s\n\n", cmd.usage)
	_, _ = fmt.Fprintf(w, "%s\n\n", cmd.description)
	_, _ = io.WriteString(w, "Options:\n")
	_, _ = io.WriteString(w, "  --format text|json                Render as text or machine-readable JSON (default: text)\n")
	_, _ = io.WriteString(w, "  --source host_process|docker_container\n")
	_, _ = io.WriteString(w, "                                   Restrict inspection to one discovery source\n")
	_, _ = io.WriteString(w, "  --name <name>                     Match a discovered runtime name\n")
	_, _ = io.WriteString(w, "  --pid <pid>                       Match one host-process runtime by PID\n")
	_, _ = io.WriteString(w, "  --container <id-or-name>          Match one Docker runtime by container name or ID prefix\n")
	_, _ = io.WriteString(w, "  --all                             Inspect every matching target instead of requiring one match\n")
	_, _ = io.WriteString(w, "\nExamples:\n")
	_, _ = fmt.Fprintf(w, "  %s inspect\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s inspect --pid 4242\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s inspect --container raylimit-xray-test --format json\n", buildinfo.BinaryName)
}
