package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/PdYrust/RayLimit/internal/buildinfo"
	"github.com/PdYrust/RayLimit/internal/correlation"
	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/privilege"
	"github.com/PdYrust/RayLimit/internal/tc"
)

const (
	exitCodeSuccess = 0
	exitCodeFailure = 1
	exitCodeUsage   = 2
)

type discoveryService interface {
	Discover(reqCtx context.Context, req discovery.Request) (discovery.Result, error)
}

type tcPlanner interface {
	Plan(action limiter.Action, scope tc.Scope) (tc.Plan, error)
	PlanUUIDAggregate(input tc.UUIDAggregatePlanInput) (tc.UUIDAggregatePlan, error)
}

type tcStateInspector interface {
	Inspect(ctx context.Context, req tc.InspectRequest) (tc.Snapshot, []tc.Result, error)
}

type nftablesStateInspector interface {
	Inspect(ctx context.Context) (tc.NftablesSnapshot, []tc.Result, error)
}

type inboundMarkSelectorDeriver interface {
	Derive(ctx context.Context, target discovery.RuntimeTarget, inboundTag string) (discovery.InboundMarkSelectorResult, error)
}

type outboundMarkSelectorDeriver interface {
	Derive(ctx context.Context, target discovery.RuntimeTarget, outboundTag string) (discovery.OutboundMarkSelectorResult, error)
}

type uuidNonIPBackendCandidateDeriver interface {
	Derive(ctx context.Context, target discovery.RuntimeTarget, uuid string) (discovery.UUIDNonIPBackendCandidate, error)
}

type uuidRoutingEvidenceProvider interface {
	ObserveUUIDRoutingEvidence(ctx context.Context, runtime discovery.SessionRuntime, uuid string) (discovery.UUIDRoutingEvidenceResult, error)
}

type uuidCorrelator interface {
	Correlate(ctx context.Context, req correlation.UUIDRequest) (correlation.UUIDResult, error)
}

type App struct {
	discovery           discoveryService
	limiterPlanner      tcPlanner
	tcInspector         tcStateInspector
	nftInspector        nftablesStateInspector
	tcRunner            tc.Runner
	uuidCorrelator      uuidCorrelator
	inboundSelector     inboundMarkSelectorDeriver
	outboundSelector    outboundMarkSelectorDeriver
	uuidNonIPBackend    uuidNonIPBackendCandidateDeriver
	uuidRoutingEvidence uuidRoutingEvidenceProvider
	privilegeStatus     func() privilege.Status
	logging             loggingModel
}

type command struct {
	name        string
	summary     string
	usage       string
	description string
	help        func(w io.Writer)
	run         func(args []string, streams commandIO) int
}

// Run executes the RayLimit CLI and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return NewApp(nil).Run(args, stdout, stderr)
}

func NewApp(discoverySvc discoveryService) App {
	if discoverySvc == nil {
		discoverySvc = discovery.NewDefaultService()
	}

	return App{
		discovery: discoverySvc,
		logging:   currentLoggingModel(),
	}
}

// Run executes the configured app and returns a process exit code.
func (a App) Run(args []string, stdout, stderr io.Writer) int {
	commands := a.commands()
	streams := newCommandIO(stdout, stderr, a.logging)

	if len(args) == 0 {
		writeRootHelp(streams.stdout, commands)
		return exitCodeSuccess
	}

	switch args[0] {
	case "-h", "-help", "--help":
		writeRootHelp(streams.stdout, commands)
		return exitCodeSuccess
	case "-version", "--version":
		if len(args) != 1 {
			return writeRootUsageError(streams.stderr, "version flags do not accept additional arguments")
		}

		_, _ = io.WriteString(streams.stdout, buildinfo.Summary()+"\n")
		return exitCodeSuccess
	case "help":
		return runHelp(commands, args[1:], streams.stdout, streams.stderr)
	}

	if isFlag(args[0]) {
		return writeRootUsageError(streams.stderr, "unknown flag %q", args[0])
	}

	cmd, ok := lookupCommand(commands, args[0])
	if !ok {
		return writeRootUsageError(streams.stderr, "unknown command %q", args[0])
	}

	subArgs := args[1:]
	if len(subArgs) == 1 && isHelpToken(subArgs[0]) {
		writeCommandHelp(streams.stdout, cmd)
		return exitCodeSuccess
	}

	return cmd.run(subArgs, streams)
}

func (a App) commands() []command {
	return []command{
		a.newLimitCommand(),
		a.newDiscoverCommand(),
		a.newInspectCommand(),
		newVersionCommand(),
	}
}

func newVersionCommand() command {
	cmd := command{
		name:        "version",
		summary:     "Show version, build, and project metadata",
		usage:       buildinfo.BinaryName + " version",
		description: "Show version, build, and project metadata for the current RayLimit binary.",
	}

	cmd.run = func(args []string, streams commandIO) int {
		if len(args) != 0 {
			return writeCommandUsageError(streams.stderr, cmd, "command %q does not accept arguments", cmd.name)
		}

		_, _ = io.WriteString(streams.stdout, buildinfo.Details())
		return exitCodeSuccess
	}

	return cmd
}

func runHelp(commands []command, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeRootHelp(stdout, commands)
		return exitCodeSuccess
	}

	if len(args) > 1 {
		return writeRootUsageError(stderr, "help accepts at most one command name")
	}

	cmd, ok := lookupCommand(commands, args[0])
	if !ok {
		return writeRootUsageError(stderr, "unknown help topic %q", args[0])
	}

	writeCommandHelp(stdout, cmd)
	return exitCodeSuccess
}

func lookupCommand(commands []command, name string) (command, bool) {
	for _, cmd := range commands {
		if cmd.name == name {
			return cmd, true
		}
	}

	return command{}, false
}

func writeRootHelp(w io.Writer, commands []command) {
	_, _ = fmt.Fprintf(w, "Usage:\n  %s <command> [arguments]\n\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "%s\n", buildinfo.ProductName)
	_, _ = fmt.Fprintf(w, "%s\n\n", buildinfo.ProductTagline)

	_, _ = io.WriteString(w, "Core commands:\n")
	for _, name := range []string{"limit", "discover", "inspect"} {
		if cmd, ok := lookupCommand(commands, name); ok {
			_, _ = fmt.Fprintf(w, "  %-9s %s\n", cmd.name, cmd.summary)
		}
	}
	_, _ = io.WriteString(w, "\nInformation:\n")
	for _, name := range []string{"version"} {
		if cmd, ok := lookupCommand(commands, name); ok {
			_, _ = fmt.Fprintf(w, "  %-9s %s\n", cmd.name, cmd.summary)
		}
	}
	_, _ = io.WriteString(w, "  help      Show command help\n\n")
	_, _ = io.WriteString(w, "Quick start:\n")
	_, _ = fmt.Fprintf(w, "  %s discover\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s inspect --pid 4242\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip 203.0.113.4 --device eth0 --direction upload --rate 1048576\n\n", buildinfo.BinaryName)
	_, _ = io.WriteString(w, "Global options:\n")
	_, _ = io.WriteString(w, "  -h, -help, --help      Show command help\n")
	_, _ = io.WriteString(w, "  -version, --version    Print brief version information\n\n")
	_, _ = io.WriteString(w, "Project:\n")
	_, _ = fmt.Fprintf(w, "  creator     %s\n", buildinfo.CreatorName)
	_, _ = fmt.Fprintf(w, "  repository  %s\n", buildinfo.RepositoryURL)
	_, _ = fmt.Fprintf(w, "  telegram    %s\n\n", buildinfo.TelegramChannelURL)
	_, _ = fmt.Fprintf(w, "Run %q for command-specific help.\n", buildinfo.BinaryName+" help <command>")
}

func writeCommandHelp(w io.Writer, cmd command) {
	if cmd.help != nil {
		cmd.help(w)
		return
	}

	_, _ = fmt.Fprintf(w, "Usage:\n  %s\n\n", cmd.usage)
	_, _ = fmt.Fprintf(w, "%s\n", cmd.description)
}

func writeRootUsageError(w io.Writer, format string, args ...any) int {
	writeValidationError(w, format, args...)
	_, _ = fmt.Fprintf(w, "Run %q for usage.\n", buildinfo.BinaryName+" help")
	return exitCodeUsage
}

func writeCommandUsageError(w io.Writer, cmd command, format string, args ...any) int {
	writeCommandHelp(w, cmd)
	_, _ = io.WriteString(w, "\n")
	writeValidationError(w, format, args...)
	return exitCodeUsage
}

func writeValidationError(w io.Writer, format string, args ...any) {
	writeDiagnostic(w, logLevelError, logPhaseValidation, fmt.Sprintf(format, args...))
}

func isHelpToken(arg string) bool {
	switch arg {
	case "-h", "-help", "--help":
		return true
	default:
		return false
	}
}

func isFlag(arg string) bool {
	return len(arg) > 0 && arg[0] == '-'
}
