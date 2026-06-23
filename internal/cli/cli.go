package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/PdYrust/RayLimit/internal/buildinfo"
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

type sessionEvidenceProvider interface {
	ObserveSessions(ctx context.Context, runtime discovery.SessionRuntime) (discovery.SessionEvidenceResult, error)
}

type App struct {
	discovery        discoveryService
	limiterPlanner   tcPlanner
	tcInspector      tcStateInspector
	nftInspector     nftablesStateInspector
	tcRunner         tc.Runner
	inboundSelector  inboundMarkSelectorDeriver
	outboundSelector outboundMarkSelectorDeriver
	sessionEvidence  sessionEvidenceProvider
	privilegeStatus  func() privilege.Status
	logging          loggingModel
	overrides        cliOverrides
}

// cliOverrides holds the runtime-binary override knobs. Fields are empty
// unless set by a global flag or, after resolveOverrides, by their RAYLIMIT_*
// environment variable.
type cliOverrides struct {
	xrayBinary   string
	containerCLI string
	tcBinary     string
	nftBinary    string
	logLevel     string
}

type command struct {
	name        string
	summary     string
	usage       string
	description string
	category    commandCategory
	help        func(w io.Writer)
	run         func(ctx context.Context, args []string, streams commandIO) int
}

// commandCategory groups commands in the root help output so the listing is
// derived from a.commands() rather than duplicated hardcoded name lists.
type commandCategory string

const (
	commandCategoryCore        commandCategory = "core"
	commandCategoryInformation commandCategory = "information"
)

// Run executes the RayLimit CLI and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	flagOverrides, remaining, err := splitGlobalOverrides(args)
	if err != nil {
		return writeRootUsageError(stderr, "%s", err.Error())
	}

	return newAppWithOverrides(resolveOverrides(flagOverrides)).Run(remaining, stdout, stderr)
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

// newAppWithOverrides builds an App whose default discovery service and lazy
// accessors honor the resolved runtime-binary overrides.
func newAppWithOverrides(overrides cliOverrides) App {
	return App{
		discovery: discovery.NewDefaultServiceWithContainerCLI(overrides.containerCLI),
		logging:   currentLoggingModel(),
		overrides: overrides,
	}
}

// splitGlobalOverrides consumes the leading global override flags (which must
// precede the subcommand) and returns their values plus the remaining args.
func splitGlobalOverrides(args []string) (cliOverrides, []string, error) {
	overrides := cliOverrides{}
	index := 0
	for index < len(args) {
		arg := args[index]
		if !isFlag(arg) {
			break
		}

		name, inlineValue, hasInline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		target, ok := globalOverrideTarget(&overrides, name)
		if !ok {
			break
		}

		if hasInline {
			*target = inlineValue
			index++
			continue
		}
		if index+1 >= len(args) {
			return cliOverrides{}, nil, fmt.Errorf("flag %s needs a value", arg)
		}
		*target = args[index+1]
		index += 2
	}

	return overrides, args[index:], nil
}

func globalOverrideTarget(overrides *cliOverrides, name string) (*string, bool) {
	switch name {
	case "xray-binary":
		return &overrides.xrayBinary, true
	case "container-cli":
		return &overrides.containerCLI, true
	case "tc-binary":
		return &overrides.tcBinary, true
	case "nft-binary":
		return &overrides.nftBinary, true
	case "log-level":
		return &overrides.logLevel, true
	default:
		return nil, false
	}
}

// resolveOverrides applies the RAYLIMIT_* environment fallbacks for any
// override that was not supplied by a flag. Flags win; env vars are consulted
// with LookupEnv so an explicitly empty value is honored as "use detection".
func resolveOverrides(flagOverrides cliOverrides) cliOverrides {
	resolved := flagOverrides
	if resolved.xrayBinary == "" {
		if value, ok := os.LookupEnv("RAYLIMIT_XRAY_BINARY"); ok {
			resolved.xrayBinary = value
		}
	}
	if resolved.containerCLI == "" {
		if value, ok := os.LookupEnv("RAYLIMIT_CONTAINER_CLI"); ok {
			resolved.containerCLI = value
		}
	}
	if resolved.tcBinary == "" {
		if value, ok := os.LookupEnv("RAYLIMIT_TC_BINARY"); ok {
			resolved.tcBinary = value
		}
	}
	if resolved.nftBinary == "" {
		if value, ok := os.LookupEnv("RAYLIMIT_NFT_BINARY"); ok {
			resolved.nftBinary = value
		}
	}
	if resolved.logLevel == "" {
		if value, ok := os.LookupEnv("RAYLIMIT_LOG_LEVEL"); ok {
			resolved.logLevel = value
		}
	}

	return resolved
}

// parseLogLevel maps an operator-facing diagnostic verbosity name to a logLevel.
func parseLogLevel(value string) (logLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error":
		return logLevelError, true
	case "warn", "warning":
		return logLevelWarn, true
	case "info":
		return logLevelInfo, true
	case "debug":
		return logLevelDebug, true
	default:
		return "", false
	}
}

// Run executes the configured app and returns a process exit code.
func (a App) Run(args []string, stdout, stderr io.Writer) int {
	// Install a signal-aware context so Ctrl+C / SIGTERM cancel in-flight work.
	// The runner and discovery exec calls already honor context cancellation, so
	// orphaned children (docker exec, xray api, tc) are torn down instead of
	// being left to half-apply tc state.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return a.runWithContext(ctx, args, stdout, stderr)
}

func (a App) runWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	commands := a.commands()
	streams := newCommandIO(stdout, stderr, a.logging)
	if level := strings.TrimSpace(a.overrides.logLevel); level != "" {
		parsed, ok := parseLogLevel(level)
		if !ok {
			return writeRootUsageError(streams.stderr, "unsupported log level %q (expected error, warn, info, or debug)", level)
		}
		streams = streams.withDiagnosticLevel(parsed)
	}

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

	return cmd.run(ctx, subArgs, streams)
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
		category:    commandCategoryInformation,
	}

	cmd.run = func(ctx context.Context, args []string, streams commandIO) int {
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

// commandsInCategory returns the commands in one help category, preserving the
// order in which a.commands() declares them.
func commandsInCategory(commands []command, category commandCategory) []command {
	matches := make([]command, 0, len(commands))
	for _, cmd := range commands {
		if cmd.category == category {
			matches = append(matches, cmd)
		}
	}

	return matches
}

// errTrackingWriter records the first write error encountered while rendering
// result output, so callers can fail loudly (for example when stdout is a
// closed pipe) instead of silently exiting 0.
type errTrackingWriter struct {
	w   io.Writer
	err error
}

func (e *errTrackingWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}

	return n, err
}

func writeRootHelp(w io.Writer, commands []command) {
	_, _ = fmt.Fprintf(w, "Usage:\n  %s <command> [arguments]\n\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "%s\n", buildinfo.ProductName)
	_, _ = fmt.Fprintf(w, "%s\n\n", buildinfo.ProductTagline)

	_, _ = io.WriteString(w, "Core commands:\n")
	for _, cmd := range commandsInCategory(commands, commandCategoryCore) {
		_, _ = fmt.Fprintf(w, "  %-9s %s\n", cmd.name, cmd.summary)
	}
	_, _ = io.WriteString(w, "\nInformation:\n")
	for _, cmd := range commandsInCategory(commands, commandCategoryInformation) {
		_, _ = fmt.Fprintf(w, "  %-9s %s\n", cmd.name, cmd.summary)
	}
	_, _ = io.WriteString(w, "  help      Show command help\n\n")
	_, _ = io.WriteString(w, "Quick start:\n")
	_, _ = fmt.Fprintf(w, "  %s discover\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s inspect --pid 4242\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip 203.0.113.4 --device eth0 --direction upload --rate 1048576\n\n", buildinfo.BinaryName)
	_, _ = io.WriteString(w, "Global options:\n")
	_, _ = io.WriteString(w, "  -h, -help, --help      Show command help\n")
	_, _ = io.WriteString(w, "  -version, --version    Print brief version information\n")
	_, _ = io.WriteString(w, "\nGlobal overrides (place before the command; flag wins over env var):\n")
	_, _ = io.WriteString(w, "  --xray-binary <path>     Override the Xray binary path/name (env RAYLIMIT_XRAY_BINARY)\n")
	_, _ = io.WriteString(w, "  --container-cli <name>   Container CLI for discovery and queries (env RAYLIMIT_CONTAINER_CLI; default docker; supports podman, nerdctl)\n")
	_, _ = io.WriteString(w, "  --tc-binary <path>       Override the tc binary path (env RAYLIMIT_TC_BINARY)\n")
	_, _ = io.WriteString(w, "  --nft-binary <path>      Override the nft binary path (env RAYLIMIT_NFT_BINARY)\n")
	_, _ = io.WriteString(w, "  --log-level <level>      Diagnostic verbosity: error|warn|info|debug (env RAYLIMIT_LOG_LEVEL; default error)\n\n")
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
	case "help", "-h", "-help", "--help":
		return true
	default:
		return false
	}
}

func isFlag(arg string) bool {
	return len(arg) > 0 && arg[0] == '-'
}

// envFlagEnabled reports whether a boolean-style environment variable is set to
// a truthy value.
func envFlagEnabled(name string) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
