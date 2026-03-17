package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/PdYrust/RayLimit/internal/buildinfo"
	"github.com/PdYrust/RayLimit/internal/discovery"
)

func (a App) newDiscoverCommand() command {
	cmd := command{
		name:        "discover",
		summary:     "Discover Xray runtime targets",
		usage:       buildinfo.BinaryName + " discover [--format text|json]",
		description: "Discover Xray runtime targets through the configured discovery service.",
	}

	cmd.help = func(w io.Writer) {
		writeDiscoverHelp(w, cmd)
	}

	cmd.run = func(args []string, streams commandIO) int {
		return a.runDiscover(args, streams, cmd)
	}

	return cmd
}

func (a App) runDiscover(args []string, streams commandIO, cmd command) int {
	flags := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	outputFormat := string(discovery.OutputFormatText)
	flags.StringVar(&outputFormat, "format", outputFormat, "output format")

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

	result, err := a.discovery.Discover(context.Background(), discovery.Request{})
	if err != nil {
		streams.diag.Errorf(logPhaseDiscovery, "discovery failed: %s", err)
		return exitCodeFailure
	}

	if err := discovery.WriteResult(streams.stdout, format, result); err != nil {
		streams.diag.Errorf(logPhaseOutput, "failed to render discovery result: %s", err)
		return exitCodeFailure
	}

	if result.HasFatalErrors() {
		return exitCodeFailure
	}

	return exitCodeSuccess
}

func writeDiscoverHelp(w io.Writer, cmd command) {
	_, _ = fmt.Fprintf(w, "Usage:\n  %s\n\n", cmd.usage)
	_, _ = fmt.Fprintf(w, "%s\n\n", cmd.description)
	_, _ = io.WriteString(w, "Options:\n")
	_, _ = io.WriteString(w, "  --format text|json    Render as text or machine-readable JSON (default: text)\n")
	_, _ = io.WriteString(w, "\nExamples:\n")
	_, _ = fmt.Fprintf(w, "  %s discover\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s discover --format json\n", buildinfo.BinaryName)
}
