package discovery

import (
	"fmt"
	"io"
	"strings"
)

// WriteInspection renders an inspection view in the requested format.
func WriteInspection(w io.Writer, format OutputFormat, result Result, selectionApplied bool) error {
	switch format {
	case OutputFormatText:
		return writeTextInspection(w, result, selectionApplied)
	case OutputFormatJSON:
		return writeJSONResult(w, result)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func writeTextInspection(w io.Writer, result Result, selectionApplied bool) error {
	if len(result.Targets) == 0 {
		message := "No Xray runtime targets are available for inspection.\n"
		if selectionApplied {
			message = "No Xray runtime targets matched the current selection.\n"
		}
		if result.HasLimitations() {
			message = strings.TrimSpace(message) + " Inspection was limited by provider availability or access issues.\n"
		}

		if _, err := io.WriteString(w, message); err != nil {
			return err
		}
	} else {
		label := "target"
		if len(result.Targets) != 1 {
			label = "targets"
		}

		if _, err := fmt.Fprintf(w, "Inspected %d Xray runtime %s.\n", len(result.Targets), label); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\nTargets:\n"); err != nil {
			return err
		}

		for index, target := range result.Targets {
			if err := writeInspectedTarget(w, index+1, target); err != nil {
				return err
			}
		}
	}

	return writeProviderIssues(w, result.ProviderErrors)
}

func writeInspectedTarget(w io.Writer, index int, target RuntimeTarget) error {
	if _, err := fmt.Fprintf(w, "  %d. %s\n", index, targetDisplayName(target)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "     source: %s\n", target.Source); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "     runtime: %s\n", runtimeTypeLabel(target)); err != nil {
		return err
	}
	if target.Identity.Binary != "" {
		if _, err := fmt.Fprintf(w, "     binary: %s\n", target.Identity.Binary); err != nil {
			return err
		}
	}
	if target.Identity.Version != "" {
		if _, err := fmt.Fprintf(w, "     version: %s\n", target.Identity.Version); err != nil {
			return err
		}
	}
	if target.APICapability != nil {
		if _, err := fmt.Fprintf(w, "     api capability: %s\n", apiCapabilityLabel(target.APICapability.Status)); err != nil {
			return err
		}
		if target.APICapability.Reason != "" {
			if _, err := fmt.Fprintf(w, "     api evidence: %s\n", target.APICapability.Reason); err != nil {
				return err
			}
		}
	}

	if target.HostProcess != nil {
		if target.HostProcess.PID != 0 {
			if _, err := fmt.Fprintf(w, "     pid: %d\n", target.HostProcess.PID); err != nil {
				return err
			}
		}
		if target.HostProcess.ExecutablePath != "" {
			if _, err := fmt.Fprintf(w, "     executable: %s\n", target.HostProcess.ExecutablePath); err != nil {
				return err
			}
		}
		if len(target.HostProcess.CommandLine) > 0 {
			if _, err := fmt.Fprintf(w, "     command: %s\n", strings.Join(target.HostProcess.CommandLine, " ")); err != nil {
				return err
			}
		}
		if target.HostProcess.WorkingDirectory != "" {
			if _, err := fmt.Fprintf(w, "     working directory: %s\n", target.HostProcess.WorkingDirectory); err != nil {
				return err
			}
		}
		if err := writeIndentedLines(w, "     config hints", target.HostProcess.ConfigPaths); err != nil {
			return err
		}
		if err := writeIndentedLines(w, "     resolved config hints", target.HostProcess.ResolvedConfigPaths); err != nil {
			return err
		}
	}

	if target.DockerContainer != nil {
		if target.DockerContainer.ID != "" {
			if _, err := fmt.Fprintf(w, "     container id: %s\n", target.DockerContainer.ID); err != nil {
				return err
			}
		}
		if target.DockerContainer.Name != "" {
			if _, err := fmt.Fprintf(w, "     container name: %s\n", target.DockerContainer.Name); err != nil {
				return err
			}
		}
		if target.DockerContainer.Image != "" {
			if _, err := fmt.Fprintf(w, "     image: %s\n", target.DockerContainer.Image); err != nil {
				return err
			}
		}
		if len(target.DockerContainer.CommandLine) > 0 {
			if _, err := fmt.Fprintf(w, "     command: %s\n", strings.Join(target.DockerContainer.CommandLine, " ")); err != nil {
				return err
			}
		}
		if target.DockerContainer.State != "" {
			if _, err := fmt.Fprintf(w, "     state: %s\n", target.DockerContainer.State); err != nil {
				return err
			}
		}
		if target.DockerContainer.Status != "" {
			if _, err := fmt.Fprintf(w, "     status: %s\n", target.DockerContainer.Status); err != nil {
				return err
			}
		}
		if err := writeIndentedLines(w, "     config hints", target.DockerContainer.ConfigPaths); err != nil {
			return err
		}
	}

	if target.Evidence != nil {
		if target.Evidence.Confidence != "" {
			if _, err := fmt.Fprintf(w, "     detection confidence: %s\n", target.Evidence.Confidence); err != nil {
				return err
			}
		}
		if err := writeIndentedLines(w, "     detection reasons", target.Evidence.Reasons); err != nil {
			return err
		}
	}

	if err := writeAPIEndpoints(w, target.APIEndpoints); err != nil {
		return err
	}
	if err := writeAPIEndpointsWithLabel(w, "     host-reachable api endpoints:\n", target.ReachableAPIEndpoints); err != nil {
		return err
	}
	if err := writeInboundSummaries(w, target.Inbounds); err != nil {
		return err
	}
	if err := writeOutboundSummaries(w, target.Outbounds); err != nil {
		return err
	}

	return nil
}

func writeAPIEndpoints(w io.Writer, endpoints []APIEndpoint) error {
	return writeAPIEndpointsWithLabel(w, "     api endpoints:\n", endpoints)
}

func writeAPIEndpointsWithLabel(w io.Writer, label string, endpoints []APIEndpoint) error {
	if len(endpoints) == 0 {
		return nil
	}

	if _, err := io.WriteString(w, label); err != nil {
		return err
	}

	for _, endpoint := range endpoints {
		line := firstNonEmpty(endpoint.Name, "api")
		switch endpoint.Network {
		case EndpointNetworkUnix:
			line = fmt.Sprintf("%s %s", line, endpoint.Path)
		default:
			if endpoint.Port != 0 {
				address := firstNonEmpty(endpoint.Address, "0.0.0.0")
				line = fmt.Sprintf("%s %s:%d", line, address, endpoint.Port)
			}
		}

		if _, err := fmt.Fprintf(w, "       %s\n", strings.TrimSpace(line)); err != nil {
			return err
		}
	}

	return nil
}

func writeInboundSummaries(w io.Writer, inbounds []InboundSummary) error {
	if len(inbounds) == 0 {
		return nil
	}

	if _, err := io.WriteString(w, "     inbounds:\n"); err != nil {
		return err
	}

	for _, inbound := range inbounds {
		line := firstNonEmpty(inbound.Tag, inbound.Protocol)
		if inbound.Port != 0 {
			address := firstNonEmpty(inbound.ListenAddress, "0.0.0.0")
			line = fmt.Sprintf("%s %s:%d", firstNonEmpty(line, "inbound"), address, inbound.Port)
		}

		if _, err := fmt.Fprintf(w, "       %s\n", strings.TrimSpace(line)); err != nil {
			return err
		}
	}

	return nil
}

func writeOutboundSummaries(w io.Writer, outbounds []OutboundSummary) error {
	if len(outbounds) == 0 {
		return nil
	}

	if _, err := io.WriteString(w, "     outbounds:\n"); err != nil {
		return err
	}

	for _, outbound := range outbounds {
		line := firstNonEmpty(outbound.Tag, outbound.Protocol, "outbound")
		if _, err := fmt.Fprintf(w, "       %s\n", strings.TrimSpace(line)); err != nil {
			return err
		}
	}

	return nil
}

func writeIndentedLines(w io.Writer, label string, values []string) error {
	if len(values) == 0 {
		return nil
	}

	if _, err := fmt.Fprintf(w, "%s:\n", label); err != nil {
		return err
	}

	for _, value := range values {
		if _, err := fmt.Fprintf(w, "       %s\n", value); err != nil {
			return err
		}
	}

	return nil
}

func runtimeTypeLabel(target RuntimeTarget) string {
	switch target.Source {
	case DiscoverySourceHostProcess:
		return "host process"
	case DiscoverySourceDockerContainer:
		return "docker container"
	default:
		return "runtime target"
	}
}

func apiCapabilityLabel(status APICapabilityStatus) string {
	switch status {
	case APICapabilityStatusLikelyConfigured:
		return "likely configured"
	case APICapabilityStatusNotEvident:
		return "not evident"
	default:
		return "unknown"
	}
}
