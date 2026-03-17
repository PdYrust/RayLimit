package discovery

import (
	"encoding/json"
	"fmt"
	"io"
)

// OutputFormat identifies the rendering format for discovery results.
type OutputFormat string

const (
	OutputFormatText OutputFormat = "text"
	OutputFormatJSON OutputFormat = "json"
)

func (f OutputFormat) Valid() bool {
	switch f {
	case OutputFormatText, OutputFormatJSON:
		return true
	default:
		return false
	}
}

// WriteResult renders a discovery result in the requested format.
func WriteResult(w io.Writer, format OutputFormat, result Result) error {
	switch format {
	case OutputFormatText:
		return writeTextResult(w, result)
	case OutputFormatJSON:
		return writeJSONResult(w, result)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func writeJSONResult(w io.Writer, result Result) error {
	payload := struct {
		Targets        []RuntimeTarget `json:"targets"`
		ProviderErrors []ProviderError `json:"provider_errors"`
	}{
		Targets:        normalizeTargets(result.Targets),
		ProviderErrors: normalizeProviderErrors(result.ProviderErrors),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func writeTextResult(w io.Writer, result Result) error {
	if len(result.Targets) == 0 {
		message := "No Xray runtime candidates found.\n"
		if result.HasLimitations() {
			message = "No Xray runtime candidates found. Discovery was limited by provider availability or access issues.\n"
		}

		if _, err := io.WriteString(w, message); err != nil {
			return err
		}
	} else {
		label := "candidate"
		if len(result.Targets) != 1 {
			label = "candidates"
		}

		if _, err := fmt.Fprintf(w, "Discovered %d Xray runtime %s.\n", len(result.Targets), label); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\nTargets:\n"); err != nil {
			return err
		}

		for i, target := range result.Targets {
			if _, err := fmt.Fprintf(w, "  %d. %s\n", i+1, targetDisplayName(target)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "     source: %s\n", target.Source); err != nil {
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
			if target.HostProcess != nil && target.HostProcess.PID != 0 {
				if _, err := fmt.Fprintf(w, "     pid: %d\n", target.HostProcess.PID); err != nil {
					return err
				}
			}
			if target.DockerContainer != nil {
				containerName := firstNonEmpty(target.DockerContainer.Name, target.DockerContainer.ID)
				if containerName != "" {
					if _, err := fmt.Fprintf(w, "     container: %s\n", containerName); err != nil {
						return err
					}
				}
				if target.DockerContainer.Image != "" {
					if _, err := fmt.Fprintf(w, "     image: %s\n", target.DockerContainer.Image); err != nil {
						return err
					}
				}
				if target.DockerContainer.Status != "" {
					if _, err := fmt.Fprintf(w, "     status: %s\n", target.DockerContainer.Status); err != nil {
						return err
					}
				}
			}
		}
	}

	return writeProviderIssues(w, result.ProviderErrors)
}

func normalizeTargets(targets []RuntimeTarget) []RuntimeTarget {
	if targets == nil {
		return []RuntimeTarget{}
	}

	return targets
}

func normalizeProviderErrors(providerErrors []ProviderError) []ProviderError {
	if providerErrors == nil {
		return []ProviderError{}
	}

	return providerErrors
}

func targetDisplayName(target RuntimeTarget) string {
	name := firstNonEmpty(target.Identity.Name, target.Identity.Binary)
	if name != "" {
		return name
	}

	if target.HostProcess != nil {
		name = firstNonEmpty(target.HostProcess.ExecutablePath)
		if name != "" {
			return name
		}
	}

	if target.DockerContainer != nil {
		name = firstNonEmpty(target.DockerContainer.Name, target.DockerContainer.ID)
		if name != "" {
			return name
		}
	}

	return "unnamed target"
}

func writeProviderIssues(w io.Writer, providerErrors []ProviderError) error {
	if len(providerErrors) == 0 {
		return nil
	}

	if _, err := io.WriteString(w, "\nProvider issues:\n"); err != nil {
		return err
	}

	for _, providerErr := range providerErrors {
		if providerErr.Source != "" {
			if _, err := fmt.Fprintf(w, "- %s (%s): %s\n", providerErr.Provider, providerErr.Source, providerErr.Message); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "- %s: %s\n", providerErr.Provider, providerErr.Message); err != nil {
				return err
			}
		}

		if providerErr.Hint != "" {
			if _, err := fmt.Fprintf(w, "  hint: %s\n", providerErr.Hint); err != nil {
				return err
			}
		}
	}

	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
