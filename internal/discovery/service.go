package discovery

import (
	"context"
	"errors"
	"fmt"
)

// Request controls which discovery sources should be queried.
type Request struct {
	Sources []DiscoverySource `json:"sources,omitempty"`
}

// Validate checks that a discovery request is internally consistent.
func (r Request) Validate() error {
	for i, source := range r.Sources {
		if !source.Valid() {
			return fmt.Errorf("invalid discovery source filter at index %d: %q", i, source)
		}
	}

	return nil
}

// Allows reports whether the request should query the given discovery source.
func (r Request) Allows(source DiscoverySource) bool {
	if len(r.Sources) == 0 {
		return true
	}

	for _, allowed := range r.Sources {
		if allowed == source {
			return true
		}
	}

	return false
}

// Provider discovers runtime targets from a specific source.
type Provider interface {
	Name() string
	Source() DiscoverySource
	Discover(ctx context.Context, req Request) (ProviderResult, error)
}

// ProviderResult captures provider-local targets and non-fatal issues.
type ProviderResult struct {
	Targets []RuntimeTarget `json:"targets,omitempty"`
	Issues  []ProviderError `json:"issues,omitempty"`
}

// Result holds the aggregated discovery targets and any provider-specific failures.
type Result struct {
	Targets        []RuntimeTarget `json:"targets,omitempty"`
	ProviderErrors []ProviderError `json:"provider_errors,omitempty"`
}

// HasErrors reports whether any provider failures were captured.
func (r Result) HasErrors() bool {
	return len(r.ProviderErrors) != 0
}

// HasFatalErrors reports whether any provider issue should fail the command.
func (r Result) HasFatalErrors() bool {
	for _, providerErr := range r.ProviderErrors {
		if providerErr.Fatal() {
			return true
		}
	}

	return false
}

// HasLimitations reports whether discovery was limited by provider access or availability.
func (r Result) HasLimitations() bool {
	for _, providerErr := range r.ProviderErrors {
		if providerErr.Limitation() {
			return true
		}
	}

	return false
}

// ProviderErrorCode identifies the operational class of a provider issue.
type ProviderErrorCode string

const (
	ProviderErrorCodeNotInstalled     ProviderErrorCode = "not_installed"
	ProviderErrorCodeUnavailable      ProviderErrorCode = "unavailable"
	ProviderErrorCodePermissionDenied ProviderErrorCode = "permission_denied"
	ProviderErrorCodePartialAccess    ProviderErrorCode = "partial_access"
	ProviderErrorCodeExecutionFailed  ProviderErrorCode = "execution_failed"
	ProviderErrorCodeInvalidData      ProviderErrorCode = "invalid_data"
)

func (c ProviderErrorCode) Fatal() bool {
	switch c {
	case ProviderErrorCodeNotInstalled, ProviderErrorCodeUnavailable, ProviderErrorCodePermissionDenied, ProviderErrorCodePartialAccess:
		return false
	case ProviderErrorCodeExecutionFailed, ProviderErrorCodeInvalidData:
		return true
	default:
		return true
	}
}

func (c ProviderErrorCode) Limitation() bool {
	switch c {
	case ProviderErrorCodeNotInstalled, ProviderErrorCodeUnavailable, ProviderErrorCodePermissionDenied, ProviderErrorCodePartialAccess:
		return true
	default:
		return false
	}
}

// ProviderError records a provider-level failure while preserving context for later reporting.
type ProviderError struct {
	Provider   string            `json:"provider"`
	Source     DiscoverySource   `json:"source,omitempty"`
	Code       ProviderErrorCode `json:"code,omitempty"`
	Message    string            `json:"message"`
	Hint       string            `json:"hint,omitempty"`
	Restricted bool              `json:"restricted"`
	Err        error             `json:"-"`
}

func (e ProviderError) Fatal() bool {
	return e.Code.Fatal()
}

func (e ProviderError) Limitation() bool {
	return e.Code.Limitation()
}

func (e ProviderError) Error() string {
	if e.Provider == "" {
		return e.Message
	}

	return fmt.Sprintf("%s: %s", e.Provider, e.Message)
}

func (e ProviderError) Unwrap() error {
	return e.Err
}

// Service coordinates discovery providers and aggregates their results in provider order.
type Service struct {
	providers []Provider
}

// NewService builds a discovery service from the given providers.
func NewService(providers ...Provider) Service {
	copied := make([]Provider, len(providers))
	copy(copied, providers)

	return Service{providers: copied}
}

// Discover executes the configured providers in order and aggregates any valid targets they return.
func (s Service) Discover(ctx context.Context, req Request) (Result, error) {
	if err := req.Validate(); err != nil {
		return Result{}, err
	}

	var result Result

	for index, provider := range s.providers {
		if provider == nil {
			result.ProviderErrors = append(result.ProviderErrors, ProviderError{
				Provider: fmt.Sprintf("provider[%d]", index),
				Code:     ProviderErrorCodeExecutionFailed,
				Message:  "provider is nil",
				Err:      errors.New("provider is nil"),
			})
			continue
		}

		source := provider.Source()
		name := provider.Name()
		if name == "" {
			name = fmt.Sprintf("provider[%d]", index)
		}

		if !source.Valid() {
			err := fmt.Errorf("provider %q returned invalid source %q", name, source)
			result.ProviderErrors = append(result.ProviderErrors, ProviderError{
				Provider: name,
				Source:   source,
				Code:     ProviderErrorCodeInvalidData,
				Message:  err.Error(),
				Err:      err,
			})
			continue
		}

		if !req.Allows(source) {
			continue
		}

		providerResult, err := provider.Discover(ctx, req)
		for _, issue := range providerResult.Issues {
			result.ProviderErrors = append(result.ProviderErrors, normalizeProviderError(name, source, issue))
		}

		if err != nil {
			var providerErr ProviderError
			if errors.As(err, &providerErr) {
				result.ProviderErrors = append(result.ProviderErrors, normalizeProviderError(name, source, providerErr))
			} else {
				result.ProviderErrors = append(result.ProviderErrors, normalizeProviderError(name, source, ProviderError{
					Code:    ProviderErrorCodeExecutionFailed,
					Message: err.Error(),
					Err:     err,
				}))
			}
		}

		for targetIndex, target := range providerResult.Targets {
			if target.Source != source {
				err := fmt.Errorf("runtime target source %q does not match provider source %q", target.Source, source)
				result.ProviderErrors = append(result.ProviderErrors, normalizeProviderError(name, source, ProviderError{
					Code:    ProviderErrorCodeInvalidData,
					Message: fmt.Sprintf("invalid runtime target at index %d: %v", targetIndex, err),
					Err:     err,
				}))
				continue
			}

			if err := target.Validate(); err != nil {
				result.ProviderErrors = append(result.ProviderErrors, normalizeProviderError(name, source, ProviderError{
					Code:    ProviderErrorCodeInvalidData,
					Message: fmt.Sprintf("invalid runtime target at index %d: %v", targetIndex, err),
					Err:     err,
				}))
				continue
			}

			result.Targets = append(result.Targets, target)
		}
	}

	return result, nil
}

func normalizeProviderError(name string, source DiscoverySource, issue ProviderError) ProviderError {
	if issue.Provider == "" {
		issue.Provider = name
	}
	if issue.Source == "" {
		issue.Source = source
	}
	if issue.Message == "" && issue.Err != nil {
		issue.Message = issue.Err.Error()
	}
	if issue.Code == "" {
		issue.Code = ProviderErrorCodeExecutionFailed
	}

	return issue
}
