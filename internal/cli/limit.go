package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"github.com/PdYrust/RayLimit/internal/buildinfo"
	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/ipaddr"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
	"github.com/PdYrust/RayLimit/internal/tc"
)

type limitOperation string

const (
	limitOperationApply  limitOperation = "limit"
	limitOperationRemove limitOperation = "remove"
)

func (o limitOperation) Valid() bool {
	switch o {
	case limitOperationApply, limitOperationRemove:
		return true
	default:
		return false
	}
}

type limitRuntimeSelection struct {
	Source    discovery.DiscoverySource
	Name      string
	PID       int
	Container string
}

func (s limitRuntimeSelection) Validate() error {
	selection := inspectSelection{
		Source:    s.Source,
		Name:      s.Name,
		PID:       s.PID,
		Container: s.Container,
	}
	if err := selection.Validate(); err != nil {
		return err
	}

	switch countSelections(s.Name != "", s.PID != 0, s.Container != "") {
	case 0:
		return errors.New("select one runtime with --pid, --container, or --name")
	case 1:
		return nil
	default:
		return errors.New("select exactly one runtime with --pid, --container, or --name")
	}
}

func (s limitRuntimeSelection) inspectSelection() inspectSelection {
	return inspectSelection{
		Source:    s.Source,
		Name:      s.Name,
		PID:       s.PID,
		Container: s.Container,
	}
}

type limitOptions struct {
	format              discovery.OutputFormat
	operation           limitOperation
	runtime             limitRuntimeSelection
	target              limitTargetSelection
	device              string
	direction           tc.Direction
	rateBytes           int64
	unlimited           bool
	execute             bool
	allowMissingTCState bool
}

func (o limitOptions) Validate() error {
	if !o.format.Valid() {
		return fmt.Errorf("unsupported output format %q", o.format)
	}
	if !o.operation.Valid() {
		return fmt.Errorf("unsupported limit operation %q", o.operation)
	}
	if err := o.runtime.Validate(); err != nil {
		return err
	}
	if err := o.target.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(o.device) == "" {
		return errors.New("device is required")
	}
	if !o.direction.Valid() {
		return fmt.Errorf("unsupported direction %q", o.direction)
	}
	targetRule, err := o.target.policyTarget()
	if err != nil {
		return err
	}
	if o.unlimited {
		if o.operation == limitOperationRemove {
			return errors.New("cannot use --unlimited with --remove")
		}
		if targetRule.Kind != policy.TargetKindIP || targetRule.All {
			return errors.New("--unlimited is only valid with a specific --ip target")
		}
	}
	if o.operation == limitOperationRemove {
		if o.rateBytes != 0 {
			return errors.New("cannot use --rate with --remove")
		}
	} else if o.unlimited {
		if o.rateBytes != 0 {
			return errors.New("cannot use --rate with --unlimited")
		}
	} else if o.rateBytes <= 0 {
		return errors.New("rate must be greater than zero")
	}
	if o.allowMissingTCState && !o.execute {
		return errors.New("--allow-missing-tc-state requires --execute")
	}

	return nil
}

type limitObservationReport struct {
	Available         bool   `json:"available"`
	Reconcilable      bool   `json:"reconcilable"`
	Matched           bool   `json:"matched"`
	AttachmentMatched *bool  `json:"attachment_matched,omitempty"`
	CleanupRootQDisc  bool   `json:"cleanup_root_qdisc,omitempty"`
	ExpectedClassID   string `json:"expected_class_id,omitempty"`
	ObservedClassID   string `json:"observed_class_id,omitempty"`
	ObservedRateBytes int64  `json:"observed_rate_bytes_per_second,omitempty"`
	Error             string `json:"error,omitempty"`
}

func (r limitObservationReport) stateLabel() string {
	switch {
	case !r.Available:
		return "unavailable"
	case !r.Reconcilable:
		return "available (not comparable)"
	default:
		return "available"
	}
}

func (r limitObservationReport) summaryError() string {
	return strings.TrimSpace(r.Error)
}

type limitDecisionReport struct {
	Kind   limiter.DecisionKind `json:"kind"`
	Reason string               `json:"reason"`
}

type limitObservedState struct {
	Observation limitObservationReport
	InspectPlan tc.Plan
	Applied     []limiter.AppliedState
	TCSnapshot  tc.Snapshot
	NFTSnapshot tc.NftablesSnapshot
}

type limitConcretePreviewResult struct {
	Report         limitReport
	Plan           *tc.Plan
	Subject        limiter.Subject
	Desired        *limiter.DesiredState
	ObservedState  limitObservedState
	ReconcileInput *tc.PeriodicReconcileInput
}

type limitPerIPPreviewIssue struct {
	Target           limitTargetReport
	Err              error
	ExecutionBlocked bool
	ExecutionNote    string
}

type limitAttachmentObservation struct {
	Comparable  bool
	Matched     bool
	Error       string
	NFTSnapshot tc.NftablesSnapshot
}

type limitPolicyEvaluationReport struct {
	PrecedenceOrder   string             `json:"precedence_order,omitempty"`
	WinningKind       policy.TargetKind  `json:"winning_kind,omitempty"`
	WinningPrecedence int                `json:"winning_precedence,omitempty"`
	EffectiveLimits   policy.LimitPolicy `json:"effective_limits,omitempty"`
	EffectiveReason   string             `json:"effective_reason,omitempty"`
	Matches           []policy.Match     `json:"matches,omitempty"`
	Winning           []policy.Match     `json:"winning,omitempty"`
	NonWinning        []policy.Match     `json:"non_winning,omitempty"`
}

func (r limitPolicyEvaluationReport) hasData() bool {
	return len(r.Matches) != 0 || r.WinningKind != "" || r.EffectiveReason != ""
}

func (r limitPolicyEvaluationReport) hasCoexistence() bool {
	return len(r.Matches) > 1 || len(r.Winning) > 1 || len(r.NonWinning) != 0
}

type limitDirectAttachmentReport struct {
	ShapingReadiness             tc.BindingReadiness       `json:"shaping_readiness,omitempty"`
	AttachmentReadiness          tc.BindingReadiness       `json:"attachment_readiness,omitempty"`
	AttachmentExecutionReadiness tc.BindingReadiness       `json:"attachment_execution_readiness,omitempty"`
	Confidence                   tc.BindingConfidence      `json:"confidence,omitempty"`
	Note                         string                    `json:"note,omitempty"`
	AttachmentExecutionNote      string                    `json:"attachment_execution_note,omitempty"`
	AttachmentExecution          []tc.DirectAttachmentRule `json:"attachment_execution,omitempty"`
}

func (r limitDirectAttachmentReport) hasData() bool {
	return r.ShapingReadiness != "" ||
		r.AttachmentReadiness != "" ||
		r.AttachmentExecutionReadiness != "" ||
		r.Confidence != "" ||
		r.Note != "" ||
		r.AttachmentExecutionNote != "" ||
		len(r.AttachmentExecution) != 0
}

type limitPerIPReconcileState string

const (
	limitPerIPReconcileStateObservedManagedState limitPerIPReconcileState = "observed_managed_state"
	limitPerIPReconcileStatePartialObservedState limitPerIPReconcileState = "partial_observed_state"
	limitPerIPReconcileStateNoObservedManaged    limitPerIPReconcileState = "no_observed_managed_state"
	limitPerIPReconcileStateNoSessions           limitPerIPReconcileState = "no_sessions"
	limitPerIPReconcileStateInsufficientEvidence limitPerIPReconcileState = "insufficient_evidence"
	limitPerIPReconcileStateUnavailableEvidence  limitPerIPReconcileState = "unavailable_evidence"
)

type limitPerIPEntryReport struct {
	Target           limitTargetReport          `json:"target"`
	Observation      *limitObservationReport    `json:"observation,omitempty"`
	Decision         *limitDecisionReport       `json:"decision,omitempty"`
	Applied          []limiter.AppliedState     `json:"applied,omitempty"`
	ReconcileInput   *tc.PeriodicReconcileInput `json:"reconcile_input,omitempty"`
	Plan             *tc.Plan                   `json:"plan,omitempty"`
	Results          []tc.Result                `json:"results,omitempty"`
	ExecutionBlocked bool                       `json:"execution_blocked,omitempty"`
	ExecutionNote    string                     `json:"execution_note,omitempty"`
}

type limitPerIPDecisionSummary struct {
	NoOp    int `json:"no_op"`
	Apply   int `json:"apply"`
	Replace int `json:"replace"`
	Remove  int `json:"remove"`
}

func (s limitPerIPDecisionSummary) hasData() bool {
	return s.NoOp != 0 || s.Apply != 0 || s.Replace != 0 || s.Remove != 0
}

func (s limitPerIPDecisionSummary) text() string {
	return fmt.Sprintf(
		"%d no-op, %d apply, %d replace, %d remove",
		s.NoOp,
		s.Apply,
		s.Replace,
		s.Remove,
	)
}

func (s limitPerIPDecisionSummary) logFields() []logField {
	return []logField{
		intLogField("per_ip_no_op_count", s.NoOp),
		intLogField("per_ip_apply_count", s.Apply),
		intLogField("per_ip_replace_count", s.Replace),
		intLogField("per_ip_remove_count", s.Remove),
	}
}

type limitPerIPExpansionReport struct {
	Provider        string                         `json:"provider,omitempty"`
	State           discovery.SessionEvidenceState `json:"state,omitempty"`
	ReconcileState  limitPerIPReconcileState       `json:"reconcile_state,omitempty"`
	DecisionSummary *limitPerIPDecisionSummary     `json:"decision_summary,omitempty"`
	ClientIPs       []string                       `json:"client_ips,omitempty"`
	Note            string                         `json:"note,omitempty"`
	Entries         []limitPerIPEntryReport        `json:"entries,omitempty"`
}

func (r limitPerIPExpansionReport) hasData() bool {
	return strings.TrimSpace(r.Provider) != "" ||
		r.State != "" ||
		r.ReconcileState != "" ||
		(r.DecisionSummary != nil && r.DecisionSummary.hasData()) ||
		len(r.ClientIPs) != 0 ||
		r.Note != "" ||
		len(r.Entries) != 0
}

func (r limitPerIPExpansionReport) hasPlan() bool {
	for _, entry := range r.Entries {
		if entry.Plan != nil {
			return true
		}
	}

	return false
}

func (r limitPerIPExpansionReport) noOp() bool {
	if len(r.Entries) == 0 {
		return false
	}

	for _, entry := range r.Entries {
		if entry.ExecutionBlocked || entry.Plan != nil || entry.Decision == nil || entry.Decision.Kind != limiter.DecisionNoOp {
			return false
		}
	}

	return true
}

type limitTargetReport struct {
	Kind          policy.TargetKind        `json:"kind"`
	Value         string                   `json:"value,omitempty"`
	IPAggregation policy.IPAggregationMode `json:"ip_aggregation,omitempty"`
}

func (r limitTargetReport) hasIPAggregation() bool {
	return strings.TrimSpace(string(r.IPAggregation)) != ""
}

func (r limitTargetReport) displayValue() string {
	if r.Kind == policy.TargetKindIP && strings.TrimSpace(r.Value) == "" {
		return "all"
	}

	return strings.TrimSpace(r.Value)
}

func (r limitTargetReport) logFields() []logField {
	fields := []logField{
		stringLogField("target", describeLimitTarget(r)),
	}
	if r.hasIPAggregation() {
		fields = append(fields, stringLogField("ip_aggregation", string(r.IPAggregation)))
	}

	return fields
}

type limitReport struct {
	Mode             string                       `json:"mode"`
	Operation        limitOperation               `json:"operation"`
	Runtime          discovery.RuntimeTarget      `json:"runtime"`
	Target           limitTargetReport            `json:"target"`
	Unlimited        bool                         `json:"unlimited,omitempty"`
	ExecutionBlocked bool                         `json:"execution_blocked,omitempty"`
	ExecutionNote    string                       `json:"execution_note,omitempty"`
	Scope            tc.Scope                     `json:"scope"`
	RateBytes        int64                        `json:"rate_bytes_per_second,omitempty"`
	PolicyEvaluation *limitPolicyEvaluationReport `json:"policy_evaluation,omitempty"`
	PerIPExpansion   *limitPerIPExpansionReport   `json:"per_ip_expansion,omitempty"`
	DirectAttachment *limitDirectAttachmentReport `json:"direct_attachment,omitempty"`
	Observation      *limitObservationReport      `json:"observation,omitempty"`
	Decision         *limitDecisionReport         `json:"decision,omitempty"`
	Plan             *tc.Plan                     `json:"plan,omitempty"`
	Results          []tc.Result                  `json:"results,omitempty"`
	ProviderErrors   []discovery.ProviderError    `json:"provider_errors,omitempty"`
}

func (r limitReport) hasPlannedWork() bool {
	if r.PerIPExpansion != nil {
		return r.PerIPExpansion.hasPlan()
	}

	return r.Plan != nil
}

func (r limitReport) noOp() bool {
	if r.PerIPExpansion != nil {
		return r.PerIPExpansion.noOp()
	}

	return r.Plan != nil && r.Plan.NoOp
}

func (r limitReport) logFields() []logField {
	fields := []logField{
		stringLogField("mode", r.Mode),
		stringLogField("operation", string(r.Operation)),
	}
	if r.PerIPExpansion != nil {
		if r.PerIPExpansion.State != "" {
			fields = append(fields, stringLogField("per_ip_evidence_state", string(r.PerIPExpansion.State)))
		}
		if r.PerIPExpansion.ReconcileState != "" {
			fields = append(fields, stringLogField("per_ip_reconcile_state", string(r.PerIPExpansion.ReconcileState)))
		}
		if r.PerIPExpansion.DecisionSummary != nil {
			fields = append(fields, r.PerIPExpansion.DecisionSummary.logFields()...)
		}
		if len(r.PerIPExpansion.ClientIPs) != 0 {
			fields = append(fields, intLogField("expanded_client_ip_count", len(r.PerIPExpansion.ClientIPs)))
		}
	}

	return append(fields, r.Target.logFields()...)
}

func (r limitReport) executionDiagnosticMessage() string {
	if r.ExecutionBlocked {
		return "limit execution blocked"
	}

	return "limit execution failed"
}

func (a App) newLimitCommand() command {
	cmd := command{
		name:        "limit",
		summary:     "Plan or execute a reconcile-aware traffic limit",
		usage:       buildinfo.BinaryName + " limit (--ip <ip|all> | --inbound <tag> | --outbound <tag>) [--ip-aggregation shared|per_ip] --device <device> --direction upload|download [--rate <bytes-per-second> | --unlimited | --remove] [--source host_process|docker_container] (--pid <pid> | --container <id-or-name> | --name <name>) [--execute] [--allow-missing-tc-state] [--format text|json]",
		description: "Plan a reconcile-aware tc-backed limit flow for a selected runtime target. IP-targeted limiting currently supports a runtime-local shared baseline with --ip all, specific IP override limits, and specific IP unlimited exceptions. When --ip all is combined with --ip-aggregation per_ip, RayLimit expands the current live client IP set into concrete specific-IP work through Xray-backed session evidence for apply and remove. Concrete direct client IP rules cover IPv4, IPv4-mapped IPv6 after canonicalization to IPv4, and IPv6 traffic that fits the current u32 backend assumption of no IPv6 extension headers. Inbound-targeted limiting uses concrete nftables mark plus tc fw attachment when readable Xray config proves one concrete TCP listener for the selected inbound tag; otherwise it stays conservative and blocks apply execution. Outbound-targeted limiting uses concrete nftables output matching plus tc fw attachment when readable Xray config proves one unique non-zero outbound socket mark for the selected tag without proxy or dialer-proxy indirection; otherwise it stays conservative and blocks concrete execution.",
	}

	cmd.help = func(w io.Writer) {
		writeLimitHelp(w, cmd)
	}

	cmd.run = func(args []string, streams commandIO) int {
		return a.runLimit(args, streams, cmd)
	}

	return cmd
}

func (a App) runLimit(args []string, streams commandIO, cmd command) int {
	flags := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	outputFormat := string(discovery.OutputFormatText)
	source := ""
	name := ""
	container := ""
	pid := 0
	device := ""
	direction := ""
	rate := int64(0)
	ip := ""
	inbound := ""
	outbound := ""
	ipAggregation := ""
	unlimited := false
	execute := false
	remove := false
	allowMissingTCState := false

	flags.StringVar(&outputFormat, "format", outputFormat, "output format")
	flags.StringVar(&source, "source", source, "discovery source")
	flags.StringVar(&name, "name", name, "runtime name")
	flags.IntVar(&pid, "pid", pid, "host process ID")
	flags.StringVar(&container, "container", container, "docker container name or ID prefix")
	flags.StringVar(&device, "device", device, "Linux network device")
	flags.StringVar(&direction, "direction", direction, "limit direction")
	flags.Int64Var(&rate, "rate", rate, "rate limit in bytes per second")
	flags.StringVar(&ip, "ip", ip, "client IPv4 or IPv6 address or all")
	flags.StringVar(&ipAggregation, "ip-aggregation", ipAggregation, "IP aggregation mode for --ip all")
	flags.StringVar(&inbound, "inbound", inbound, "inbound tag")
	flags.StringVar(&outbound, "outbound", outbound, "outbound tag")
	flags.BoolVar(&unlimited, "unlimited", unlimited, "create a specific IP unlimited exception")
	flags.BoolVar(&execute, "execute", execute, "perform real local tc execution")
	flags.BoolVar(&remove, "remove", remove, "remove the selected target rule set instead of planning a new one")
	flags.BoolVar(&allowMissingTCState, "allow-missing-tc-state", allowMissingTCState, "allow real execution when tc state cannot be observed first")

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

	options := limitOptions{
		format:    discovery.OutputFormat(outputFormat),
		operation: limitOperationApply,
		runtime: limitRuntimeSelection{
			Source:    discovery.DiscoverySource(source),
			Name:      strings.TrimSpace(name),
			PID:       pid,
			Container: strings.TrimSpace(container),
		},
		target: limitTargetSelection{
			IP:            strings.TrimSpace(ip),
			Inbound:       strings.TrimSpace(inbound),
			Outbound:      strings.TrimSpace(outbound),
			IPAggregation: policy.IPAggregationMode(strings.ToLower(strings.TrimSpace(ipAggregation))),
		},
		device:              strings.TrimSpace(device),
		direction:           tc.Direction(strings.TrimSpace(direction)),
		rateBytes:           rate,
		unlimited:           unlimited,
		execute:             execute,
		allowMissingTCState: allowMissingTCState,
	}
	if remove {
		options.operation = limitOperationRemove
	}

	if err := options.Validate(); err != nil {
		return writeCommandUsageError(streams.stderr, cmd, err.Error())
	}
	result, err := a.discovery.Discover(context.Background(), discovery.Request{})
	if err != nil {
		streams.diag.Errorf(logPhaseDiscovery, "limit planning failed during discovery: %s", err)
		return exitCodeFailure
	}

	selectedTargets := filterInspectionTargets(result.Targets, options.runtime.inspectSelection())
	if len(selectedTargets) == 0 {
		fields := []logField{}
		if result.HasLimitations() {
			fields = append(fields, boolLogField("provider_limitations", true))
		}
		streams.diag.Errorw(logPhaseSelection, "no runtime target matched the current selection", fields...)
		return exitCodeFailure
	}
	if len(selectedTargets) > 1 {
		streams.diag.Errorw(
			logPhaseSelection,
			"multiple runtime targets matched; refine the selection",
			intLogField("count", len(selectedTargets)),
		)
		return exitCodeFailure
	}

	report, execErr := a.limitReport(selectedTargets[0], options, result.ProviderErrors)
	if err := writeLimitReport(streams.stdout, options.format, report); err != nil {
		fields := append(report.logFields(), errorLogField(err))
		streams.diag.Errorw(logPhaseOutput, "failed to render limit result", fields...)
		return exitCodeFailure
	}
	if execErr != nil {
		fields := append(report.logFields(), errorLogField(execErr))
		streams.diag.Errorw(logPhaseExecution, report.executionDiagnosticMessage(), fields...)
		return exitCodeFailure
	}

	return exitCodeSuccess
}

func (a App) limitReport(target discovery.RuntimeTarget, options limitOptions, providerErrors []discovery.ProviderError) (limitReport, error) {
	if options.target.NormalizedIPAggregation() == policy.IPAggregationModePerIP {
		return a.limitPerIPReport(context.Background(), target, options, providerErrors)
	}

	preview, previewErr := a.limitConcretePreview(context.Background(), target, options.target, options, providerErrors)
	if previewErr != nil || preview.Plan == nil {
		return preview.Report, previewErr
	}

	results, execErr := a.executeLimitPlan(context.Background(), *preview.Plan, options)
	preview.Report.Results = results
	if execErr != nil {
		preview.Report.ExecutionNote = execErr.Error()
		if options.execute && len(results) == 0 {
			preview.Report.ExecutionBlocked = true
		}
		return preview.Report, fmt.Errorf("limit execution failed: %w", execErr)
	}

	return preview.Report, nil
}

func (a App) limitPerIPReport(ctx context.Context, target discovery.RuntimeTarget, options limitOptions, providerErrors []discovery.ProviderError) (limitReport, error) {
	runtime, err := discovery.SessionRuntimeFromTarget(target)
	if err != nil {
		return limitReport{}, fmt.Errorf("failed to bind selected runtime: %w", err)
	}

	session := discovery.Session{Runtime: runtime}
	options.target.apply(&session)
	if err := session.Validate(); err != nil {
		return limitReport{}, fmt.Errorf("failed to construct session context: %w", err)
	}

	scope := tc.Scope{
		Device:    options.device,
		Direction: options.direction,
	}

	_, desired, err := a.limitState(session, options.target, options)
	if err != nil {
		return limitReport{}, err
	}

	report := limitReport{
		Mode:           limitMode(options.execute),
		Operation:      options.operation,
		Runtime:        target,
		Target:         limitTargetReportFromSelection(options.target),
		Unlimited:      options.unlimited,
		Scope:          scope,
		RateBytes:      options.rateBytes,
		ProviderErrors: providerErrors,
	}
	if desired != nil {
		report.PolicyEvaluation = limitPolicyEvaluationFromEvaluation(desired.PolicyEvaluation)
	}

	evidenceResult, err := a.sessionEvidenceProvider().ObserveSessions(ctx, runtime)
	if err != nil {
		return report, fmt.Errorf("failed to observe live client IP evidence: %w", err)
	}

	clientIPs := limitPerIPClientIPs(evidenceResult)
	expansion := &limitPerIPExpansionReport{
		Provider:  strings.TrimSpace(evidenceResult.Provider),
		State:     evidenceResult.State(),
		ClientIPs: clientIPs,
		Note:      limitPerIPExpansionNote(options.operation, evidenceResult, clientIPs),
	}
	report.PerIPExpansion = expansion

	switch expansion.State {
	case discovery.SessionEvidenceStateUnavailable, discovery.SessionEvidenceStateInsufficient:
		expansion.ReconcileState = limitPerIPReconcileStateFromEvidenceState(expansion.State)
		report.ExecutionBlocked = true
		report.ExecutionNote = limitPerIPBlockingNote(options.operation, evidenceResult, options.execute)
		if options.execute {
			return report, errors.New(report.ExecutionNote)
		}
		return report, nil
	case discovery.SessionEvidenceStateNoSessions:
		expansion.ReconcileState = limitPerIPReconcileStateNoSessions
		return report, nil
	}
	if len(clientIPs) == 0 {
		expansion.ReconcileState = limitPerIPReconcileStateNoObservedManaged
		report.ExecutionBlocked = true
		report.ExecutionNote = limitPerIPNoUsableClientIPsNote(options.operation, expansion.Note, options.execute)
		if options.execute {
			return report, errors.New(report.ExecutionNote)
		}
		return report, nil
	}

	previews := make([]limitConcretePreviewResult, 0, len(clientIPs))
	previewIssues := make([]limitPerIPPreviewIssue, 0)
	for _, clientIP := range clientIPs {
		entryTarget := limitTargetSelection{IP: clientIP}
		preview, previewErr := a.limitConcretePreview(ctx, target, entryTarget, options, nil)
		previews = append(previews, preview)
		entryTargetReport := preview.Report.Target
		if entryTargetReport.Kind == "" {
			entryTargetReport = limitTargetReportFromSelection(entryTarget)
		}
		entry := limitPerIPEntryReport{
			Target:           entryTargetReport,
			Observation:      preview.Report.Observation,
			Decision:         preview.Report.Decision,
			Applied:          append([]limiter.AppliedState(nil), preview.ObservedState.Applied...),
			ReconcileInput:   copyPeriodicReconcileInput(preview.ReconcileInput),
			Plan:             preview.Report.Plan,
			ExecutionBlocked: preview.Report.ExecutionBlocked,
			ExecutionNote:    preview.Report.ExecutionNote,
		}
		expansion.Entries = append(expansion.Entries, entry)

		if previewErr != nil {
			previewIssues = append(previewIssues, limitPerIPPreviewIssue{
				Target:           entry.Target,
				Err:              previewErr,
				ExecutionBlocked: entry.ExecutionBlocked,
				ExecutionNote:    entry.ExecutionNote,
			})
		}
	}

	if err := limitFinalizePerIPExpansion(options.operation, previews, expansion); err != nil {
		return report, err
	}
	if len(previewIssues) != 0 {
		message := limitPerIPPreviewIssuesMessage(options.operation, previewIssues, options.execute)
		if limitPerIPPreviewIssuesBlocked(previewIssues) {
			report.ExecutionBlocked = true
			report.ExecutionNote = message
		}
		return report, errors.New(message)
	}

	for index, preview := range previews {
		plan := preview.Plan
		if plan == nil {
			continue
		}

		results, execErr := a.executeLimitPlan(ctx, *plan, options)
		expansion.Entries[index].Results = results
		report.Results = append(report.Results, results...)
		if execErr != nil {
			expansion.Entries[index].ExecutionNote = execErr.Error()
			if options.execute && len(results) == 0 {
				expansion.Entries[index].ExecutionBlocked = true
			}
			report.ExecutionNote = execErr.Error()
			if options.execute && len(report.Results) == 0 {
				report.ExecutionBlocked = true
			}
			return report, fmt.Errorf("limit execution failed: %w", execErr)
		}
	}

	return report, nil
}

func (a App) limitConcretePreview(ctx context.Context, target discovery.RuntimeTarget, selection limitTargetSelection, options limitOptions, providerErrors []discovery.ProviderError) (limitConcretePreviewResult, error) {
	runtime, err := discovery.SessionRuntimeFromTarget(target)
	if err != nil {
		return limitConcretePreviewResult{}, fmt.Errorf("failed to bind selected runtime: %w", err)
	}

	session := discovery.Session{Runtime: runtime}
	selection.apply(&session)
	if err := session.Validate(); err != nil {
		return limitConcretePreviewResult{}, fmt.Errorf("failed to construct session context: %w", err)
	}

	scope := tc.Scope{
		Device:    options.device,
		Direction: options.direction,
	}

	subject, desired, err := a.limitState(session, selection, options)
	if err != nil {
		return limitConcretePreviewResult{}, err
	}

	report := limitReport{
		Mode:           limitMode(options.execute),
		Operation:      options.operation,
		Runtime:        target,
		Target:         limitTargetReportFromSelection(selection),
		Unlimited:      options.unlimited,
		Scope:          scope,
		RateBytes:      options.rateBytes,
		ProviderErrors: providerErrors,
	}
	if desired != nil {
		report.PolicyEvaluation = limitPolicyEvaluationFromEvaluation(desired.PolicyEvaluation)
	}

	observedState, err := a.observeLimitState(ctx, target, subject, desired, scope, options.operation)
	if err != nil {
		return limitConcretePreviewResult{}, fmt.Errorf("failed to inspect current tc state: %w", err)
	}
	observation := observedState.Observation
	report.Observation = &observation
	if directAttachment := limitDirectAttachmentReportFromPlan(observedState.InspectPlan); directAttachment.hasData() {
		report.DirectAttachment = &directAttachment
	}

	decision, err := a.limitDecision(options.operation, subject, desired, observedState.Observation, observedState.Applied)
	if err != nil {
		return limitConcretePreviewResult{}, fmt.Errorf("failed to reconcile desired and observed tc state: %w", err)
	}
	decisionReport := limitDecisionReport{
		Kind:   decision.Kind,
		Reason: decision.Reason,
	}
	report.Decision = &decisionReport

	action, err := decision.Action()
	if err != nil {
		return limitConcretePreviewResult{Report: report, Subject: subject, Desired: desired, ObservedState: observedState}, fmt.Errorf("failed to derive limiter action from reconcile decision: %w", err)
	}
	var plan *tc.Plan
	if action != nil {
		planned, err := a.limitPlan(ctx, target, *action, scope, observedState, options.operation)
		if err != nil {
			return limitConcretePreviewResult{Report: report, Subject: subject, Desired: desired, ObservedState: observedState}, fmt.Errorf("failed to build tc plan: %w", err)
		}
		report.Plan = &planned
		plan = &planned
	}
	reconcileInput, err := limitPeriodicReconcileInput(subject, desired, observedState, plan, scope, options.operation)
	if err != nil {
		return limitConcretePreviewResult{Report: report, Subject: subject, Desired: desired, ObservedState: observedState, Plan: plan}, fmt.Errorf("failed to derive managed-state reconcile input: %w", err)
	}

	executionPlan := observedState.InspectPlan
	if plan != nil {
		executionPlan = *plan
	}

	if options.execute && options.operation != limitOperationRemove {
		switch selection.Kind() {
		case policy.TargetKindInbound:
			if executionPlan.MarkAttachment == nil || executionPlan.MarkAttachment.Readiness != tc.BindingReadinessReady {
				report.ExecutionBlocked = true
				report.ExecutionNote = blockedInboundApplyExecutionNote(executionPlan)
				return limitConcretePreviewResult{Report: report, Plan: plan, Subject: subject, Desired: desired, ObservedState: observedState, ReconcileInput: reconcileInput}, errors.New(report.ExecutionNote)
			}
		case policy.TargetKindOutbound:
			if executionPlan.MarkAttachment == nil || executionPlan.MarkAttachment.Readiness != tc.BindingReadinessReady {
				report.ExecutionBlocked = true
				report.ExecutionNote = blockedOutboundApplyExecutionNote(executionPlan)
				return limitConcretePreviewResult{Report: report, Plan: plan, Subject: subject, Desired: desired, ObservedState: observedState, ReconcileInput: reconcileInput}, errors.New(report.ExecutionNote)
			}
		}
	}

	if options.execute &&
		options.operation == limitOperationRemove &&
		(selection.Kind() == policy.TargetKindInbound || selection.Kind() == policy.TargetKindOutbound) &&
		(executionPlan.MarkAttachment == nil || executionPlan.MarkAttachment.Readiness != tc.BindingReadinessReady) {
		hasObservedFWFilter := observedState.TCSnapshot.HasFWClassFilter(executionPlan.Handles.RootHandle, executionPlan.Handles.ClassID)
		if hasObservedFWFilter {
			nftSnapshot, _, nftErr := a.nftablesInspector().Inspect(ctx)
			if nftErr != nil {
				report.ExecutionBlocked = true
				switch selection.Kind() {
				case policy.TargetKindInbound:
					report.ExecutionNote = missingObservedInboundRemoveExecutionNote(nftErr)
				default:
					report.ExecutionNote = missingObservedOutboundRemoveExecutionNote(nftErr)
				}
				return limitConcretePreviewResult{Report: report, Plan: plan, Subject: subject, Desired: desired, ObservedState: observedState, ReconcileInput: reconcileInput}, errors.New(report.ExecutionNote)
			}

			identityKind := tc.IdentityKindOutbound
			switch selection.Kind() {
			case policy.TargetKindInbound:
				identityKind = tc.IdentityKindInbound
			}
			if nftSnapshot.HasManagedMarkAttachment(identityKind, scope.Direction, executionPlan.Handles.ClassID) {
				report.ExecutionBlocked = true
				switch selection.Kind() {
				case policy.TargetKindInbound:
					report.ExecutionNote = blockedInboundRemoveExecutionNote(executionPlan)
				default:
					report.ExecutionNote = blockedOutboundRemoveExecutionNote(executionPlan)
				}
				return limitConcretePreviewResult{Report: report, Plan: plan, Subject: subject, Desired: desired, ObservedState: observedState, ReconcileInput: reconcileInput}, errors.New(report.ExecutionNote)
			}
		}

		if hasObservedFWFilter {
			report.ExecutionBlocked = true
			switch selection.Kind() {
			case policy.TargetKindInbound:
				report.ExecutionNote = blockedInboundRemoveExecutionNote(executionPlan)
			default:
				report.ExecutionNote = blockedOutboundRemoveExecutionNote(executionPlan)
			}
			return limitConcretePreviewResult{Report: report, Plan: plan, Subject: subject, Desired: desired, ObservedState: observedState, ReconcileInput: reconcileInput}, errors.New(report.ExecutionNote)
		}
	}

	if plan == nil {
		return limitConcretePreviewResult{
			Report:         report,
			Subject:        subject,
			Desired:        desired,
			ObservedState:  observedState,
			ReconcileInput: reconcileInput,
		}, nil
	}

	if options.execute &&
		plan.MarkAttachment != nil &&
		plan.MarkAttachment.Readiness == tc.BindingReadinessReady &&
		!observedState.Observation.Reconcilable {
		report.ExecutionBlocked = true
		report.ExecutionNote = missingObservedMarkAttachmentExecutionNote(observedState.Observation)
		return limitConcretePreviewResult{Report: report, Plan: plan, Subject: subject, Desired: desired, ObservedState: observedState, ReconcileInput: reconcileInput}, errors.New(report.ExecutionNote)
	}

	if options.execute && !observedState.Observation.Reconcilable && !options.allowMissingTCState {
		report.ExecutionBlocked = true
		report.ExecutionNote = missingObservedStateExecutionNote(observedState.Observation)
		return limitConcretePreviewResult{Report: report, Plan: plan, Subject: subject, Desired: desired, ObservedState: observedState, ReconcileInput: reconcileInput}, errors.New(report.ExecutionNote)
	}

	return limitConcretePreviewResult{
		Report:         report,
		Plan:           plan,
		Subject:        subject,
		Desired:        desired,
		ObservedState:  observedState,
		ReconcileInput: reconcileInput,
	}, nil
}

func (a App) executeLimitPlan(ctx context.Context, plan tc.Plan, options limitOptions) ([]tc.Result, error) {
	return tc.NewExecutor(a.tcRunner, !options.execute, a.privilegeStatus).Execute(ctx, plan)
}

func limitPerIPClientIPs(result discovery.SessionEvidenceResult) []string {
	if len(result.Evidence) == 0 {
		return nil
	}

	clientIPs := make([]string, 0, len(result.Evidence))
	seen := make(map[string]struct{}, len(result.Evidence))
	for _, session := range result.Sessions() {
		normalized, err := ipaddr.Normalize(session.Client.IP)
		if err != nil {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		clientIPs = append(clientIPs, normalized)
	}
	sort.Strings(clientIPs)

	return clientIPs
}

func limitPerIPExpansionNote(operation limitOperation, result discovery.SessionEvidenceResult, clientIPs []string) string {
	switch result.State() {
	case discovery.SessionEvidenceStateAvailable:
		if len(clientIPs) == 0 {
			return "live session evidence was available, but no usable client IPs were returned for per_ip expansion"
		}
		return fmt.Sprintf(
			"expanded the requested per_ip %s into %d concrete client IP target(s) using current live Xray session evidence; concrete work and cleanup stay limited to the client IPs currently proven by that evidence",
			limitPerIPOperationLabel(operation),
			len(clientIPs),
		)
	case discovery.SessionEvidenceStateNoSessions:
		return "no live client IPs are currently visible through Xray-backed session evidence for the selected runtime"
	default:
		if summary := strings.TrimSpace(result.IssueSummary()); summary != "" {
			return "per_ip expansion could not build concrete client IP work from current live session evidence; " + summary
		}
		return "per_ip expansion could not build concrete client IP work because live client IP evidence is not currently available"
	}
}

func limitPerIPBlockingNote(operation limitOperation, result discovery.SessionEvidenceResult, execute bool) string {
	message := strings.TrimSpace(result.IssueSummary())
	if message == "" {
		message = "live client IP evidence is not currently available for per_ip expansion"
	}

	return fmt.Sprintf(
		"%s requires live client IP evidence for the selected runtime; %s",
		limitPerIPActivityLabel(operation, execute),
		message,
	)
}

func limitPerIPNoUsableClientIPsNote(operation limitOperation, note string, execute bool) string {
	detail := strings.TrimSpace(note)
	if detail == "" {
		detail = "no usable client IPs were returned from current live session evidence"
	}

	return fmt.Sprintf(
		"%s requires at least one usable client IP from current live session evidence for the selected runtime; %s",
		limitPerIPActivityLabel(operation, execute),
		detail,
	)
}

func limitPerIPOperationLabel(operation limitOperation) string {
	if operation == limitOperationRemove {
		return "remove"
	}

	return "apply"
}

func limitPerIPActivityLabel(operation limitOperation, execute bool) string {
	action := fmt.Sprintf("per_ip %s planning", limitPerIPOperationLabel(operation))
	if execute {
		action = fmt.Sprintf("real per_ip %s execution", limitPerIPOperationLabel(operation))
	}

	return action
}

func resultsHaveFailures(results []tc.Result) bool {
	for _, result := range results {
		if strings.TrimSpace(result.Error) != "" {
			return true
		}
	}

	return false
}

func writeExecutionStatusText(w io.Writer, prefix string, blocked bool, note string, results []tc.Result) {
	switch {
	case blocked:
		_, _ = fmt.Fprintf(w, "%sExecution status: blocked\n", prefix)
	case resultsHaveFailures(results):
		_, _ = fmt.Fprintf(w, "%sExecution status: failed\n", prefix)
	}
	if note != "" {
		_, _ = fmt.Fprintf(w, "%sExecution note: %s\n", prefix, note)
	}
}

func describePerIPEntryOutcome(mode string, entry limitPerIPEntryReport) string {
	switch {
	case entry.ExecutionBlocked:
		return "blocked"
	case resultsHaveFailures(entry.Results):
		return "failed"
	case entry.Plan == nil:
		return "no changes"
	case mode == "dry-run":
		return "plan ready"
	case len(entry.Results) == 0:
		return "no changes"
	default:
		return "executed"
	}
}

func describePerIPEntryWork(mode string, entry limitPerIPEntryReport) string {
	switch {
	case entry.ExecutionBlocked:
		return "No concrete commands were run."
	case resultsHaveFailures(entry.Results):
		return fmt.Sprintf("Execution stopped after %d command(s).", len(entry.Results))
	case entry.Plan == nil:
		return "No concrete tc changes are required."
	case mode == "dry-run":
		return fmt.Sprintf("Planned %d command(s).", len(entry.Results))
	case len(entry.Results) == 0:
		return "No concrete commands were run."
	default:
		return fmt.Sprintf("Executed %d command(s).", len(entry.Results))
	}
}

func limitPerIPReconcileStateFromEvidenceState(state discovery.SessionEvidenceState) limitPerIPReconcileState {
	switch state {
	case discovery.SessionEvidenceStateInsufficient:
		return limitPerIPReconcileStateInsufficientEvidence
	case discovery.SessionEvidenceStateUnavailable:
		return limitPerIPReconcileStateUnavailableEvidence
	case discovery.SessionEvidenceStateNoSessions:
		return limitPerIPReconcileStateNoSessions
	default:
		return ""
	}
}

func limitPerIPReconcileStateFromEntries(entries []limitPerIPEntryReport) limitPerIPReconcileState {
	if len(entries) == 0 {
		return limitPerIPReconcileStateNoObservedManaged
	}

	observedCount := 0
	for _, entry := range entries {
		if limitPerIPEntryHasObservedManagedState(entry) {
			observedCount++
		}
	}

	switch {
	case observedCount == 0:
		return limitPerIPReconcileStateNoObservedManaged
	case observedCount != len(entries):
		return limitPerIPReconcileStatePartialObservedState
	default:
		return limitPerIPReconcileStateObservedManagedState
	}
}

func limitPerIPEntryHasObservedManagedState(entry limitPerIPEntryReport) bool {
	if len(entry.Applied) != 0 {
		return true
	}
	if entry.ReconcileInput == nil {
		return false
	}

	for _, object := range entry.ReconcileInput.Observed.Objects {
		if object.Kind != tc.ManagedObjectRootQDisc {
			return true
		}
	}

	return false
}

func limitPeriodicReconcileInput(subject limiter.Subject, desired *limiter.DesiredState, observedState limitObservedState, plan *tc.Plan, scope tc.Scope, operation limitOperation) (*tc.PeriodicReconcileInput, error) {
	basisPlan, ok, err := limitManagedStatePlan(subject, desired, observedState, plan, scope, operation)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	snapshot := observedState.TCSnapshot
	if strings.TrimSpace(snapshot.Device) == "" {
		snapshot = tc.Snapshot{Device: scope.Device}
	}

	input, err := tc.ReconcileInputForPlan(snapshot, observedState.NFTSnapshot, basisPlan)
	if err != nil {
		return nil, err
	}

	return &input, nil
}

func limitManagedStatePlan(subject limiter.Subject, desired *limiter.DesiredState, observedState limitObservedState, plan *tc.Plan, scope tc.Scope, operation limitOperation) (tc.Plan, bool, error) {
	if plan != nil {
		return *plan, true, nil
	}
	if desired == nil && operation != limitOperationRemove {
		return tc.Plan{}, false, nil
	}

	basis := observedState.InspectPlan
	basis.Action = limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: subject,
		Desired: desired,
	}
	if operation == limitOperationRemove {
		basis.Action = limiter.Action{
			Kind:    limiter.ActionRemove,
			Subject: subject,
			Applied: append([]limiter.AppliedState(nil), observedState.Applied...),
		}
	}
	basis.Scope = scope
	if err := basis.Validate(); err != nil {
		return tc.Plan{}, false, err
	}

	return basis, true, nil
}

func copyPeriodicReconcileInput(input *tc.PeriodicReconcileInput) *tc.PeriodicReconcileInput {
	if input == nil {
		return nil
	}

	copied := tc.PeriodicReconcileInput{
		Desired: tc.ManagedStateSet{
			OwnerKey: input.Desired.OwnerKey,
			Objects:  append([]tc.ManagedObject(nil), input.Desired.Objects...),
		},
		Observed: tc.ManagedStateSet{
			OwnerKey: input.Observed.OwnerKey,
			Objects:  append([]tc.ManagedObject(nil), input.Observed.Objects...),
		},
		RetainEvidence: input.RetainEvidence,
	}

	return &copied
}

func limitPerIPSharedRemoveCleanup(previews []limitConcretePreviewResult) (int, *tc.Plan, error) {
	if len(previews) == 0 {
		return -1, nil, nil
	}

	for _, preview := range previews {
		if !preview.ObservedState.Observation.Available || preview.ReconcileInput == nil {
			return -1, nil, nil
		}
	}

	for index := len(previews) - 1; index >= 0; index-- {
		if previews[index].Plan != nil && planHasStepNamed(previews[index].Plan.Steps, "delete-root-qdisc") {
			return -1, nil, nil
		}
	}

	observed := limitPerIPObservedManagedObjects(previews)
	if len(observed) == 0 {
		return -1, nil, nil
	}

	rootHandle := strings.TrimSpace(previews[0].ObservedState.InspectPlan.Handles.RootHandle)
	snapshot := previews[0].ObservedState.TCSnapshot
	if rootHandle == "" || strings.TrimSpace(snapshot.Device) == "" {
		return -1, nil, nil
	}
	if !snapshot.EligibleForRootQDiscCleanupAfterManagedObjectRemoval(rootHandle, observed) {
		return -1, nil, nil
	}

	index := limitPerIPSharedCleanupOwnerIndex(previews)
	if index == -1 {
		return -1, nil, nil
	}

	if previews[index].Plan != nil {
		updated, err := tc.AppendRootQDiscCleanup(*previews[index].Plan)
		if err != nil {
			return -1, nil, err
		}
		return index, &updated, nil
	}

	basis := previews[index].ObservedState.InspectPlan
	basis.Action = limiter.Action{
		Kind:    limiter.ActionRemove,
		Subject: previews[index].Subject,
		Applied: append([]limiter.AppliedState(nil), previews[index].ObservedState.Applied...),
	}
	basis.NoOp = false
	basis.Steps = nil
	updated, err := tc.AppendRootQDiscCleanup(basis)
	if err != nil {
		return -1, nil, err
	}

	return index, &updated, nil
}

func limitPerIPObservedManagedObjects(previews []limitConcretePreviewResult) []tc.ManagedObject {
	seen := make(map[string]struct{})
	objects := make([]tc.ManagedObject, 0)
	for _, preview := range previews {
		if preview.ReconcileInput == nil {
			continue
		}
		for _, object := range preview.ReconcileInput.Observed.Objects {
			key := object.Key()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			objects = append(objects, object)
		}
	}
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Key() < objects[j].Key()
	})

	return objects
}

func limitPerIPSharedCleanupOwnerIndex(previews []limitConcretePreviewResult) int {
	for index := len(previews) - 1; index >= 0; index-- {
		if previews[index].Plan != nil {
			return index
		}
	}
	if len(previews) == 0 {
		return -1
	}

	return len(previews) - 1
}

func limitPerIPSharedCleanupDecisionReason() string {
	return "the expanded per_ip remove set leaves only the managed root qdisc in observed state; remove that shared root qdisc as final cleanup for the current visible client IP set"
}

func limitFinalizePerIPExpansion(operation limitOperation, previews []limitConcretePreviewResult, expansion *limitPerIPExpansionReport) error {
	if operation == limitOperationRemove {
		cleanupIndex, cleanupPlan, err := limitPerIPSharedRemoveCleanup(previews)
		if err != nil {
			return fmt.Errorf("failed to derive shared per_ip remove cleanup: %w", err)
		}
		if cleanupPlan != nil {
			previews[cleanupIndex].Plan = cleanupPlan
			previews[cleanupIndex].Report.Plan = cleanupPlan
			expansion.Entries[cleanupIndex].Plan = cleanupPlan
			if expansion.Entries[cleanupIndex].Decision == nil || expansion.Entries[cleanupIndex].Decision.Kind == limiter.DecisionNoOp {
				expansion.Entries[cleanupIndex].Decision = &limitDecisionReport{
					Kind:   limiter.DecisionRemove,
					Reason: limitPerIPSharedCleanupDecisionReason(),
				}
			}
		}
	}

	expansion.DecisionSummary = limitPerIPDecisionSummaryFromEntries(expansion.Entries)
	expansion.ReconcileState = limitPerIPReconcileStateFromEntries(expansion.Entries)
	if operation == limitOperationRemove &&
		expansion.ReconcileState == limitPerIPReconcileStateNoObservedManaged &&
		expansion.hasPlan() {
		expansion.ReconcileState = limitPerIPReconcileStateObservedManagedState
	}

	return nil
}

func limitPerIPDecisionSummaryFromEntries(entries []limitPerIPEntryReport) *limitPerIPDecisionSummary {
	if len(entries) == 0 {
		return nil
	}

	summary := &limitPerIPDecisionSummary{}
	for _, entry := range entries {
		if entry.Decision == nil {
			continue
		}
		switch entry.Decision.Kind {
		case limiter.DecisionNoOp:
			summary.NoOp++
		case limiter.DecisionApply:
			summary.Apply++
		case limiter.DecisionReplace:
			summary.Replace++
		case limiter.DecisionRemove:
			summary.Remove++
		}
	}
	if !summary.hasData() {
		return nil
	}

	return summary
}

func limitPerIPPreviewIssuesBlocked(issues []limitPerIPPreviewIssue) bool {
	if len(issues) == 0 {
		return false
	}

	for _, issue := range issues {
		if !issue.ExecutionBlocked {
			return false
		}
	}

	return true
}

func limitPerIPPreviewIssuesMessage(operation limitOperation, issues []limitPerIPPreviewIssue, execute bool) string {
	details := make([]string, 0, len(issues))
	for _, issue := range issues {
		message := strings.TrimSpace(issue.ExecutionNote)
		if message == "" && issue.Err != nil {
			message = strings.TrimSpace(issue.Err.Error())
		}
		if message == "" {
			message = "unknown preparation error"
		}
		details = append(details, fmt.Sprintf("%s (%s)", describeLimitTarget(issue.Target), message))
	}

	state := "could not prepare"
	if limitPerIPPreviewIssuesBlocked(issues) {
		state = "was blocked"
	}

	return fmt.Sprintf(
		"%s %s for %d expanded target(s): %s",
		limitPerIPActivityLabel(operation, execute),
		state,
		len(issues),
		strings.Join(details, "; "),
	)
}

func (a App) limitState(session discovery.Session, target limitTargetSelection, options limitOptions) (limiter.Subject, *limiter.DesiredState, error) {
	targetRule, err := target.policyTarget()
	if err != nil {
		return limiter.Subject{}, nil, fmt.Errorf("failed to construct policy target: %w", err)
	}

	subject, err := limiter.SubjectFromTarget(targetRule, session)
	if err != nil {
		return limiter.Subject{}, nil, fmt.Errorf("failed to construct limiter subject: %w", err)
	}

	if options.operation == limitOperationRemove {
		return subject, nil, nil
	}

	policyRule := policy.Policy{
		Name:   "cli-limit-request",
		Target: targetRule,
	}
	if options.unlimited {
		policyRule.Effect = policy.EffectExclude
	} else {
		policyRule.Limits = limitPolicyForDirection(options.direction, options.rateBytes)
	}

	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		policyRule,
	}, session)
	if err != nil {
		return limiter.Subject{}, nil, fmt.Errorf("failed to evaluate limit policy: %w", err)
	}

	desired, err := limiter.DesiredStateFromEvaluation(session, evaluation)
	if err != nil {
		return limiter.Subject{}, nil, fmt.Errorf("failed to construct desired limiter state: %w", err)
	}

	return subject, &desired, nil
}

func (a App) observeLimitState(ctx context.Context, target discovery.RuntimeTarget, subject limiter.Subject, desired *limiter.DesiredState, scope tc.Scope, operation limitOperation) (limitObservedState, error) {
	inspectAction := limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: subject,
	}

	inspectPlan, err := a.planWithAttachments(ctx, target, inspectAction, scope)
	if err != nil {
		return limitObservedState{}, err
	}
	if desired != nil {
		mode := desired.Mode
		execution, err := tc.BuildDirectAttachmentExecution(inspectPlan.Binding, scope, mode, inspectAttachmentClassID(mode, inspectPlan.Handles.ClassID))
		if err != nil {
			return limitObservedState{}, err
		}
		inspectPlan.AttachmentExecution = execution
		if err := inspectPlan.Validate(); err != nil {
			return limitObservedState{}, err
		}
	}

	observation := limitObservationReport{
		ExpectedClassID: inspectPlan.Handles.ClassID,
	}

	snapshot, _, inspectErr := a.inspector().Inspect(ctx, tc.InspectRequest{Device: scope.Device})
	if inspectErr != nil {
		observation.Error = fmt.Sprintf("tc state inspection failed: %v", inspectErr)
		return limitObservedState{
			Observation: observation,
			InspectPlan: inspectPlan,
		}, nil
	}

	observation.Available = true
	observation.Reconcilable = true

	attachmentObservation, err := a.observeAttachmentState(ctx, inspectPlan, snapshot)
	if err != nil {
		return limitObservedState{}, err
	}
	if attachmentObservation.Comparable {
		observation.AttachmentMatched = boolPtr(attachmentObservation.Matched)
	}
	if attachmentObservation.Error != "" {
		observation.Reconcilable = false
		observation.Error = attachmentObservation.Error
	}

	applied := make([]limiter.AppliedState, 0, 2)

	class, ok := snapshot.Class(observation.ExpectedClassID)
	if ok {
		observation.Matched = true
		observation.ObservedClassID = class.ClassID

		limitApplied, err := class.AppliedState(subject, scope.Direction)
		if err != nil {
			if operation == limitOperationRemove {
				observation.Error = fmt.Sprintf("observed class %s could not be fully parsed: %v", class.ClassID, err)
				return limitObservedState{
					Observation: observation,
					InspectPlan: inspectPlan,
					TCSnapshot:  snapshot,
					NFTSnapshot: attachmentObservation.NFTSnapshot,
				}, nil
			}

			observation.Reconcilable = false
			observation.Error = fmt.Sprintf("observed class %s could not be reconciled: %v", class.ClassID, err)
			return limitObservedState{
				Observation: observation,
				InspectPlan: inspectPlan,
				TCSnapshot:  snapshot,
				NFTSnapshot: attachmentObservation.NFTSnapshot,
			}, nil
		}

		applied = append(applied, limitApplied)
		observation.ObservedRateBytes = observedRateBytes(limitApplied, scope.Direction)
	}

	unlimitedApplied, hasUnlimited, err := observedUnlimitedAppliedState(subject, inspectPlan.Binding, scope, inspectPlan.Handles.RootHandle, snapshot)
	if err != nil {
		return limitObservedState{}, err
	}
	if hasUnlimited {
		applied = append(applied, unlimitedApplied)
	}
	if operation == limitOperationRemove {
		comparable, matched, err := observedRemoveDirectAttachmentMatch(subject, inspectPlan.Binding, scope, inspectPlan.Handles.RootHandle, inspectPlan.Handles.ClassID, snapshot)
		if err != nil {
			return limitObservedState{}, err
		}
		if comparable {
			observation.AttachmentMatched = boolPtr(matched)
		}
	}

	if operation == limitOperationRemove {
		switch {
		case inspectPlan.MarkAttachment != nil && inspectPlan.MarkAttachment.Readiness == tc.BindingReadinessReady:
			observation.CleanupRootQDisc = snapshot.EligibleForRootQDiscCleanupAfterMarkAttachmentRemoval(
				inspectPlan.Handles.RootHandle,
				observation.ExpectedClassID,
				*inspectPlan.MarkAttachment,
			)
		case containsAppliedMode(applied, limiter.DesiredModeLimit):
			limitExecution, err := tc.BuildDirectAttachmentExecution(inspectPlan.Binding, scope, limiter.DesiredModeLimit, inspectPlan.Handles.ClassID)
			if err != nil {
				return limitObservedState{}, err
			}
			observation.CleanupRootQDisc = snapshot.EligibleForRootQDiscCleanupAfterDirectAttachmentRemoval(
				inspectPlan.Handles.RootHandle,
				observation.ExpectedClassID,
				limitExecution,
			)
		case containsAppliedMode(applied, limiter.DesiredModeUnlimited):
			unlimitedExecution, err := tc.BuildDirectAttachmentExecution(inspectPlan.Binding, scope, limiter.DesiredModeUnlimited, "")
			if err != nil {
				return limitObservedState{}, err
			}
			observation.CleanupRootQDisc = snapshot.EligibleForRootQDiscCleanupAfterDirectAttachmentRemoval(
				inspectPlan.Handles.RootHandle,
				observation.ExpectedClassID,
				unlimitedExecution,
			)
		case observation.Matched:
			observation.CleanupRootQDisc = snapshot.EligibleForRootQDiscCleanup(inspectPlan.Handles.RootHandle, observation.ExpectedClassID)
		}
	}

	return limitObservedState{
		Observation: observation,
		InspectPlan: inspectPlan,
		Applied:     applied,
		TCSnapshot:  snapshot,
		NFTSnapshot: attachmentObservation.NFTSnapshot,
	}, nil
}

func (a App) limitPlan(ctx context.Context, target discovery.RuntimeTarget, action limiter.Action, scope tc.Scope, observedState limitObservedState, operation limitOperation) (tc.Plan, error) {
	plan, err := a.planWithAttachments(ctx, target, action, scope)
	if err != nil {
		return tc.Plan{}, err
	}
	if plan.MarkAttachment != nil && plan.MarkAttachment.Readiness == tc.BindingReadinessReady {
		switch action.Kind {
		case limiter.ActionApply, limiter.ActionReconcile:
			plan, err = tc.AppendMarkAttachmentApply(plan, observedState.TCSnapshot, observedState.NFTSnapshot)
		case limiter.ActionRemove:
			plan, err = tc.AppendMarkAttachmentRemove(plan, observedState.TCSnapshot, observedState.NFTSnapshot)
		}
		if err != nil {
			return tc.Plan{}, err
		}
	} else if action.Kind == limiter.ActionRemove &&
		plan.AttachmentExecution.Readiness == tc.BindingReadinessReady &&
		observedState.Observation.Available {
		plan, err = tc.AppendObservedDirectAttachmentCleanup(plan, observedState.TCSnapshot)
		if err != nil {
			return tc.Plan{}, err
		}
	}
	if operation == limitOperationRemove && observedState.Observation.CleanupRootQDisc && !planHasStepNamed(plan.Steps, "delete-root-qdisc") {
		plan, err = tc.AppendRootQDiscCleanup(plan)
		if err != nil {
			return tc.Plan{}, err
		}
	}

	return plan, nil
}

func (a App) limitDecision(operation limitOperation, subject limiter.Subject, desired *limiter.DesiredState, observation limitObservationReport, applied []limiter.AppliedState) (limiter.Decision, error) {
	if operation == limitOperationRemove {
		return removeLimitDecision(subject, observation, applied)
	}

	if desired != nil &&
		observation.Reconcilable &&
		observation.AttachmentMatched != nil &&
		!*observation.AttachmentMatched &&
		len(applied) == 1 &&
		applied[0].MatchesDesired(*desired) {
		decision := limiter.Decision{
			Kind:    limiter.DecisionApply,
			Subject: &subject,
			Desired: desired,
			Reason:  attachmentReapplyDecisionReason(subject),
		}
		if err := decision.Validate(); err != nil {
			return limiter.Decision{}, err
		}

		return decision, nil
	}

	if observation.Reconcilable {
		return (limiter.Reconciler{}).Decide(desired, applied)
	}

	decision := limiter.Decision{
		Kind:    limiter.DecisionApply,
		Subject: &subject,
		Desired: desired,
		Reason:  fallbackLimitDecisionReason(observation),
	}
	if err := decision.Validate(); err != nil {
		return limiter.Decision{}, err
	}

	return decision, nil
}

func attachmentReapplyDecisionReason(subject limiter.Subject) string {
	switch subject.Kind {
	case policy.TargetKindInbound, policy.TargetKindOutbound:
		return "matching class already satisfies the requested rate, but the expected mark-backed attachment rules were not observed; reapply the class and concrete attachment rules"
	default:
		return "matching direct class already satisfies the requested rate, but the expected direct attachment rules were not observed; reapply the class and concrete attachment rules"
	}
}

func blockedInboundApplyExecutionNote(plan tc.Plan) string {
	if plan.MarkAttachment != nil && strings.TrimSpace(plan.MarkAttachment.Reason) != "" {
		return fmt.Sprintf("real inbound apply execution requires one concrete inbound mark-backed attachment path; %s", strings.TrimSpace(plan.MarkAttachment.Reason))
	}

	return "real inbound apply execution requires one concrete inbound mark-backed attachment path for the selected inbound tag"
}

func blockedInboundRemoveExecutionNote(plan tc.Plan) string {
	if plan.MarkAttachment != nil && strings.TrimSpace(plan.MarkAttachment.Reason) != "" {
		return fmt.Sprintf("real inbound remove execution requires the same concrete inbound mark-backed attachment path used for apply cleanup; %s", strings.TrimSpace(plan.MarkAttachment.Reason))
	}

	return "real inbound remove execution requires the same concrete inbound mark-backed attachment path used for apply cleanup"
}

func blockedOutboundApplyExecutionNote(plan tc.Plan) string {
	if plan.MarkAttachment != nil && strings.TrimSpace(plan.MarkAttachment.Reason) != "" {
		return fmt.Sprintf("real outbound apply execution requires one concrete outbound mark-backed attachment path; %s", strings.TrimSpace(plan.MarkAttachment.Reason))
	}

	return "real outbound apply execution requires one concrete outbound mark-backed attachment path for the selected outbound tag"
}

func blockedOutboundRemoveExecutionNote(plan tc.Plan) string {
	if plan.MarkAttachment != nil && strings.TrimSpace(plan.MarkAttachment.Reason) != "" {
		return fmt.Sprintf("real outbound remove execution requires the same concrete outbound mark-backed attachment path used for apply cleanup; %s", strings.TrimSpace(plan.MarkAttachment.Reason))
	}

	return "real outbound remove execution requires the same concrete outbound mark-backed attachment path used for apply cleanup"
}

func (a App) planner() tcPlanner {
	if a.limiterPlanner != nil {
		return a.limiterPlanner
	}

	return tc.Planner{}
}

func (a App) inspector() tcStateInspector {
	if a.tcInspector != nil {
		return a.tcInspector
	}

	return tc.Inspector{Runner: a.tcRunner}
}

func (a App) nftablesInspector() nftablesStateInspector {
	if a.nftInspector != nil {
		return a.nftInspector
	}

	return tc.NftablesInspector{Runner: a.tcRunner}
}

func (a App) inboundSelectorDeriver() inboundMarkSelectorDeriver {
	if a.inboundSelector != nil {
		return a.inboundSelector
	}

	return discovery.NewInboundMarkSelectorDeriver()
}

func (a App) outboundSelectorDeriver() outboundMarkSelectorDeriver {
	if a.outboundSelector != nil {
		return a.outboundSelector
	}

	return discovery.NewOutboundMarkSelectorDeriver()
}

func (a App) sessionEvidenceProvider() sessionEvidenceProvider {
	if a.sessionEvidence != nil {
		return a.sessionEvidence
	}

	provider := discovery.NewXraySessionEvidenceProvider(a.discovery)
	return provider
}

func (a App) planWithAttachments(ctx context.Context, target discovery.RuntimeTarget, action limiter.Action, scope tc.Scope) (tc.Plan, error) {
	plan, err := a.planner().Plan(action, scope)
	if err != nil {
		return tc.Plan{}, err
	}

	if plan.Binding.Identity == nil {
		return plan, nil
	}

	switch plan.Binding.Identity.Kind {
	case tc.IdentityKindInbound:
		selectorResult, err := a.inboundSelectorDeriver().Derive(ctx, target, plan.Binding.Identity.Value)
		if err != nil {
			return tc.Plan{}, err
		}
		if selectorResult.Selector == nil {
			execution := tc.MarkAttachmentExecution{
				Identity: *plan.Binding.Identity,
				Filter: tc.MarkAttachmentFilterSpec{
					Parent:  plan.Handles.RootHandle,
					ClassID: plan.Handles.ClassID,
				},
				Readiness:  tc.BindingReadinessUnavailable,
				Confidence: tc.BindingConfidenceMedium,
				Reason:     strings.TrimSpace(selectorResult.Reason),
			}
			plan.MarkAttachment = &execution
			if err := plan.Validate(); err != nil {
				return tc.Plan{}, err
			}
			return plan, nil
		}

		execution, err := tc.BuildMarkAttachmentExecution(tc.MarkAttachmentInput{
			Identity: *plan.Binding.Identity,
			Scope:    scope,
			ClassID:  plan.Handles.ClassID,
			Selector: tc.MarkAttachmentSelector{
				Expression:  append([]string(nil), selectorResult.Selector.Expression...),
				Description: selectorResult.Selector.Description,
			},
			Confidence: tc.BindingConfidenceHigh,
		})
		if err != nil {
			return tc.Plan{}, err
		}
		plan.MarkAttachment = &execution
	case tc.IdentityKindOutbound:
		selectorResult, err := a.outboundSelectorDeriver().Derive(ctx, target, plan.Binding.Identity.Value)
		if err != nil {
			return tc.Plan{}, err
		}
		if selectorResult.Selector == nil {
			execution := tc.MarkAttachmentExecution{
				Identity: *plan.Binding.Identity,
				Filter: tc.MarkAttachmentFilterSpec{
					Parent:  plan.Handles.RootHandle,
					ClassID: plan.Handles.ClassID,
				},
				Readiness:  tc.BindingReadinessUnavailable,
				Confidence: tc.BindingConfidenceMedium,
				Reason:     strings.TrimSpace(selectorResult.Reason),
			}
			plan.MarkAttachment = &execution
			if err := plan.Validate(); err != nil {
				return tc.Plan{}, err
			}
			return plan, nil
		}

		execution, err := tc.BuildMarkAttachmentExecution(tc.MarkAttachmentInput{
			Identity: *plan.Binding.Identity,
			Scope:    scope,
			ClassID:  plan.Handles.ClassID,
			Selector: tc.MarkAttachmentSelector{
				Expression:  append([]string(nil), selectorResult.Selector.Expression...),
				Description: selectorResult.Selector.Description,
			},
			PacketMark: selectorResult.Selector.SocketMark,
			Confidence: tc.BindingConfidenceMedium,
		})
		if err != nil {
			return tc.Plan{}, err
		}
		plan.MarkAttachment = &execution
	default:
		return plan, nil
	}
	if err := plan.Validate(); err != nil {
		return tc.Plan{}, err
	}

	return plan, nil
}

func (a App) observeAttachmentState(ctx context.Context, inspectPlan tc.Plan, snapshot tc.Snapshot) (limitAttachmentObservation, error) {
	if inspectPlan.MarkAttachment != nil && inspectPlan.MarkAttachment.Readiness == tc.BindingReadinessReady {
		nftSnapshot, _, err := a.nftablesInspector().Inspect(ctx)
		if err != nil {
			return limitAttachmentObservation{
				Error:       fmt.Sprintf("nftables state inspection failed: %v", err),
				NFTSnapshot: nftSnapshot,
			}, nil
		}

		observation, err := tc.ObserveMarkAttachment(snapshot, nftSnapshot, *inspectPlan.MarkAttachment)
		if err != nil {
			return limitAttachmentObservation{}, err
		}

		return limitAttachmentObservation{
			Comparable:  observation.Comparable,
			Matched:     observation.Matched,
			NFTSnapshot: nftSnapshot,
		}, nil
	}

	observation, err := tc.ObserveDirectAttachment(snapshot, inspectPlan)
	if err != nil {
		return limitAttachmentObservation{}, err
	}

	return limitAttachmentObservation{
		Comparable: observation.Comparable,
		Matched:    observation.Matched,
	}, nil
}

func planHasStepNamed(steps []tc.Step, name string) bool {
	for _, step := range steps {
		if strings.TrimSpace(step.Name) == strings.TrimSpace(name) {
			return true
		}
	}

	return false
}

func inspectAttachmentClassID(mode limiter.DesiredMode, classID string) string {
	if mode == limiter.DesiredModeUnlimited {
		return ""
	}

	return classID
}

func containsAppliedMode(applied []limiter.AppliedState, mode limiter.DesiredMode) bool {
	for _, state := range applied {
		if state.Mode == mode {
			return true
		}
	}

	return false
}

func observedUnlimitedAppliedState(subject limiter.Subject, binding tc.Binding, scope tc.Scope, rootHandle string, snapshot tc.Snapshot) (limiter.AppliedState, bool, error) {
	if subject.Kind != policy.TargetKindIP || subject.All {
		return limiter.AppliedState{}, false, nil
	}

	execution, err := tc.BuildDirectAttachmentExecution(binding, scope, limiter.DesiredModeUnlimited, "")
	if err != nil {
		return limiter.AppliedState{}, false, err
	}
	if execution.Readiness != tc.BindingReadinessReady {
		return limiter.AppliedState{}, false, nil
	}

	filters := snapshot.DirectAttachmentFilters(rootHandle, "", execution)
	if len(filters) == 0 {
		return limiter.AppliedState{}, false, nil
	}

	applied := limiter.AppliedState{
		Mode:    limiter.DesiredModeUnlimited,
		Subject: subject,
		Driver:  "tc",
	}
	if err := applied.Validate(); err != nil {
		return limiter.AppliedState{}, false, err
	}

	return applied, true, nil
}

func observedRemoveDirectAttachmentMatch(subject limiter.Subject, binding tc.Binding, scope tc.Scope, rootHandle string, classID string, snapshot tc.Snapshot) (bool, bool, error) {
	if subject.Kind != policy.TargetKindIP || subject.All {
		return false, false, nil
	}

	comparable := false
	for _, mode := range []limiter.DesiredMode{limiter.DesiredModeUnlimited, limiter.DesiredModeLimit} {
		execution, err := tc.BuildDirectAttachmentExecution(binding, scope, mode, inspectAttachmentClassID(mode, classID))
		if err != nil {
			return false, false, err
		}
		if execution.Readiness != tc.BindingReadinessReady {
			continue
		}
		comparable = true
		if len(snapshot.DirectAttachmentFilters(rootHandle, inspectAttachmentClassID(mode, classID), execution)) != 0 {
			return true, true, nil
		}
	}

	return comparable, false, nil
}

func limitMode(execute bool) string {
	if execute {
		return "execute"
	}

	return "dry-run"
}

func countSelections(active ...bool) int {
	count := 0
	for _, selected := range active {
		if selected {
			count++
		}
	}

	return count
}

func limitPolicyForDirection(direction tc.Direction, rateBytes int64) policy.LimitPolicy {
	limit := &policy.RateLimit{BytesPerSecond: rateBytes}
	switch direction {
	case tc.DirectionUpload:
		return policy.LimitPolicy{Upload: limit}
	case tc.DirectionDownload:
		return policy.LimitPolicy{Download: limit}
	default:
		return policy.LimitPolicy{}
	}
}

func fallbackLimitDecisionReason(observation limitObservationReport) string {
	if observation.summaryError() != "" {
		return observation.summaryError() + "; proceeding with an apply plan without comparable observed state"
	}

	return "tc state could not be compared; proceeding with an apply plan without observed state"
}

func removeLimitDecision(subject limiter.Subject, observation limitObservationReport, applied []limiter.AppliedState) (limiter.Decision, error) {
	if observation.Reconcilable {
		switch {
		case len(applied) != 0:
			return (limiter.Reconciler{}).Decide(nil, applied)
		case observation.Matched:
			decision := limiter.Decision{
				Kind:    limiter.DecisionRemove,
				Subject: &subject,
				Reason:  "matching class-backed state was observed for the selected target rule set",
			}
			if err := decision.Validate(); err != nil {
				return limiter.Decision{}, err
			}
			return decision, nil
		case observation.AttachmentMatched != nil && *observation.AttachmentMatched:
			decision := limiter.Decision{
				Kind:    limiter.DecisionRemove,
				Subject: &subject,
				Reason:  "managed attachment rules were observed for the selected target rule set",
			}
			if err := decision.Validate(); err != nil {
				return limiter.Decision{}, err
			}
			return decision, nil
		default:
			decision := limiter.Decision{
				Kind:    limiter.DecisionNoOp,
				Subject: &subject,
				Reason:  "no applied state matching the selected target rule set was observed",
			}
			if err := decision.Validate(); err != nil {
				return limiter.Decision{}, err
			}
			return decision, nil
		}
	}

	decision := limiter.Decision{
		Kind:    limiter.DecisionRemove,
		Subject: &subject,
		Reason:  fallbackRemoveDecisionReason(observation),
	}
	if err := decision.Validate(); err != nil {
		return limiter.Decision{}, err
	}

	return decision, nil
}

func observedRateBytes(applied limiter.AppliedState, direction tc.Direction) int64 {
	switch direction {
	case tc.DirectionUpload:
		if applied.Limits.Upload != nil {
			return applied.Limits.Upload.BytesPerSecond
		}
	case tc.DirectionDownload:
		if applied.Limits.Download != nil {
			return applied.Limits.Download.BytesPerSecond
		}
	}

	return 0
}

func missingObservedStateMessage(observation limitObservationReport) string {
	if message := observation.summaryError(); message != "" {
		return message
	}

	return "tc state could not be observed or compared"
}

func missingObservedStateExecutionNote(observation limitObservationReport) string {
	return fmt.Sprintf(
		"real execution requires observed tc state; %s; rerun with --allow-missing-tc-state to execute without observation",
		missingObservedStateMessage(observation),
	)
}

func missingObservedMarkAttachmentExecutionNote(observation limitObservationReport) string {
	return fmt.Sprintf(
		"concrete mark-backed execution requires observed tc and nftables state; %s",
		missingObservedStateMessage(observation),
	)
}

func missingObservedOutboundRemoveExecutionNote(err error) string {
	return fmt.Sprintf(
		"real outbound remove execution requires observed nftables state when concrete outbound mark-backed cleanup cannot be derived from current config: %v",
		err,
	)
}

func missingObservedInboundRemoveExecutionNote(err error) string {
	return fmt.Sprintf(
		"real inbound remove execution requires observed nftables state when concrete inbound mark-backed cleanup cannot be derived from current config: %v",
		err,
	)
}

func fallbackRemoveDecisionReason(observation limitObservationReport) string {
	if observation.summaryError() != "" {
		return observation.summaryError() + "; proceeding with a remove plan without comparable observed state"
	}

	return "tc state could not be compared; proceeding with a remove plan without observed state"
}

func writeLimitReport(w io.Writer, format discovery.OutputFormat, report limitReport) error {
	switch format {
	case discovery.OutputFormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case discovery.OutputFormatText:
		writeLimitText(w, report)
		return nil
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}

func limitPolicyEvaluationFromEvaluation(evaluation policy.Evaluation) *limitPolicyEvaluationReport {
	if !evaluation.HasMatch() {
		return nil
	}

	report := limitPolicyEvaluationReport{
		PrecedenceOrder:   policy.DescribeTargetKindPrecedence(),
		WinningKind:       evaluation.Selection.Kind,
		WinningPrecedence: evaluation.Selection.Precedence,
		EffectiveLimits:   evaluation.EffectiveLimits,
		EffectiveReason:   evaluation.EffectiveReason,
		Matches:           orderedPolicyMatchesForReport(evaluation.Matches),
		Winning:           orderedPolicyMatchesForReport(evaluation.WinningPolicies()),
		NonWinning:        orderedPolicyMatchesForReport(evaluation.NonWinningPolicies()),
	}

	return &report
}

func orderedPolicyMatchesForReport(matches []policy.Match) []policy.Match {
	ordered := append([]policy.Match(nil), matches...)
	sort.SliceStable(ordered, func(left, right int) bool {
		if ordered[left].Precedence != ordered[right].Precedence {
			return ordered[left].Precedence > ordered[right].Precedence
		}

		return ordered[left].Index < ordered[right].Index
	})

	return ordered
}

func limitTargetReportFromSelection(selection limitTargetSelection) limitTargetReport {
	target, err := selection.policyTarget()
	if err != nil {
		report := limitTargetReport{
			Kind:  selection.Kind(),
			Value: strings.TrimSpace(selection.Value()),
		}
		if report.Kind == policy.TargetKindIP && strings.EqualFold(report.Value, "all") {
			report.Value = "all"
			report.IPAggregation = selection.NormalizedIPAggregation()
		}

		return report
	}

	report := limitTargetReport{
		Kind:          target.Kind,
		IPAggregation: target.NormalizedIPAggregation(),
	}
	if target.Kind == policy.TargetKindIP && target.All {
		report.Value = "all"
	} else {
		report.Value = strings.TrimSpace(target.Value)
	}

	return report
}

func limitDirectAttachmentReportFromPlan(plan tc.Plan) limitDirectAttachmentReport {
	report := limitDirectAttachmentReport{
		ShapingReadiness:             limitShapingReadinessFromPlan(plan),
		AttachmentReadiness:          plan.Binding.Readiness,
		AttachmentExecutionReadiness: plan.AttachmentExecution.Readiness,
		Confidence:                   plan.AttachmentExecution.Confidence,
		Note:                         strings.TrimSpace(plan.Binding.Reason),
		AttachmentExecutionNote:      strings.TrimSpace(plan.AttachmentExecution.Reason),
		AttachmentExecution:          append([]tc.DirectAttachmentRule(nil), plan.AttachmentExecution.Rules...),
	}
	if report.Confidence == "" {
		report.Confidence = plan.Binding.Confidence
	}
	if plan.MarkAttachment != nil {
		report.AttachmentReadiness = plan.MarkAttachment.Readiness
		report.AttachmentExecutionReadiness = plan.MarkAttachment.Readiness
		report.Confidence = plan.MarkAttachment.Confidence
		if note := strings.TrimSpace(plan.MarkAttachment.Rule.Selector.Description); note != "" && plan.MarkAttachment.Readiness == tc.BindingReadinessReady {
			report.Note = note
		} else {
			report.Note = strings.TrimSpace(plan.MarkAttachment.Reason)
		}
		report.AttachmentExecutionNote = strings.TrimSpace(plan.MarkAttachment.Reason)
		report.AttachmentExecution = nil
	}

	return report
}

func limitShapingReadinessFromPlan(plan tc.Plan) tc.BindingReadiness {
	if plan.Action.Subject.Kind == policy.TargetKindIP &&
		plan.Action.Subject.All &&
		plan.Action.Subject.NormalizedIPAggregation() == policy.IPAggregationModePerIP {
		return plan.Binding.Readiness
	}

	return tc.BindingReadinessReady
}

func boolPtr(value bool) *bool {
	return &value
}

func writeLimitText(w io.Writer, report limitReport) {
	_, _ = io.WriteString(w, "Request:\n")
	_, _ = fmt.Fprintf(w, "Mode: %s\n", report.Mode)
	_, _ = fmt.Fprintf(w, "Operation: %s\n", report.Operation)
	_, _ = fmt.Fprintf(w, "Runtime: %s\n", describeLimitRuntime(report.Runtime))
	writeLimitTargetText(w, report.Target)
	if report.PolicyEvaluation != nil && report.PolicyEvaluation.hasCoexistence() {
		writeTextSectionHeading(w, "Policy")
		writeLimitPolicyEvaluationText(w, "", *report.PolicyEvaluation)
	}
	writeTextSectionHeading(w, "Requested state")
	writeRequestedLimitText(w, report.Operation, report.Scope, report.RateBytes, report.Unlimited)
	if report.PerIPExpansion != nil && report.PerIPExpansion.hasData() {
		writeTextSectionHeading(w, "Per-IP expansion")
		writeLimitPerIPExpansionText(w, report.Mode, *report.PerIPExpansion)
	} else {
		if report.DirectAttachment != nil && report.DirectAttachment.hasData() {
			writeTextSectionHeading(w, "Direct attachment")
			writeDirectAttachmentText(w, *report.DirectAttachment)
		}
		if report.Observation != nil {
			writeTextSectionHeading(w, "Observation")
			writeObservationText(w, *report.Observation, "Matching class-backed state")
		}
		if report.Decision != nil {
			writeTextSectionHeading(w, "Decision")
			writeDecisionText(w, *report.Decision)
		}
		if report.Plan != nil {
			cleanupRootQDisc := false
			if report.Observation != nil {
				cleanupRootQDisc = report.Observation.CleanupRootQDisc
			}
			writeTextSectionHeading(w, "Plan")
			writePlanText(w, describePlanAction(*report.Plan), report.Operation, cleanupRootQDisc, report.Plan.Handles.ClassID, shouldShowPlanClassID(*report.Plan), report.Plan.Steps)
		}
	}
	writeTextSectionHeading(w, "Execution")
	writeExecutionStatusText(w, "", report.ExecutionBlocked, report.ExecutionNote, report.Results)
	writeExecutionResultsSection(w, report.Results)
	writeOutcomeSummary(w, report.Mode, report.ExecutionBlocked, report.hasPlannedWork(), report.noOp(), report.Results)
}

func writeLimitPolicyEvaluationText(w io.Writer, prefix string, report limitPolicyEvaluationReport) {
	_, _ = fmt.Fprintf(w, "%sPrecedence order: %s\n", prefix, report.PrecedenceOrder)
	if len(report.Matches) != 0 {
		_, _ = fmt.Fprintf(w, "%sMatched rules: %d total\n", prefix, len(report.Matches))
	}
	_, _ = fmt.Fprintf(w, "%sWinning kind: %s\n", prefix, report.WinningKind)
	if report.WinningPrecedence != 0 {
		_, _ = fmt.Fprintf(w, "%sWinning precedence: %d\n", prefix, report.WinningPrecedence)
	}
	if report.EffectiveReason != "" {
		_, _ = fmt.Fprintf(w, "%sEffective selection reason: %s\n", prefix, report.EffectiveReason)
	}
	if report.EffectiveLimits.HasAny() {
		_, _ = fmt.Fprintf(w, "%sEffective limits: %s\n", prefix, describeLimitPolicy(report.EffectiveLimits))
	}
	if len(report.Winning) != 0 {
		_, _ = fmt.Fprintf(w, "%sWinning matches:\n", prefix)
		for index, match := range report.Winning {
			_, _ = fmt.Fprintf(w, "%s  %d. %s\n", prefix, index+1, describePolicyMatch(match))
		}
	}
	if len(report.NonWinning) != 0 {
		_, _ = fmt.Fprintf(w, "%sNon-winning matches:\n", prefix)
		for index, match := range report.NonWinning {
			_, _ = fmt.Fprintf(w, "%s  %d. %s\n", prefix, index+1, describePolicyMatch(match))
		}
	}
}

func writeDirectAttachmentText(w io.Writer, report limitDirectAttachmentReport) {
	if report.ShapingReadiness != "" {
		_, _ = fmt.Fprintf(w, "Direct shaping readiness: %s\n", report.ShapingReadiness)
	}
	if report.AttachmentReadiness != "" {
		_, _ = fmt.Fprintf(w, "Direct attachment readiness: %s\n", report.AttachmentReadiness)
	}
	if report.AttachmentExecutionReadiness != "" {
		_, _ = fmt.Fprintf(w, "Direct attachment execution readiness: %s\n", report.AttachmentExecutionReadiness)
	}
	if report.Confidence != "" {
		_, _ = fmt.Fprintf(w, "Direct attachment confidence: %s\n", report.Confidence)
	}
	if report.Note != "" {
		_, _ = fmt.Fprintf(w, "Direct attachment note: %s\n", report.Note)
	}
	if report.AttachmentExecutionNote != "" {
		_, _ = fmt.Fprintf(w, "Direct attachment execution note: %s\n", report.AttachmentExecutionNote)
	}
	if len(report.AttachmentExecution) != 0 {
		_, _ = io.WriteString(w, "Direct attachment execution rules:\n")
		for index, rule := range report.AttachmentExecution {
			_, _ = fmt.Fprintf(w, "  %d. %s\n", index+1, describeDirectAttachmentRule(rule))
			if rule.Reason != "" {
				_, _ = fmt.Fprintf(w, "     Execution note: %s\n", rule.Reason)
			}
		}
	}
}

func writeLimitTargetText(w io.Writer, target limitTargetReport) {
	_, _ = fmt.Fprintf(w, "Target: %s\n", describeLimitTarget(target))
	if target.hasIPAggregation() {
		_, _ = fmt.Fprintf(w, "IP aggregation: %s\n", target.IPAggregation)
	}
}

func writeLimitPerIPExpansionText(w io.Writer, mode string, report limitPerIPExpansionReport) {
	if report.Provider != "" {
		_, _ = fmt.Fprintf(w, "Per-IP evidence provider: %s\n", report.Provider)
	}
	if report.State != "" {
		_, _ = fmt.Fprintf(w, "Per-IP evidence state: %s\n", report.State)
	}
	if report.ReconcileState != "" {
		_, _ = fmt.Fprintf(w, "Per-IP reconcile state: %s\n", report.ReconcileState)
	}
	if len(report.ClientIPs) == 0 {
		_, _ = io.WriteString(w, "Visible client IPs: none\n")
	} else {
		_, _ = fmt.Fprintf(w, "Visible client IPs: %d\n", len(report.ClientIPs))
		for index, clientIP := range report.ClientIPs {
			_, _ = fmt.Fprintf(w, "  %d. %s\n", index+1, clientIP)
		}
	}
	if report.Note != "" {
		_, _ = fmt.Fprintf(w, "Per-IP expansion note: %s\n", report.Note)
	}
	if report.DecisionSummary != nil && report.DecisionSummary.hasData() {
		_, _ = fmt.Fprintf(w, "Decision summary: %s\n", report.DecisionSummary.text())
	}
	if len(report.Entries) == 0 {
		return
	}

	_, _ = io.WriteString(w, "Expanded targets:\n")
	for index, entry := range report.Entries {
		_, _ = fmt.Fprintf(w, "  %d. %s\n", index+1, describeLimitTarget(entry.Target))
		if entry.Observation != nil {
			_, _ = fmt.Fprintf(w, "     Observed tc state: %s\n", entry.Observation.stateLabel())
			if entry.Observation.Error != "" {
				_, _ = fmt.Fprintf(w, "     Observation note: %s\n", entry.Observation.Error)
			}
		}
		if entry.Decision != nil && entry.Decision.Kind != "" {
			_, _ = fmt.Fprintf(w, "     Reconcile decision: %s\n", entry.Decision.Kind)
		}
		if entry.Decision != nil && entry.Decision.Reason != "" {
			_, _ = fmt.Fprintf(w, "     Decision reason: %s\n", entry.Decision.Reason)
		}
		_, _ = fmt.Fprintf(w, "     Observed applied states: %d\n", len(entry.Applied))
		for appliedIndex, applied := range entry.Applied {
			_, _ = fmt.Fprintf(w, "       %d. %s\n", appliedIndex+1, describeAppliedState(applied))
		}
		if entry.ReconcileInput != nil {
			if ownerKey := reconcileOwnerKey(*entry.ReconcileInput); ownerKey != "" {
				_, _ = fmt.Fprintf(w, "     Managed owner key: %s\n", ownerKey)
			}
			_, _ = fmt.Fprintf(w, "     Desired managed objects: %d\n", len(entry.ReconcileInput.Desired.Objects))
			_, _ = fmt.Fprintf(w, "     Observed managed objects: %d\n", len(entry.ReconcileInput.Observed.Objects))
		}
		if entry.Plan != nil {
			_, _ = fmt.Fprintf(w, "     Planned action: %s\n", describePerIPPlannedAction(entry))
			if entry.Plan.Action.Kind == limiter.ActionRemove {
				_, _ = fmt.Fprintf(
					w,
					"     Cleanup scope: %s\n",
					cleanupScopeLabel(planHasStepNamed(entry.Plan.Steps, "delete-root-qdisc"), entry.Plan.Steps),
				)
			}
			if shouldShowPlanClassID(*entry.Plan) && entry.Plan.Handles.ClassID != "" {
				_, _ = fmt.Fprintf(w, "     Class ID: %s\n", entry.Plan.Handles.ClassID)
			}
			if len(entry.Plan.Steps) != 0 {
				_, _ = io.WriteString(w, "     Planned commands:\n")
				for stepIndex, step := range entry.Plan.Steps {
					_, _ = fmt.Fprintf(
						w,
						"       %d. %s\n",
						stepIndex+1,
						strings.Join(append([]string{step.Command.Path}, step.Command.Args...), " "),
					)
				}
			}
		}
		_, _ = fmt.Fprintf(w, "     Outcome: %s\n", describePerIPEntryOutcome(mode, entry))
		_, _ = fmt.Fprintf(w, "     Work summary: %s\n", describePerIPEntryWork(mode, entry))
		if entry.ExecutionNote != "" {
			_, _ = fmt.Fprintf(w, "     Status note: %s\n", entry.ExecutionNote)
		}
	}
}

func describePerIPPlannedAction(entry limitPerIPEntryReport) string {
	if entry.Plan == nil {
		return ""
	}

	action := describePlanAction(*entry.Plan)
	if entry.Decision != nil &&
		entry.Decision.Kind == limiter.DecisionApply &&
		entry.Observation != nil &&
		entry.Observation.Matched &&
		entry.Observation.AttachmentMatched != nil &&
		!*entry.Observation.AttachmentMatched {
		return action + " (reapply)"
	}

	return action
}

func describeAppliedState(applied limiter.AppliedState) string {
	description := fmt.Sprintf("%s via %s", applied.Mode, strings.TrimSpace(applied.Driver))
	if applied.Mode == limiter.DesiredModeLimit {
		description += fmt.Sprintf(" (%s)", describeLimitPolicy(applied.Limits))
	}
	if reference := strings.TrimSpace(applied.Reference); reference != "" {
		description += fmt.Sprintf(" [reference=%s]", reference)
	}

	return description
}

func reconcileOwnerKey(input tc.PeriodicReconcileInput) string {
	if ownerKey := strings.TrimSpace(input.Desired.OwnerKey); ownerKey != "" {
		return ownerKey
	}

	return strings.TrimSpace(input.Observed.OwnerKey)
}

func describeDirectAttachmentRule(rule tc.DirectAttachmentRule) string {
	base := fmt.Sprintf("%s pref %d (%s)", rule.Classifier, rule.Preference, rule.Readiness)
	switch rule.Classifier {
	case tc.DirectAttachmentClassifierMatchAll:
		return fmt.Sprintf("%s all client IPs -> %s", base, rule.ClassID)
	case tc.DirectAttachmentClassifierU32:
		protocol, prefixLength := describeClientIPIdentity(rule.Identity.Value)
		if rule.Disposition == tc.DirectAttachmentDispositionPass {
			return fmt.Sprintf("%s %s %s/%d match %s -> pass", base, rule.Identity.Kind, rule.Identity.Value, prefixLength, rule.MatchField)
		}
		return fmt.Sprintf("%s %s %s/%d -> %s protocol %s match %s", base, rule.Identity.Kind, rule.Identity.Value, prefixLength, rule.ClassID, protocol, rule.MatchField)
	default:
		return base
	}
}

func describeClientIPIdentity(value string) (string, int) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", 0
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return "ip", 32
	}
	if addr.Is6() {
		return "ipv6", 128
	}

	return "", 0
}

func writePlanSteps(w io.Writer, steps []tc.Step) {
	for index, step := range steps {
		_, _ = fmt.Fprintf(w, "  %d. %s\n", index+1, strings.Join(append([]string{step.Command.Path}, step.Command.Args...), " "))
	}
}

func writeRequestedLimitText(w io.Writer, operation limitOperation, scope tc.Scope, rateBytes int64, unlimited bool) {
	if operation == limitOperationRemove {
		_, _ = fmt.Fprintf(w, "Requested removal: explicit %s rule set on %s\n", scope.Direction, scope.Device)
		return
	}
	if unlimited {
		_, _ = fmt.Fprintf(w, "Requested state: %s unlimited exception on %s\n", scope.Direction, scope.Device)
		return
	}

	_, _ = fmt.Fprintf(w, "Requested limit: %s %d bytes/s on %s\n", scope.Direction, rateBytes, scope.Device)
}

func writeObservationText(w io.Writer, observation limitObservationReport, matchedLabel string) {
	_, _ = fmt.Fprintf(w, "Observed tc state: %s\n", observation.stateLabel())
	if observation.Available {
		_, _ = fmt.Fprintf(w, "%s: %s\n", matchedLabel, yesNo(observation.Matched))
		if observation.AttachmentMatched != nil {
			_, _ = fmt.Fprintf(w, "Matching attachment rules: %s\n", yesNo(*observation.AttachmentMatched))
		}
	}
	if observation.ExpectedClassID != "" {
		_, _ = fmt.Fprintf(w, "Expected class ID: %s\n", observation.ExpectedClassID)
	}
	if observation.ObservedClassID != "" {
		_, _ = fmt.Fprintf(w, "Observed class ID: %s\n", observation.ObservedClassID)
	}
	if observation.ObservedRateBytes > 0 {
		_, _ = fmt.Fprintf(w, "Observed rate: %d bytes/s\n", observation.ObservedRateBytes)
	}
	if observation.Error != "" {
		_, _ = fmt.Fprintf(w, "Observation note: %s\n", observation.Error)
	}
}

func writeDecisionText(w io.Writer, decision limitDecisionReport) {
	_, _ = fmt.Fprintf(w, "Reconcile decision: %s\n", decision.Kind)
	_, _ = fmt.Fprintf(w, "Decision reason: %s\n", decision.Reason)
}

func writePlanText(w io.Writer, action string, operation limitOperation, cleanupRootQDisc bool, classID string, showClassID bool, steps []tc.Step) {
	_, _ = fmt.Fprintf(w, "Planned action: %s\n", action)
	if operation == limitOperationRemove {
		_, _ = fmt.Fprintf(w, "Cleanup scope: %s\n", cleanupScopeLabel(cleanupRootQDisc, steps))
	}
	if showClassID && classID != "" {
		_, _ = fmt.Fprintf(w, "Class ID: %s\n", classID)
	}
	if len(steps) != 0 {
		_, _ = io.WriteString(w, "Planned commands:\n")
		writePlanSteps(w, steps)
	}
}

func describePlanAction(plan tc.Plan) string {
	switch plan.Action.Kind {
	case limiter.ActionReconcile:
		return "replace"
	default:
		return string(plan.Action.Kind)
	}
}

func writeExecutionResultsSection(w io.Writer, results []tc.Result) {
	if len(results) == 0 {
		return
	}

	_, _ = io.WriteString(w, "Execution results:\n")
	writeExecutionResults(w, results)
}

func writeExecutionResults(w io.Writer, results []tc.Result) {
	for index, result := range results {
		_, _ = fmt.Fprintf(w, "  %d. %s: %s\n", index+1, result.Step, executionResultStatus(result))
		if detail := strings.TrimSpace(result.Error); detail != "" {
			_, _ = fmt.Fprintf(w, "     error: %s\n", detail)
			continue
		}
		if detail := strings.TrimSpace(result.Stderr); detail != "" {
			_, _ = fmt.Fprintf(w, "     stderr: %s\n", detail)
		}
	}
}

func executionResultStatus(result tc.Result) string {
	if result.Error != "" {
		return "failed"
	}
	if result.Skipped {
		return "skipped"
	}
	return "ok"
}

func cleanupScopeLabel(cleanupRootQDisc bool, steps []tc.Step) string {
	if removePlanDeletesClass(steps) {
		if cleanupRootQDisc {
			return "class plus root qdisc"
		}
		return "class only"
	}
	if cleanupRootQDisc {
		return "attachment rules plus root qdisc"
	}
	return "attachment rules only"
}

func removePlanDeletesClass(steps []tc.Step) bool {
	for _, step := range steps {
		name := strings.TrimSpace(step.Name)
		if name == "delete-class" || strings.HasSuffix(name, "-class") {
			return true
		}
	}

	return false
}

func shouldShowPlanClassID(plan tc.Plan) bool {
	if plan.Action.Desired != nil {
		return plan.Action.Desired.Mode == limiter.DesiredModeLimit
	}

	return removePlanDeletesClass(plan.Steps)
}

func writeOutcomeSummary(w io.Writer, mode string, blocked bool, hasPlan bool, noOp bool, results []tc.Result) {
	_, _ = fmt.Fprintf(w, "Outcome: %s\n", outcomeLabel(mode, blocked, hasPlan, noOp, results))

	if blocked {
		if mode == "dry-run" {
			_, _ = io.WriteString(w, "No system changes were made.\n")
		} else {
			_, _ = io.WriteString(w, "No commands were executed.\n")
		}
		return
	}

	if resultsHaveFailures(results) {
		_, _ = fmt.Fprintf(w, "Execution stopped after %d command(s).\n", len(results))
		return
	}

	if !hasPlan {
		_, _ = io.WriteString(w, "No tc changes are required.\n")
		if mode == "dry-run" {
			_, _ = io.WriteString(w, "No system changes were made.\n")
		} else {
			_, _ = io.WriteString(w, "No commands were executed.\n")
		}
		return
	}

	if mode == "dry-run" {
		_, _ = io.WriteString(w, "No system changes were made.\n")
		return
	}

	if noOp {
		_, _ = io.WriteString(w, "Local tc state already matches the requested state.\n")
		_, _ = io.WriteString(w, "No commands were executed.\n")
		return
	}

	if len(results) == 0 {
		_, _ = io.WriteString(w, "No commands were executed.\n")
		return
	}

	_, _ = fmt.Fprintf(w, "Executed %d command(s).\n", len(results))
}

func outcomeLabel(mode string, blocked bool, hasPlan bool, noOp bool, results []tc.Result) string {
	switch {
	case blocked:
		return "blocked"
	case resultsHaveFailures(results):
		return "failed"
	case !hasPlan:
		return "no changes"
	case mode == "dry-run":
		return "plan ready"
	case noOp:
		return "no changes"
	case len(results) == 0:
		return "no changes"
	default:
		return "executed"
	}
}

func writeTextSectionHeading(w io.Writer, title string) {
	_, _ = fmt.Fprintf(w, "\n%s:\n", title)
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func describeLimitPolicy(limits policy.LimitPolicy) string {
	parts := make([]string, 0, 2)
	if limits.Upload != nil {
		parts = append(parts, fmt.Sprintf("upload=%d bytes/s", limits.Upload.BytesPerSecond))
	}
	if limits.Download != nil {
		parts = append(parts, fmt.Sprintf("download=%d bytes/s", limits.Download.BytesPerSecond))
	}
	if len(parts) == 0 {
		return "none"
	}

	return strings.Join(parts, ", ")
}

func describePolicyMatch(match policy.Match) string {
	name := strings.TrimSpace(match.Policy.Name)
	if name == "" {
		name = fmt.Sprintf("policy-%d", match.Index+1)
	}

	return fmt.Sprintf(
		"%s [%s %s, effect=%s, precedence=%d]",
		name,
		match.Policy.Target.Kind,
		describePolicyTargetValue(match.Policy.Target),
		describePolicyEffect(match.Policy.Effect),
		match.Precedence,
	)
}

func describePolicyTargetValue(target policy.Target) string {
	if target.Kind == policy.TargetKindIP && target.All {
		return "all"
	}

	return strings.TrimSpace(target.Value)
}

func describeLimitTarget(target limitTargetReport) string {
	value := target.displayValue()
	if value == "" {
		return string(target.Kind)
	}

	return fmt.Sprintf("%s %s", target.Kind, value)
}

func describePolicyEffect(effect policy.Effect) string {
	if effect == "" {
		return string(policy.EffectLimit)
	}

	return string(effect)
}

func describeLimitRuntime(target discovery.RuntimeTarget) string {
	switch target.Source {
	case discovery.DiscoverySourceHostProcess:
		if target.HostProcess != nil && target.HostProcess.PID != 0 {
			return fmt.Sprintf("host process %d", target.HostProcess.PID)
		}
	case discovery.DiscoverySourceDockerContainer:
		if target.DockerContainer != nil {
			if target.DockerContainer.Name != "" {
				return fmt.Sprintf("docker container %s", target.DockerContainer.Name)
			}
			if target.DockerContainer.ID != "" {
				return fmt.Sprintf("docker container %s", target.DockerContainer.ID)
			}
		}
	}

	if target.Identity.Name != "" {
		return target.Identity.Name
	}

	return string(target.Source)
}

func writeLimitHelp(w io.Writer, cmd command) {
	_, _ = fmt.Fprintf(w, "Usage:\n  %s\n\n", cmd.usage)
	_, _ = fmt.Fprintf(w, "%s\n\n", cmd.description)
	_, _ = io.WriteString(w, "Plan first by default. Add --execute only when the selected limiter path is concrete and the local environment can apply tc state safely.\n\n")
	_, _ = io.WriteString(w, "Target selection:\n")
	_, _ = io.WriteString(w, "  --ip <ip|all>                     Specific client IP or all client IPs within the selected runtime\n")
	_, _ = io.WriteString(w, "  --ip-aggregation shared|per_ip    Aggregation mode for --ip all (default: shared)\n")
	_, _ = io.WriteString(w, "  --inbound <tag>                   Inbound-scoped target (concrete for one readable concrete TCP listener)\n")
	_, _ = io.WriteString(w, "  --outbound <tag>                  Outbound-scoped target (concrete when readable Xray config proves one unique non-zero socket mark without proxy or dialer-proxy indirection)\n")
	_, _ = io.WriteString(w, "\nPlanning and execution:\n")
	_, _ = io.WriteString(w, "  --device <device>                 Linux network device to plan against\n")
	_, _ = io.WriteString(w, "  --direction upload|download       Limit direction\n")
	_, _ = io.WriteString(w, "  --rate <bytes-per-second>         Rate in bytes per second (required unless --remove or --unlimited)\n")
	_, _ = io.WriteString(w, "  --unlimited                       Specific IP unlimited exception that bypasses any matching shared --ip all baseline\n")
	_, _ = io.WriteString(w, "  --remove                          Remove the selected limiter state instead of planning a new one\n")
	_, _ = io.WriteString(w, "  --execute                         Perform real local tc execution\n")
	_, _ = io.WriteString(w, "  --allow-missing-tc-state          Allow real execution when tc state cannot be observed first\n")
	_, _ = io.WriteString(w, "  --format text|json                Render as text or machine-readable JSON (default: text)\n")
	_, _ = io.WriteString(w, "\nRuntime selection:\n")
	_, _ = io.WriteString(w, "  --source host_process|docker_container\n")
	_, _ = io.WriteString(w, "                                   Restrict runtime selection to one discovery source\n")
	_, _ = io.WriteString(w, "  --name <name>                     Select a runtime by discovered name\n")
	_, _ = io.WriteString(w, "  --pid <pid>                       Select a host runtime by process ID\n")
	_, _ = io.WriteString(w, "  --container <id-or-name>          Select a Docker runtime by container name or ID prefix\n")
	_, _ = io.WriteString(w, "\nExamples:\n")
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip all --device eth0 --direction upload --rate 1048576\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip all --ip-aggregation per_ip --device eth0 --direction upload --rate 1048576\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip all --ip-aggregation per_ip --device eth0 --direction upload --remove\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip 203.0.113.4 --device eth0 --direction upload --rate 1048576\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip 2001:db8::10 --device eth0 --direction download --rate 524288\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip 203.0.113.4 --device eth0 --direction upload --unlimited\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --inbound api-in --device eth0 --direction upload --rate 1048576\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --container raylimit-xray-test --outbound proxy --device eth0 --direction upload --rate 262144 --execute\n", buildinfo.BinaryName)
	_, _ = fmt.Fprintf(w, "  %s limit --pid 4242 --ip 203.0.113.4 --device eth0 --direction upload --remove\n", buildinfo.BinaryName)
	_, _ = io.WriteString(w, "\nRule precedence:\n")
	_, _ = io.WriteString(w, "  When multiple rule kinds match the same live session, RayLimit keeps the highest-precedence kind only: ip > inbound > outbound. Within IP, a specific IP target overrides a shared --ip all baseline. At one specificity, exclude rules suppress limit rules and multiple winning limit rules merge by taking the tightest upload/download value per direction.\n")
	_, _ = io.WriteString(w, "\nCurrent execution paths:\n")
	_, _ = io.WriteString(w, "  --ip all currently installs a runtime-local shared baseline through a direct matchall attachment. Specific --ip rules install direct client IP classify or pass rules that override or bypass that shared baseline. IPv4, IPv4-mapped IPv6, and native IPv6 stay supported within the current u32 assumption of no IPv6 extension headers for specific IP matching.\n")
	_, _ = io.WriteString(w, "  --ip all --ip-aggregation per_ip expands the current live client IP set through Xray-backed session evidence and reuses the specific IP direct attachment path for apply and remove. Shared root-qdisc cleanup stays conservative and only runs when the current visible client IP set proves that cleanup is safe. When live evidence is unavailable or insufficient, planning is blocked and execution is refused.\n")
	_, _ = io.WriteString(w, "  --inbound adds concrete nftables mark plus tc fw attachment when readable Xray config proves one concrete TCP listener for the selected inbound tag. Wildcard, missing, unreadable, ambiguous, or non-TCP inbound config stays conservative and blocks apply execution.\n")
	_, _ = io.WriteString(w, "  --outbound adds concrete nftables output matching plus tc fw attachment when readable Xray config proves one unique non-zero outbound socket mark without proxy or dialer-proxy indirection. Unreadable config, zero or shared marks, and outbound chaining stay conservative and block concrete execution.\n")
}
