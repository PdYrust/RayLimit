package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const xrayOnlineIPSessionIDPrefix = "xray-online-ip:"

// xrayOnlineIPSessionIDSeparator delimits the user and client-IP components
// inside a synthesized online-IP session id. It is deliberately a character
// that never appears in an IPv4 or IPv6 literal so the id can be split back
// into its parts unambiguously even for IPv6 addresses (whose own ":"
// separators would otherwise be impossible to disambiguate).
const xrayOnlineIPSessionIDSeparator = "|"

// defaultXrayAPITimeout is the per-call timeout applied to xray API invocations
// when the provider does not override it. It is intentionally generous because
// statsonlineiplist can be slow on busy servers with many online users.
const defaultXrayAPITimeout = 15 * time.Second

// xrayAPITimeoutGrace is added to the xray --timeout value when deriving the
// hard process-execution deadline, leaving the runtime room to honor its own
// timeout and return a structured error before the process is force-killed.
const xrayAPITimeoutGrace = 5 * time.Second

// xrayExecCommandContext constructs the exec command for xray API invocations.
// It is a package variable so tests can substitute a fake process.
var xrayExecCommandContext = exec.CommandContext

// xrayLookPath resolves an executable for the API runners and guards against a
// missing binary. It is a package variable so tests can substitute resolution
// without touching the real filesystem.
var xrayLookPath = exec.LookPath

type xrayAPICommandRunner func(ctx context.Context, binary string, server string, timeout time.Duration, command string, args ...string) ([]byte, error)
type xrayContainerAPICommandRunner func(ctx context.Context, containerID string, binary string, server string, timeout time.Duration, command string, args ...string) ([]byte, error)

type xrayGetAllOnlineUsersResponse struct {
	Users []string `json:"users"`
}

type xrayGetStatsOnlineIPListResponse struct {
	// Name carries the ">>>"-delimited identity record (for example
	// "user>>>alice>>>online") that newer Xray/fork builds attach to the JSON
	// form of statsonlineiplist. It is captured so the email it encodes can be
	// validated against the requested user before the reported IPs are trusted.
	Name string           `json:"name"`
	IPs  map[string]int64 `json:"ips"`
}

type xraySessionQueryError struct {
	Code    SessionEvidenceIssueCode
	Message string
	// Cause, when non-nil, is the underlying error that produced this query
	// failure. It is exposed via Unwrap so callers can match sentinel errors
	// (for example errors.Is(err, exec.ErrNotFound) for a missing binary) while
	// Code remains the primary classification surface. It is optional: most
	// query errors are synthesized without an underlying cause and leave it nil.
	Cause error
}

func (e xraySessionQueryError) Error() string {
	return strings.TrimSpace(e.Message)
}

// Unwrap returns the underlying cause, or nil when none was recorded, so
// errors.Is / errors.As can traverse to a wrapped sentinel without disturbing
// the Code-based classification (errors.As on xraySessionQueryError still
// matches this error itself first).
func (e xraySessionQueryError) Unwrap() error {
	return e.Cause
}

func newXraySessionQueryError(code SessionEvidenceIssueCode, format string, args ...any) error {
	return xraySessionQueryError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// newXraySessionQueryErrorWithCause is newXraySessionQueryError plus an
// underlying cause exposed through Unwrap, for guards that must stay matchable
// with errors.Is (for example the LookPath not-found guard, which must remain
// distinguishable as exec.ErrNotFound while still carrying the Unavailable
// code).
func newXraySessionQueryErrorWithCause(code SessionEvidenceIssueCode, cause error, format string, args ...any) error {
	return xraySessionQueryError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// IsXrayOnlineIPSessionID reports whether a session id was synthesized from
// Xray's live online-IP evidence rather than discovered as a concrete
// connection identity.
func IsXrayOnlineIPSessionID(sessionID string) bool {
	return strings.HasPrefix(strings.TrimSpace(sessionID), xrayOnlineIPSessionIDPrefix)
}

func defaultXraySessionQuery(runner xrayAPICommandRunner, containerRunner xrayContainerAPICommandRunner, timeout time.Duration, binaryOverride string) xraySessionQuery {
	return func(ctx context.Context, target RuntimeTarget, endpoint APIEndpoint) ([]SessionEvidence, error) {
		runtime, err := SessionRuntimeFromTarget(target)
		if err != nil {
			return nil, fmt.Errorf("failed to derive runtime association for Xray session querying: %w", err)
		}

		server, queryRunner, err := xrayQueryTransport(target, endpoint, runner, containerRunner, timeout, binaryOverride)
		if err != nil {
			return nil, fmt.Errorf("xray api transport setup for %s failed: %w", describeAPIEndpoint(endpoint), err)
		}

		return queryXraySessions(ctx, runtime, endpoint, server, queryRunner, resolveStatsUserOnlineGate(target))
	}
}

// resolveStatsUserOnlineGate returns the StatsUserOnline enablement state that
// should gate empty online-user results, or nil when the gate must not apply.
//
// The StatsUserOnline service-presence requirement is specific to the Sanaei
// Xray fork; vanilla xray-core does not need it for its StatsService query
// path. Applying the gate to a vanilla runtime would misreport a genuine
// no-sessions result as a configuration error, so the gate is only consulted
// for runtimes detected as the fork via runtimeIsSanaeiFork.
func resolveStatsUserOnlineGate(target RuntimeTarget) *bool {
	if !runtimeIsSanaeiFork(target) {
		return nil
	}
	if target.APICapability == nil {
		return nil
	}

	return target.APICapability.StatsUserOnline
}

// runtimeIsSanaeiFork reports whether the runtime is the Sanaei Xray fork, based
// on the prefix-matched binary identity from runtime detection. It covers both
// host runtimes (Identity.Binary, which is the executable basename, with the
// discovered executable path as a defensive fallback) and container runtimes
// (Identity.Binary set to the in-container fork binary).
//
// Vanilla xray/xray-core binaries do not match, and an unknown (empty) binary
// returns false so the fork-specific StatsUserOnline gate never applies to a
// runtime we could not positively identify as the fork.
func runtimeIsSanaeiFork(target RuntimeTarget) bool {
	if matchesSanaeiForkBinary(target.Identity.Binary) {
		return true
	}
	if target.HostProcess != nil && matchesSanaeiForkBinary(target.HostProcess.ExecutablePath) {
		return true
	}

	return false
}

func xrayQueryTransport(
	target RuntimeTarget,
	endpoint APIEndpoint,
	runner xrayAPICommandRunner,
	containerRunner xrayContainerAPICommandRunner,
	timeout time.Duration,
	binaryOverride string,
) (string, func(context.Context, string, ...string) ([]byte, error), error) {
	if containerID := strings.TrimSpace(targetContainerID(target)); containerID != "" {
		binary := resolveContainerXrayBinary(target, binaryOverride)
		internalEndpoints := orderedAPIEndpoints(target.APIEndpoints)
		for _, internalEndpoint := range internalEndpoints {
			server, err := xrayAPIServerAddress(internalEndpoint)
			if err != nil {
				continue
			}
			return server, func(ctx context.Context, command string, args ...string) ([]byte, error) {
				return containerRunner(ctx, containerID, binary, server, timeout, command, args...)
			}, nil
		}
	}

	server, err := xrayAPIServerAddress(endpoint)
	if err != nil {
		return "", nil, err
	}

	binary := resolveHostXrayBinary(target, binaryOverride)

	return server, func(ctx context.Context, command string, args ...string) ([]byte, error) {
		return runner(ctx, binary, server, timeout, command, args...)
	}, nil
}

// resolveHostXrayBinary selects the executable used to query a host runtime's
// Xray API. An explicit override wins; otherwise it prefers the detected
// absolute executable path (no PATH lookup required), then the detected binary
// basename, and finally the literal "xray" for backwards compatibility.
func resolveHostXrayBinary(target RuntimeTarget, override string) string {
	if override = strings.TrimSpace(override); override != "" {
		return override
	}
	if target.HostProcess != nil {
		if path := strings.TrimSpace(target.HostProcess.ExecutablePath); path != "" {
			return path
		}
	}
	if binary := strings.TrimSpace(target.Identity.Binary); binary != "" {
		return binary
	}

	return "xray"
}

// resolveContainerXrayBinary selects the in-container executable used to query a
// containerized runtime's Xray API. An explicit override wins; otherwise it
// uses the detected in-container binary basename and falls back to the literal
// "xray".
func resolveContainerXrayBinary(target RuntimeTarget, override string) string {
	if override = strings.TrimSpace(override); override != "" {
		return override
	}
	if binary := strings.TrimSpace(target.Identity.Binary); binary != "" {
		return binary
	}

	return "xray"
}

func queryXraySessions(
	ctx context.Context,
	runtime SessionRuntime,
	endpoint APIEndpoint,
	server string,
	runner func(ctx context.Context, command string, args ...string) ([]byte, error),
	statsUserOnline *bool,
) ([]SessionEvidence, error) {
	users, err := queryXrayOnlineUsers(ctx, runner, server)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		if statsUserOnline != nil && !*statsUserOnline {
			return nil, newXraySessionQueryError(
				SessionEvidenceIssueStatsUserOnlineNotEnabled,
				"Xray API endpoint %s returned no online users because the %q service is not enabled; add %q to the Xray config \"api.services\" array and restart Xray to enable live online-user evidence",
				server,
				statsUserOnlineServiceName,
				statsUserOnlineServiceName,
			)
		}
		return nil, nil
	}

	evidence := make([]SessionEvidence, 0, len(users))
	for _, user := range users {
		ips, err := queryXrayOnlineIPs(ctx, runner, server, user)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, newXraySessionQueryError(
				SessionEvidenceIssueInsufficient,
				"Xray StatsService reported online user %q at %s, but no live client IP evidence was returned",
				user,
				server,
			)
		}

		for _, ip := range ips {
			evidence = append(evidence, SessionEvidence{
				Runtime: runtime,
				Session: Session{
					ID:      xrayOnlineIPSessionID(user, ip),
					Runtime: runtime,
					Client: SessionClient{
						IP: ip,
					},
				},
				Confidence: SessionEvidenceConfidenceHigh,
				Note:       fmt.Sprintf("observed via Xray StatsService online IP query through API endpoint %s", describeAPIEndpoint(endpoint)),
			})
		}
	}

	sort.SliceStable(evidence, func(i, j int) bool {
		left := evidence[i]
		right := evidence[j]
		leftKey := strings.Join([]string{
			strings.TrimSpace(left.Session.ID),
			strings.TrimSpace(left.Session.Client.IP),
		}, "|")
		rightKey := strings.Join([]string{
			strings.TrimSpace(right.Session.ID),
			strings.TrimSpace(right.Session.Client.IP),
		}, "|")
		return leftKey < rightKey
	})

	return evidence, nil
}

func defaultXrayAPICommandRunner(ctx context.Context, binary string, server string, timeout time.Duration, command string, args ...string) ([]byte, error) {
	timeout = normalizeXrayAPITimeout(timeout)

	resolved, err := xrayLookPath(binary)
	if err != nil {
		return nil, xrayNotInstalledIssue(binary, err)
	}

	stdout, stderr, runErr := runXrayProcess(ctx, timeout, resolved, xrayAPIArgv(server, timeout, true, command, args))
	if runErr == nil {
		return stdout, nil
	}

	// Some Xray/fork builds reject the -json flag with a non-zero exit. Retry
	// once in plain-text mode so the wire-format parser can still extract
	// evidence from the runtime.
	if xrayRejectedJSONFlag(stderr) {
		plainStdout, plainStderr, plainErr := runXrayProcess(ctx, timeout, resolved, xrayAPIArgv(server, timeout, false, command, args))
		if plainErr == nil {
			return plainStdout, nil
		}
		return nil, xrayAPICommandError(command, server, "", firstNonEmpty(plainStderr, stderr), plainErr)
	}

	return nil, xrayAPICommandError(command, server, "", stderr, runErr)
}

func runXrayContainerAPICommand(ctx context.Context, cli string, containerID string, binary string, server string, timeout time.Duration, command string, args ...string) ([]byte, error) {
	cli = normalizeContainerCLI(cli)
	timeout = normalizeXrayAPITimeout(timeout)

	if _, err := xrayLookPath(cli); err != nil {
		return nil, containerCLINotInstalledIssue(cli, err)
	}

	stdout, stderr, runErr := runXrayProcess(ctx, timeout, cli, xrayContainerAPIArgv(containerID, binary, server, timeout, true, command, args))
	if runErr == nil {
		return stdout, nil
	}

	if xrayRejectedJSONFlag(stderr) {
		plainStdout, plainStderr, plainErr := runXrayProcess(ctx, timeout, cli, xrayContainerAPIArgv(containerID, binary, server, timeout, false, command, args))
		if plainErr == nil {
			return plainStdout, nil
		}
		return nil, xrayAPICommandError(command, server, containerID, firstNonEmpty(plainStderr, stderr), plainErr)
	}

	return nil, xrayAPICommandError(command, server, containerID, stderr, runErr)
}

// xrayNotInstalledIssue reports that the resolved Xray binary could not be
// found or executed. It returns a typed xraySessionQueryError so the
// session-evidence layer surfaces it with a stable issue code instead of a
// confusing downstream "not found".
func xrayNotInstalledIssue(binary string, err error) error {
	return newXraySessionQueryErrorWithCause(
		SessionEvidenceIssueUnavailable,
		err,
		"Xray binary %q was not found for API querying: %v; install Xray or ensure the detected binary is accessible",
		strings.TrimSpace(binary),
		err,
	)
}

// runXrayProcess executes one prepared xray/docker invocation with separated
// stdout and stderr buffers. Only stdout is returned to the caller for parsing;
// the trimmed stderr is returned separately so it can be surfaced in error
// messages without ever corrupting the parsed payload.
func runXrayProcess(ctx context.Context, timeout time.Duration, name string, argv []string) (stdout []byte, stderr string, err error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout+xrayAPITimeoutGrace)
	defer cancel()

	cmd := xrayExecCommandContext(runCtx, name, argv...)
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	return outBuf.Bytes(), strings.TrimSpace(errBuf.String()), runErr
}

// xrayAPIArgv builds the argv for a direct `xray api` invocation. When
// jsonOutput is set the -json flag is included so structured output is emitted
// by runtimes that support it.
func xrayAPIArgv(server string, timeout time.Duration, jsonOutput bool, command string, args []string) []string {
	argv := []string{"api", command}
	if jsonOutput {
		argv = append(argv, "-json")
	}
	argv = append(argv, "--server="+server, xrayTimeoutFlag(timeout))
	return append(argv, args...)
}

// xrayContainerAPIArgv builds the argv for a `docker exec <id> <binary> api`
// invocation, mirroring xrayAPIArgv inside the container. The binary is the
// detected in-container Xray executable name.
func xrayContainerAPIArgv(containerID string, binary string, server string, timeout time.Duration, jsonOutput bool, command string, args []string) []string {
	argv := []string{"exec", containerID, binary, "api", command}
	if jsonOutput {
		argv = append(argv, "-json")
	}
	argv = append(argv, "--server="+server, xrayTimeoutFlag(timeout))
	return append(argv, args...)
}

func xrayTimeoutFlag(timeout time.Duration) string {
	seconds := int(normalizeXrayAPITimeout(timeout).Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("--timeout=%d", seconds)
}

func normalizeXrayAPITimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultXrayAPITimeout
	}
	return timeout
}

// xrayRejectedJSONFlag reports whether a runtime's stderr indicates that the
// -json flag was not recognized, in which case a plain-text retry is warranted.
func xrayRejectedJSONFlag(stderr string) bool {
	lower := strings.ToLower(stderr)
	if !strings.Contains(lower, "json") {
		return false
	}
	return strings.Contains(lower, "flag provided but not defined") ||
		strings.Contains(lower, "unknown flag") ||
		strings.Contains(lower, "unknown shorthand") ||
		strings.Contains(lower, "not defined") ||
		strings.Contains(lower, "invalid") ||
		strings.Contains(lower, "unexpected")
}

func xrayAPICommandError(command string, server string, containerID string, stderr string, err error) error {
	message := strings.TrimSpace(stderr)
	if message == "" && err != nil {
		message = err.Error()
	}

	code := SessionEvidenceIssueUnavailable
	if strings.Contains(strings.ToLower(message), "permission denied") {
		code = SessionEvidenceIssuePermissionDenied
	}

	if strings.TrimSpace(containerID) != "" {
		return newXraySessionQueryError(
			code,
			"Xray API command %q failed inside container %s against %s: %s",
			command,
			containerID,
			server,
			message,
		)
	}

	return newXraySessionQueryError(
		code,
		"Xray API command %q failed against %s: %s",
		command,
		server,
		message,
	)
}

func xrayAPIServerAddress(endpoint APIEndpoint) (string, error) {
	if endpoint.Network != EndpointNetworkTCP {
		return "", newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray live session querying currently supports only TCP API endpoints; %s is not queryable",
			describeAPIEndpoint(endpoint),
		)
	}
	if endpoint.Port <= 0 {
		return "", newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray live session querying requires a concrete TCP port; %s is incomplete",
			describeAPIEndpoint(endpoint),
		)
	}

	host := normalizeWildcardListenHost(endpoint.Address)

	return net.JoinHostPort(host, strconv.Itoa(endpoint.Port)), nil
}

func queryXrayOnlineUsers(ctx context.Context, runner func(context.Context, string, ...string) ([]byte, error), server string) ([]string, error) {
	output, err := runner(ctx, "statsgetallonlineusers")
	if err != nil {
		return nil, err
	}

	var rawUsers []string
	if xrayResponseIsJSON(output) {
		var response xrayGetAllOnlineUsersResponse
		if err := json.Unmarshal(output, &response); err != nil {
			return nil, newXraySessionQueryError(
				SessionEvidenceIssueInsufficient,
				"Xray API endpoint %s returned an invalid online-users response: %v",
				server,
				err,
			)
		}
		rawUsers = response.Users
	} else {
		rawUsers = parseXrayOnlineUsersText(output)
	}

	users := make([]string, 0, len(rawUsers))
	seen := make(map[string]struct{}, len(rawUsers))
	for _, user := range rawUsers {
		user = strings.TrimSpace(user)
		if user == "" {
			continue
		}
		if _, ok := seen[user]; ok {
			continue
		}
		seen[user] = struct{}{}
		users = append(users, user)
	}
	sort.Strings(users)

	return users, nil
}

func queryXrayOnlineIPs(ctx context.Context, runner func(context.Context, string, ...string) ([]byte, error), server string, user string) ([]string, error) {
	output, err := runner(ctx, "statsonlineiplist", "-email", user)
	if err != nil {
		return nil, err
	}

	var rawIPs []string
	if xrayResponseIsJSON(output) {
		var response xrayGetStatsOnlineIPListResponse
		if err := json.Unmarshal(output, &response); err != nil {
			return nil, newXraySessionQueryError(
				SessionEvidenceIssueInsufficient,
				"Xray API endpoint %s returned an invalid online-ip response for user %q: %v",
				server,
				user,
				err,
			)
		}
		if err := verifyXrayOnlineIPAttribution(response.Name, user, server); err != nil {
			return nil, err
		}
		if len(response.IPs) == 0 {
			return nil, nil
		}
		rawIPs = make([]string, 0, len(response.IPs))
		for ip := range response.IPs {
			rawIPs = append(rawIPs, ip)
		}
	} else {
		rawIPs, err = parseXrayOnlineIPsText(output, user, server)
		if err != nil {
			return nil, err
		}
	}

	ips := make([]string, 0, len(rawIPs))
	seen := make(map[string]struct{}, len(rawIPs))
	for _, ip := range rawIPs {
		normalized := normalizeXrayClientIP(ip)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		ips = append(ips, normalized)
	}
	sort.Strings(ips)

	return ips, nil
}

// xrayResponseIsJSON reports whether an Xray API CLI response should be decoded
// as JSON. Detection peeks at the first non-whitespace byte: '{' or '[' selects
// JSON, while any other leading byte selects the fork's plain-text wire format.
// Empty or whitespace-only output is treated as plain text, which the line
// parsers reduce to an empty record set.
func xrayResponseIsJSON(output []byte) bool {
	for _, b := range output {
		switch b {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			continue
		}
		return b == '{' || b == '['
	}

	return false
}

// xrayWireRecordEmail extracts the email segment from one ">>>"-delimited Xray
// fork record such as "user>>>alice>>>online". The email is the segment at
// index 1. A record without the delimiter is treated as a bare email value so
// vanilla plain-text output is also tolerated. The boolean reports whether the
// record was structurally parsable; the email may still be empty for a
// malformed record such as "user>>>>>>online".
func xrayWireRecordEmail(record string) (string, bool) {
	record = strings.TrimSpace(record)
	if record == "" {
		return "", false
	}
	if !strings.Contains(record, ">>>") {
		return record, true
	}

	segments := strings.Split(record, ">>>")
	if len(segments) < 2 {
		return "", true
	}

	return strings.TrimSpace(segments[1]), true
}

// parseXrayOnlineUsersText parses the fork's plain-text statsgetallonlineusers
// output, one record per line, extracting the email segment from each line.
// Records with an empty or unparsable email segment (such as
// "user>>>>>>online") are skipped rather than propagated downstream.
func parseXrayOnlineUsersText(output []byte) []string {
	lines := strings.Split(string(output), "\n")
	emails := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		email, ok := xrayWireRecordEmail(line)
		if !ok || email == "" {
			continue
		}
		emails = append(emails, email)
	}

	return emails
}

// parseXrayOnlineIPsText parses the fork's plain-text statsonlineiplist output,
// one record per line in the form "user>>>email>>>online>>>ip". The IP is read
// from the final segment, and the email segment (index 1) is verified against
// the requested user so mis-attributed evidence is rejected rather than
// trusted. Lines without a trailing IP segment carry no address and are
// skipped, while a single-segment line is accepted as a bare IP for
// compatibility with output that omits the identity prefix.
func parseXrayOnlineIPsText(output []byte, user string, server string) ([]string, error) {
	requested := strings.TrimSpace(user)
	lines := strings.Split(string(output), "\n")
	ips := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		segments := strings.Split(line, ">>>")
		switch {
		case len(segments) >= 4:
			email := strings.TrimSpace(segments[1])
			if email == "" {
				continue
			}
			if email != requested {
				return nil, newXraySessionQueryError(
					SessionEvidenceIssueInsufficient,
					"Xray API endpoint %s mis-attributed online-ip evidence: requested user %q but a response record was scoped to %q",
					server,
					requested,
					email,
				)
			}
			if ip := strings.TrimSpace(segments[len(segments)-1]); ip != "" {
				ips = append(ips, ip)
			}
		case len(segments) == 1:
			if ip := strings.TrimSpace(segments[0]); ip != "" {
				ips = append(ips, ip)
			}
		default:
			// A 2- or 3-segment record carries no trailing IP address; skip it.
		}
	}

	return ips, nil
}

// verifyXrayOnlineIPAttribution confirms that the "name" field returned by the
// JSON form of statsonlineiplist is scoped to the requested user. The field
// carries a ">>>"-delimited record (for example "user>>>alice>>>online"); when
// present, its email segment must match the requested user so mis-attributed
// evidence is rejected. An absent field is tolerated for compatibility with
// responses that omit it.
func verifyXrayOnlineIPAttribution(name string, user string, server string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	requested := strings.TrimSpace(user)
	email, ok := xrayWireRecordEmail(name)
	if !ok || email == "" {
		return newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray API endpoint %s returned an online-ip response for user %q without a parsable email attribution (%q)",
			server,
			requested,
			name,
		)
	}
	if email != requested {
		return newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray API endpoint %s mis-attributed online-ip evidence: requested user %q but the response was scoped to %q",
			server,
			requested,
			email,
		)
	}

	return nil
}

// normalizeXrayClientIP canonicalizes a client IP value reported by the Xray
// API. It accepts a bare address, and also tolerates host:port and
// "[v6]:port" forms by returning only the address component. IPv4-mapped IPv6
// addresses are unmapped to their IPv4 form. Values that match none of these
// shapes are returned verbatim.
func normalizeXrayClientIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap().String()
	}
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return addrPort.Addr().Unmap().String()
	}

	return value
}

func xrayOnlineIPSessionID(user string, ip string) string {
	user = strings.ToLower(strings.TrimSpace(user))
	ip = strings.TrimSpace(ip)
	return xrayOnlineIPSessionIDPrefix + user + xrayOnlineIPSessionIDSeparator + ip
}

func sessionQueryErrorCode(err error) (SessionEvidenceIssueCode, bool) {
	var queryErr xraySessionQueryError
	if errors.As(err, &queryErr) {
		return queryErr.Code, true
	}

	return "", false
}
