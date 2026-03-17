package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

const xrayOnlineIPSessionIDPrefix = "xray-online-ip:"
const xrayOnlineUserSessionIDPrefix = "xray-online-user:"

type xrayAPICommandRunner func(ctx context.Context, server string, command string, args ...string) ([]byte, error)
type xrayContainerAPICommandRunner func(ctx context.Context, containerID string, server string, command string, args ...string) ([]byte, error)

type xrayGetAllOnlineUsersResponse struct {
	Users []string `json:"users"`
}

type xrayGetStatsOnlineIPListResponse struct {
	Name string           `json:"name"`
	IPs  map[string]int64 `json:"ips"`
}

type xraySessionQueryError struct {
	Code    SessionEvidenceIssueCode
	Message string
}

func (e xraySessionQueryError) Error() string {
	return strings.TrimSpace(e.Message)
}

func newXraySessionQueryError(code SessionEvidenceIssueCode, format string, args ...any) error {
	return xraySessionQueryError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// IsXrayOnlineIPSessionID reports whether a session id was synthesized from
// Xray's live online-IP evidence rather than discovered as a concrete
// connection identity.
func IsXrayOnlineIPSessionID(sessionID string) bool {
	return strings.HasPrefix(strings.TrimSpace(sessionID), xrayOnlineIPSessionIDPrefix)
}

func IsXrayOnlineUserSessionID(sessionID string) bool {
	return strings.HasPrefix(strings.TrimSpace(sessionID), xrayOnlineUserSessionIDPrefix)
}

func IsXrayLiveEvidenceSessionID(sessionID string) bool {
	return IsXrayOnlineIPSessionID(sessionID) || IsXrayOnlineUserSessionID(sessionID)
}

func defaultXraySessionQuery(runner xrayAPICommandRunner, containerRunner xrayContainerAPICommandRunner) xraySessionQuery {
	return func(ctx context.Context, target RuntimeTarget, endpoint APIEndpoint) ([]SessionEvidence, error) {
		runtime, err := SessionRuntimeFromTarget(target)
		if err != nil {
			return nil, fmt.Errorf("failed to derive runtime association for Xray session querying: %w", err)
		}

		server, queryRunner, err := xrayQueryTransport(target, endpoint, runner, containerRunner)
		if err != nil {
			return nil, err
		}

		return queryXraySessions(ctx, runtime, endpoint, server, queryRunner)
	}
}

func defaultXrayUUIDSessionQuery(runner xrayAPICommandRunner, containerRunner xrayContainerAPICommandRunner) xrayUUIDSessionQuery {
	return func(ctx context.Context, target RuntimeTarget, endpoint APIEndpoint, uuid string) ([]SessionEvidence, error) {
		runtime, err := SessionRuntimeFromTarget(target)
		if err != nil {
			return nil, fmt.Errorf("failed to derive runtime association for Xray uuid session querying: %w", err)
		}

		server, queryRunner, err := xrayQueryTransport(target, endpoint, runner, containerRunner)
		if err != nil {
			return nil, err
		}

		return queryXraySpecificUser(ctx, runtime, endpoint, server, strings.TrimSpace(uuid), queryRunner)
	}
}

func xrayQueryTransport(
	target RuntimeTarget,
	endpoint APIEndpoint,
	runner xrayAPICommandRunner,
	containerRunner xrayContainerAPICommandRunner,
) (string, func(context.Context, string, ...string) ([]byte, error), error) {
	if containerID := strings.TrimSpace(targetContainerID(target)); containerID != "" {
		internalEndpoints := orderedAPIEndpoints(target.APIEndpoints)
		for _, internalEndpoint := range internalEndpoints {
			server, err := xrayAPIServerAddress(internalEndpoint)
			if err != nil {
				continue
			}
			return server, func(ctx context.Context, command string, args ...string) ([]byte, error) {
				return containerRunner(ctx, containerID, server, command, args...)
			}, nil
		}
	}

	server, err := xrayAPIServerAddress(endpoint)
	if err != nil {
		return "", nil, err
	}

	return server, func(ctx context.Context, command string, args ...string) ([]byte, error) {
		return runner(ctx, server, command, args...)
	}, nil
}

func queryXraySessions(
	ctx context.Context,
	runtime SessionRuntime,
	endpoint APIEndpoint,
	server string,
	runner func(ctx context.Context, command string, args ...string) ([]byte, error),
) ([]SessionEvidence, error) {
	users, err := queryXrayOnlineUsers(ctx, runner, server)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
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
					Policy: SessionPolicyIdentity{
						UUID: user,
					},
					Client: SessionClient{
						IP: ip,
					},
				},
				Confidence: SessionEvidenceConfidenceHigh,
				Note:       fmt.Sprintf("observed via Xray StatsService online IP query through API endpoint %s", describeAPIEndpoint(endpoint)),
			})
		}
	}

	sort.Slice(evidence, func(i, j int) bool {
		left := evidence[i]
		right := evidence[j]
		leftKey := strings.Join([]string{
			left.Session.Policy.Key(),
			strings.TrimSpace(left.Session.Client.IP),
			strings.TrimSpace(left.Session.ID),
		}, "|")
		rightKey := strings.Join([]string{
			right.Session.Policy.Key(),
			strings.TrimSpace(right.Session.Client.IP),
			strings.TrimSpace(right.Session.ID),
		}, "|")
		return leftKey < rightKey
	})

	return evidence, nil
}

func queryXraySpecificUser(
	ctx context.Context,
	runtime SessionRuntime,
	endpoint APIEndpoint,
	server string,
	uuid string,
	runner func(ctx context.Context, command string, args ...string) ([]byte, error),
) ([]SessionEvidence, error) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return nil, newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray live session querying requires a non-empty uuid for targeted membership lookup",
		)
	}

	ips, name, err := queryXrayOnlineIPsWithName(ctx, runner, server, uuid)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 && strings.TrimSpace(name) == "" {
		return nil, nil
	}

	if len(ips) == 0 {
		return []SessionEvidence{
			{
				Runtime: runtime,
				Session: Session{
					ID:      xrayOnlineUserSessionID(uuid),
					Runtime: runtime,
					Policy: SessionPolicyIdentity{
						UUID: uuid,
					},
				},
				Confidence: SessionEvidenceConfidenceMedium,
				Note:       fmt.Sprintf("observed via Xray StatsService online-user evidence through API endpoint %s; concrete client-ip evidence was not returned", describeAPIEndpoint(endpoint)),
			},
		}, nil
	}

	evidence := make([]SessionEvidence, 0, len(ips))
	for _, ip := range ips {
		evidence = append(evidence, SessionEvidence{
			Runtime: runtime,
			Session: Session{
				ID:      xrayOnlineIPSessionID(uuid, ip),
				Runtime: runtime,
				Policy: SessionPolicyIdentity{
					UUID: uuid,
				},
				Client: SessionClient{
					IP: ip,
				},
			},
			Confidence: SessionEvidenceConfidenceHigh,
			Note:       fmt.Sprintf("observed via Xray StatsService online IP query through API endpoint %s", describeAPIEndpoint(endpoint)),
		})
	}

	return evidence, nil
}

func defaultXrayAPICommandRunner(ctx context.Context, server string, command string, args ...string) ([]byte, error) {
	argv := []string{"api", command, "--server=" + server, "--timeout=3"}
	argv = append(argv, args...)

	cmd := exec.CommandContext(ctx, "xray", argv...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		code := SessionEvidenceIssueUnavailable
		if strings.Contains(strings.ToLower(message), "permission denied") {
			code = SessionEvidenceIssuePermissionDenied
		}
		return nil, newXraySessionQueryError(
			code,
			"Xray API command %q failed against %s: %s",
			command,
			server,
			message,
		)
	}

	return output, nil
}

func defaultXrayContainerAPICommandRunner(ctx context.Context, containerID string, server string, command string, args ...string) ([]byte, error) {
	argv := []string{"exec", containerID, "xray", "api", command, "--server=" + server, "--timeout=3"}
	argv = append(argv, args...)

	cmd := exec.CommandContext(ctx, "docker", argv...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		code := SessionEvidenceIssueUnavailable
		if strings.Contains(strings.ToLower(message), "permission denied") {
			code = SessionEvidenceIssuePermissionDenied
		}
		return nil, newXraySessionQueryError(
			code,
			"Xray API command %q failed inside container %s against %s: %s",
			command,
			containerID,
			server,
			message,
		)
	}

	return output, nil
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

	host := strings.TrimSpace(endpoint.Address)
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}

	return fmt.Sprintf("%s:%d", host, endpoint.Port), nil
}

func queryXrayOnlineUsers(ctx context.Context, runner func(context.Context, string, ...string) ([]byte, error), server string) ([]string, error) {
	output, err := runner(ctx, "statsgetallonlineusers")
	if err != nil {
		return nil, err
	}

	var response xrayGetAllOnlineUsersResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray API endpoint %s returned an invalid online-users response: %v",
			server,
			err,
		)
	}

	users := make([]string, 0, len(response.Users))
	seen := make(map[string]struct{}, len(response.Users))
	for _, user := range response.Users {
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
	ips, _, err := queryXrayOnlineIPsWithName(ctx, runner, server, user)
	return ips, err
}

func queryXrayOnlineIPsWithName(ctx context.Context, runner func(context.Context, string, ...string) ([]byte, error), server string, user string) ([]string, string, error) {
	output, err := runner(ctx, "statsonlineiplist", "-email", user)
	if err != nil {
		return nil, "", err
	}

	var response xrayGetStatsOnlineIPListResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, "", newXraySessionQueryError(
			SessionEvidenceIssueInsufficient,
			"Xray API endpoint %s returned an invalid online-ip response for user %q: %v",
			server,
			user,
			err,
		)
	}

	if len(response.IPs) == 0 {
		return nil, strings.TrimSpace(response.Name), nil
	}

	ips := make([]string, 0, len(response.IPs))
	seen := make(map[string]struct{}, len(response.IPs))
	for ip := range response.IPs {
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

	return ips, strings.TrimSpace(response.Name), nil
}

func normalizeXrayClientIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}

	return addr.Unmap().String()
}

func xrayOnlineIPSessionID(user string, ip string) string {
	user = strings.ToLower(strings.TrimSpace(user))
	ip = strings.TrimSpace(ip)
	return xrayOnlineIPSessionIDPrefix + user + ":" + ip
}

func xrayOnlineUserSessionID(user string) string {
	user = strings.ToLower(strings.TrimSpace(user))
	return xrayOnlineUserSessionIDPrefix + user
}

func sessionQueryErrorCode(err error) (SessionEvidenceIssueCode, bool) {
	var queryErr xraySessionQueryError
	if errors.As(err, &queryErr) {
		return queryErr.Code, true
	}

	return "", false
}
