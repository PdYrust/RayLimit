package discovery

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// stubAPIRunner builds a runner closure compatible with queryXrayOnlineUsers /
// queryXrayOnlineIPs. The handler receives the api command and its arguments so
// tests can vary the response by command and by requested email.
func stubAPIRunner(handler func(command string, args ...string) ([]byte, error)) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, command string, args ...string) ([]byte, error) {
		return handler(command, args...)
	}
}

func TestQueryXrayOnlineUsersPlainTextSkipsEmptyEmailSegment(t *testing.T) {
	runner := stubAPIRunner(func(command string, args ...string) ([]byte, error) {
		if command != "statsgetallonlineusers" {
			t.Fatalf("unexpected command %q with args %#v", command, args)
		}
		return []byte("user>>>user-a>>>online\nuser>>>>>>online\nuser>>>user-c>>>online\n"), nil
	})

	users, err := queryXrayOnlineUsers(context.Background(), runner, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("expected plain-text online-users parsing to succeed, got %v", err)
	}

	want := []string{"user-a", "user-c"}
	if !reflect.DeepEqual(users, want) {
		t.Fatalf("expected empty-email record to be skipped, got %#v", users)
	}
	for _, user := range users {
		if user == "user" {
			t.Fatalf("literal identity prefix leaked into parsed users: %#v", users)
		}
	}
}

func TestQueryXrayOnlineIPsPlainTextExtractsTrailingIPSegment(t *testing.T) {
	runner := stubAPIRunner(func(command string, args ...string) ([]byte, error) {
		if command != "statsonlineiplist" {
			t.Fatalf("unexpected command %q with args %#v", command, args)
		}
		if len(args) != 2 || args[0] != "-email" || args[1] != "user-a" {
			t.Fatalf("unexpected statsonlineiplist args %#v", args)
		}
		return []byte("user>>>user-a>>>online>>>203.0.113.10\nuser>>>user-a>>>online>>>203.0.113.11\n"), nil
	})

	ips, err := queryXrayOnlineIPs(context.Background(), runner, "127.0.0.1:10085", "user-a")
	if err != nil {
		t.Fatalf("expected plain-text online-ip parsing to succeed, got %v", err)
	}

	want := []string{"203.0.113.10", "203.0.113.11"}
	if !reflect.DeepEqual(ips, want) {
		t.Fatalf("expected both trailing IP segments to be extracted, got %#v", ips)
	}
}

func TestQueryXrayOnlineIPsPlainTextRejectsMisattributedUser(t *testing.T) {
	runner := stubAPIRunner(func(command string, args ...string) ([]byte, error) {
		if command != "statsonlineiplist" {
			t.Fatalf("unexpected command %q with args %#v", command, args)
		}
		return []byte("user>>>user-b>>>online>>>203.0.113.10\n"), nil
	})

	ips, err := queryXrayOnlineIPs(context.Background(), runner, "127.0.0.1:10085", "user-a")
	if err == nil {
		t.Fatalf("expected mis-attributed online-ip evidence to be rejected, got %#v", ips)
	}

	code, ok := sessionQueryErrorCode(err)
	if !ok || code != SessionEvidenceIssueInsufficient {
		t.Fatalf("expected insufficient query error, got code=%q ok=%v err=%v", code, ok, err)
	}
}

func TestQueryXrayOnlineIPsJSONVerifiesNameAttribution(t *testing.T) {
	const payload = `{"name":"user>>>user-a>>>online","ips":{"203.0.113.10":1710000000}}`

	runner := stubAPIRunner(func(command string, args ...string) ([]byte, error) {
		if command != "statsonlineiplist" {
			t.Fatalf("unexpected command %q with args %#v", command, args)
		}
		return []byte(payload), nil
	})

	ips, err := queryXrayOnlineIPs(context.Background(), runner, "127.0.0.1:10085", "user-a")
	if err != nil {
		t.Fatalf("expected JSON online-ip parsing to succeed for the attributed user, got %v", err)
	}
	if want := []string{"203.0.113.10"}; !reflect.DeepEqual(ips, want) {
		t.Fatalf("expected attributed IP to be returned, got %#v", ips)
	}

	mismatch, err := queryXrayOnlineIPs(context.Background(), runner, "127.0.0.1:10085", "user-z")
	if err == nil {
		t.Fatalf("expected JSON name attribution mismatch to be rejected, got %#v", mismatch)
	}
	code, ok := sessionQueryErrorCode(err)
	if !ok || code != SessionEvidenceIssueInsufficient {
		t.Fatalf("expected insufficient query error for mismatched name, got code=%q ok=%v err=%v", code, ok, err)
	}
}

func TestQueryXrayOnlineUsersJSONFormStillParses(t *testing.T) {
	runner := stubAPIRunner(func(command string, args ...string) ([]byte, error) {
		if command != "statsgetallonlineusers" {
			t.Fatalf("unexpected command %q with args %#v", command, args)
		}
		return []byte(`{"users":["user-b","user-a","user-a"]}`), nil
	})

	users, err := queryXrayOnlineUsers(context.Background(), runner, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("expected JSON online-users parsing to succeed, got %v", err)
	}

	if want := []string{"user-a", "user-b"}; !reflect.DeepEqual(users, want) {
		t.Fatalf("expected deduplicated, sorted JSON users, got %#v", users)
	}
}

func TestQueryXrayOnlineUsersEmptyOutputYieldsNoUsers(t *testing.T) {
	runner := stubAPIRunner(func(string, ...string) ([]byte, error) {
		return []byte("   \n"), nil
	})

	users, err := queryXrayOnlineUsers(context.Background(), runner, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("expected empty output to be treated as no sessions, got %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("expected no users from empty output, got %#v", users)
	}
}

func TestQueryXraySessionsReportsStatsUserOnlineNotEnabledOnEmptyUsers(t *testing.T) {
	endpoint := APIEndpoint{Name: "api", Network: EndpointNetworkTCP, Address: "127.0.0.1", Port: 10085}
	runner := func(_ context.Context, command string, args ...string) ([]byte, error) {
		if command != "statsgetallonlineusers" {
			t.Fatalf("unexpected command %q with args %#v", command, args)
		}
		return []byte(`{"users":[]}`), nil
	}

	statsUserOnlineDisabled := false
	evidence, err := queryXraySessions(
		context.Background(),
		testXrayEvidenceRuntime(),
		endpoint,
		"127.0.0.1:10085",
		runner,
		&statsUserOnlineDisabled,
	)
	if err == nil {
		t.Fatalf("expected StatsUserOnline-not-enabled error, got evidence %#v", evidence)
	}

	code, ok := sessionQueryErrorCode(err)
	if !ok || code != SessionEvidenceIssueStatsUserOnlineNotEnabled {
		t.Fatalf("expected stats-user-online-not-enabled query error, got code=%q ok=%v err=%v", code, ok, err)
	}
	if !strings.Contains(err.Error(), "StatsUserOnline") || !strings.Contains(err.Error(), "api.services") {
		t.Fatalf("expected actionable message naming the service and config key, got %q", err.Error())
	}
}

func TestQueryXraySessionsTreatsEmptyUsersAsNoSessionsWhenGateNotApplicable(t *testing.T) {
	endpoint := APIEndpoint{Name: "api", Network: EndpointNetworkTCP, Address: "127.0.0.1", Port: 10085}
	runner := func(_ context.Context, command string, args ...string) ([]byte, error) {
		if command != "statsgetallonlineusers" {
			t.Fatalf("unexpected command %q with args %#v", command, args)
		}
		return []byte(`{"users":[]}`), nil
	}

	statsUserOnlineEnabled := true
	gates := map[string]*bool{
		"enabled":      &statsUserOnlineEnabled,
		"undetermined": nil,
	}
	for name, gate := range gates {
		evidence, err := queryXraySessions(
			context.Background(),
			testXrayEvidenceRuntime(),
			endpoint,
			"127.0.0.1:10085",
			runner,
			gate,
		)
		if err != nil {
			t.Fatalf("[%s] expected genuine no-sessions to succeed, got %v", name, err)
		}
		if evidence != nil {
			t.Fatalf("[%s] expected no evidence for empty users, got %#v", name, evidence)
		}
	}
}
