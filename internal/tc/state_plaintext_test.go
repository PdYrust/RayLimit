package tc

import (
	"context"
	"errors"
	"testing"
)

func TestParseSnapshotParsesJSONOutputRegression(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{Step: "show-qdisc", Stdout: `[{"kind":"htb","handle":"1:"}]`},
		{Step: "show-class", Stdout: `[{"kind":"htb","classid":"1:2a","parent":"1:","options":{"rate":"2048bps","ceil":"4096bps"}}]`},
		{Step: "show-filter", Stdout: `[{"kind":"u32","parent":"1:","protocol":"ip","pref":100,"options":{"flowid":"1:2a"}}]`},
	})
	if err != nil {
		t.Fatalf("expected JSON parsing to succeed, got %v", err)
	}
	if len(snapshot.QDiscs) != 1 || snapshot.QDiscs[0].Kind != "htb" {
		t.Fatalf("unexpected qdiscs: %#v", snapshot.QDiscs)
	}
	if len(snapshot.Classes) != 1 || snapshot.Classes[0].RateBytesPerSecond != 2048 || snapshot.Classes[0].CeilBytesPerSecond != 4096 {
		t.Fatalf("unexpected classes: %#v", snapshot.Classes)
	}
	if len(snapshot.Filters) != 1 || snapshot.Filters[0].Preference != 100 || snapshot.Filters[0].FlowID != "1:2a" {
		t.Fatalf("unexpected filters: %#v", snapshot.Filters)
	}
}

func TestParseSnapshotParsesPlainTextQDisc(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{Step: "show-qdisc", Stdout: "qdisc htb 1: root refcnt 2 r2q 10 default 10 direct_packets_stat 0\n"},
	})
	if err != nil {
		t.Fatalf("expected plain-text qdisc parsing to succeed, got %v", err)
	}
	if len(snapshot.QDiscs) != 1 {
		t.Fatalf("expected one qdisc, got %#v", snapshot.QDiscs)
	}
	q := snapshot.QDiscs[0]
	if q.Kind != "htb" || q.Handle != "1:" || q.Parent != "root" {
		t.Fatalf("unexpected qdisc: %#v", q)
	}
}

func TestParseSnapshotParsesPlainTextClassRate(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{Step: "show-class", Stdout: "class htb 1:1 root prio 0 rate 10Mbit ceil 10Mbit burst 1600b cburst 1600b\n"},
	})
	if err != nil {
		t.Fatalf("expected plain-text class parsing to succeed, got %v", err)
	}
	if len(snapshot.Classes) != 1 {
		t.Fatalf("expected one class, got %#v", snapshot.Classes)
	}
	c := snapshot.Classes[0]
	if c.Kind != "htb" || c.ClassID != "1:1" || c.Parent != "root" {
		t.Fatalf("unexpected class identity: %#v", c)
	}
	if c.RateBytesPerSecond != 1_250_000 || c.CeilBytesPerSecond != 1_250_000 {
		t.Fatalf("expected 10Mbit to parse to 1,250,000 bytes/s, got %#v", c)
	}
}

func TestParseSnapshotParsesPlainTextFilter(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{Step: "show-filter", Stdout: "filter parent 1: protocol ip pref 100 u32 chain 0 fh 800::800 order 1 key ht 800 bkt 0 flowid 1:1\n  match 0a000000/ff000000 at 12\n"},
	})
	if err != nil {
		t.Fatalf("expected plain-text filter parsing to succeed, got %v", err)
	}
	if len(snapshot.Filters) != 1 {
		t.Fatalf("expected one filter, got %#v", snapshot.Filters)
	}
	f := snapshot.Filters[0]
	if f.Kind != "u32" || f.Parent != "1:" || f.Protocol != "ip" {
		t.Fatalf("unexpected filter identity: %#v", f)
	}
	if f.Preference != 100 || f.Handle != "800::800" || f.FlowID != "1:1" {
		t.Fatalf("unexpected filter fields: %#v", f)
	}
}

func TestParseSnapshotEmptyOutputYieldsEmptySnapshot(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{Step: "show-qdisc", Stdout: ""},
		{Step: "show-class", Stdout: "   \n"},
		{Step: "show-filter", Stdout: ""},
	})
	if err != nil {
		t.Fatalf("expected empty output to yield an empty snapshot, got %v", err)
	}
	if len(snapshot.QDiscs) != 0 || len(snapshot.Classes) != 0 || len(snapshot.Filters) != 0 {
		t.Fatalf("expected an empty snapshot, got %#v", snapshot)
	}
}

func TestParseSnapshotMalformedOutputReturnsTypedError(t *testing.T) {
	_, err := ParseSnapshot("eth0", []Result{
		{Step: "show-class", Stdout: "garbage not tc output\n"},
	})
	if err == nil {
		t.Fatal("expected malformed output to fail parsing")
	}

	var parseErr *TCStateParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected a *TCStateParseError, got %T: %v", err, err)
	}
	if parseErr.Object != "class" {
		t.Fatalf("expected the class object to be named, got %#v", parseErr)
	}
}

func TestParseSnapshotMalformedJSONReturnsTypedError(t *testing.T) {
	_, err := ParseSnapshot("eth0", []Result{
		{Step: "show-class", Stdout: `[{"kind":"htb"`},
	})
	if err == nil {
		t.Fatal("expected malformed JSON to fail parsing")
	}
	var parseErr *TCStateParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected a *TCStateParseError for malformed JSON, got %T: %v", err, err)
	}
}

type countingProbeRunner struct {
	stdout string
	calls  int
}

func (r *countingProbeRunner) Run(_ context.Context, _ Command) (Result, error) {
	r.calls++
	return Result{Stdout: r.stdout}, nil
}

func TestTCJSONCapabilityCachesProbeResult(t *testing.T) {
	runner := &countingProbeRunner{stdout: "[]"}
	var capability tcJSONCapability

	if !capability.Supported(context.Background(), runner, "") {
		t.Fatal("expected JSON support to be detected from a JSON probe response")
	}
	if !capability.Supported(context.Background(), runner, "") {
		t.Fatal("expected the cached capability to remain true")
	}
	if runner.calls != 1 {
		t.Fatalf("expected the probe to run exactly once, got %d", runner.calls)
	}
}

func TestTCJSONCapabilityDetectsPlainTextRuntime(t *testing.T) {
	runner := &countingProbeRunner{stdout: "qdisc noqueue 0: root refcnt 2"}
	var capability tcJSONCapability

	if capability.Supported(context.Background(), runner, "") {
		t.Fatal("expected a plain-text probe response to report no JSON support")
	}
}
