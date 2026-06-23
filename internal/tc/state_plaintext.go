package tc

import (
	"fmt"
	"strconv"
	"strings"
)

// TCStateParseError reports tc output that matched neither the JSON grammar
// (iproute2 -j output) nor the plain-text grammar emitted by older / BusyBox /
// stripped tc builds. Callers can use errors.As to distinguish genuinely
// malformed output from an empty (but valid) tc state.
type TCStateParseError struct {
	// Object is the tc object being parsed: "qdisc", "class", or "filter".
	Object string
	// Sample is a short, trimmed snippet of the offending output.
	Sample string
}

func (e *TCStateParseError) Error() string {
	return fmt.Sprintf("tc %s output was not parsable as JSON or plain text: %q", e.Object, e.Sample)
}

func newTCStateParseError(object string, sample string) error {
	return &TCStateParseError{Object: object, Sample: tcSampleSnippet(sample)}
}

func tcSampleSnippet(value string) string {
	value = strings.TrimSpace(value)
	const limit = 120
	if len(value) > limit {
		return value[:limit] + "…"
	}

	return value
}

// tcOutputIsJSON reports whether tc output should be decoded as JSON. tc -j
// emits a top-level array, so the first non-whitespace byte is '['. Empty or
// whitespace-only output is treated as non-JSON (the plain-text parsers reduce
// it to an empty result set).
func tcOutputIsJSON(stdout string) bool {
	for _, r := range stdout {
		switch r {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			continue
		}
		return r == '['
	}

	return false
}

func tcNonEmptyLines(stdout string) []string {
	rawLines := strings.Split(stdout, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lines = append(lines, trimmed)
	}

	return lines
}

// parseQDiscStatesText parses the plain-text form of `tc qdisc show`, e.g.
// "qdisc htb 1: root refcnt 2 r2q 10 default 10 direct_packets_stat 0".
// Unknown trailing fields are ignored; a line that is not a qdisc record is a
// hard parse error.
func parseQDiscStatesText(stdout string) ([]QDiscState, error) {
	lines := tcNonEmptyLines(stdout)
	states := make([]QDiscState, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "qdisc" {
			return nil, newTCStateParseError("qdisc", line)
		}

		states = append(states, QDiscState{
			Kind:   fields[1],
			Handle: fields[2],
			Parent: parseTCParentFromFields(fields[3:]),
		})
	}

	return states, nil
}

// parseClassStatesText parses the plain-text form of `tc class show`, e.g.
// "class htb 1:1 root prio 0 rate 10Mbit ceil 10Mbit burst 1600b cburst 1600b".
func parseClassStatesText(stdout string) ([]ClassState, error) {
	lines := tcNonEmptyLines(stdout)
	states := make([]ClassState, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "class" {
			return nil, newTCStateParseError("class", line)
		}

		states = append(states, ClassState{
			Kind:               fields[1],
			ClassID:            fields[2],
			Parent:             parseTCParentFromFields(fields[3:]),
			RateBytesPerSecond: parseTCRateAfter(fields, "rate"),
			CeilBytesPerSecond: parseTCRateAfter(fields, "ceil"),
		})
	}

	return states, nil
}

// parseFilterStatesText parses the plain-text form of `tc filter show`, e.g.
// "filter parent 1: protocol ip pref 100 u32 ... fh 800::800 ... flowid 1:1".
// Indented continuation lines (match/key/action details) that follow a parsed
// filter are ignored; a non-filter leading line before any filter record is a
// hard parse error.
func parseFilterStatesText(stdout string) ([]FilterState, error) {
	lines := tcNonEmptyLines(stdout)
	states := make([]FilterState, 0, len(lines))
	parsedAny := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != "filter" {
			if parsedAny {
				// Continuation/detail line for the preceding filter record.
				continue
			}
			return nil, newTCStateParseError("filter", line)
		}

		parsedAny = true
		states = append(states, parseTCFilterLine(fields))
	}

	return states, nil
}

func parseTCFilterLine(fields []string) FilterState {
	state := FilterState{}
	for index := 0; index < len(fields); index++ {
		switch fields[index] {
		case "parent":
			if index+1 < len(fields) {
				state.Parent = fields[index+1]
			}
		case "protocol":
			if index+1 < len(fields) {
				state.Protocol = fields[index+1]
			}
		case "pref", "preference":
			if index+1 < len(fields) {
				if value, ok := parseTCUint32(fields[index+1]); ok {
					state.Preference = value
				}
			}
			// The classifier kind immediately follows the preference value.
			if index+2 < len(fields) && state.Kind == "" {
				if isTCFilterKind(fields[index+2]) {
					state.Kind = fields[index+2]
				}
			}
		case "fh", "handle":
			if index+1 < len(fields) {
				state.Handle = fields[index+1]
			}
		case "flowid", "classid":
			if index+1 < len(fields) {
				state.FlowID = fields[index+1]
			}
		}
	}

	if state.Kind == "" {
		for _, field := range fields {
			if isTCFilterKind(field) {
				state.Kind = field
				break
			}
		}
	}

	return state
}

func parseTCParentFromFields(fields []string) string {
	for index := 0; index < len(fields); index++ {
		switch fields[index] {
		case "root":
			return "root"
		case "parent":
			if index+1 < len(fields) {
				return fields[index+1]
			}
		}
	}

	return ""
}

func parseTCRateAfter(fields []string, key string) int64 {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == key {
			if value, ok := parseBytesPerSecondString(fields[index+1]); ok {
				return value
			}
			return 0
		}
	}

	return 0
}

func parseTCUint32(value string) (uint32, bool) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, false
	}

	return uint32(parsed), true
}

func isTCFilterKind(value string) bool {
	switch value {
	case "u32", "fw", "flower", "matchall", "basic", "route", "bpf", "cgroup", "flow", "rsvp", "tcindex":
		return true
	default:
		return false
	}
}
