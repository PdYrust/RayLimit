package tc

import (
	"strconv"
	"strings"
)

// nftOutputIsJSON reports whether nft output should be decoded as JSON. `nft -j
// list ruleset` emits a top-level object ('{'); some builds wrap it in an array
// ('['). Empty or whitespace-only output is treated as non-JSON so the
// plain-text parser reduces it to an empty snapshot.
func nftOutputIsJSON(stdout string) bool {
	for _, r := range stdout {
		switch r {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			continue
		}
		return r == '{' || r == '['
	}

	return false
}

// parseNftablesRulesetText parses the plain-text form of `nft [-a] list ruleset`
// into the same minimal NftablesSnapshot the JSON path produces. It is emitted
// by nftables builds that predate `-j` (or silently ignore it) and looks like:
//
//	table inet raylimit { # handle 1
//		chain raylimit_inbound_upload { # handle 2
//			type filter hook input priority mangle; policy accept;
//			tcp dport 443 counter meta mark set 0x1 comment "raylimit:..." # handle 4
//		}
//	}
//
// The parser is intentionally lenient: it tracks brace depth so anonymous sets
// or unrelated blocks do not confuse table/chain detection, ignores unknown
// lines, and silently skips tables whose family is not one RayLimit manages.
func parseNftablesRulesetText(stdout string) (NftablesSnapshot, error) {
	snapshot := NftablesSnapshot{}

	depth := 0
	var (
		curTableFamily string
		curTableName   string
		curTableValid  bool
		curChainIdx    = -1
	)

	for _, raw := range strings.Split(stdout, "\n") {
		line, handle := stripNftHandleComment(strings.TrimSpace(raw))
		if line == "" {
			continue
		}

		if line == "}" {
			depth--
			switch {
			case depth <= 0:
				depth = 0
				curTableFamily = ""
				curTableName = ""
				curTableValid = false
				curChainIdx = -1
			case depth == 1:
				// Closed a chain (or other depth-2 block) back to table scope.
				curChainIdx = -1
			}
			continue
		}

		if strings.HasSuffix(line, "{") {
			depth++
			fields := strings.Fields(strings.TrimSuffix(line, "{"))
			switch {
			case depth == 1 && len(fields) >= 3 && fields[0] == "table":
				curTableFamily = fields[1]
				curTableName = fields[2]
				curTableValid = validNftablesFamily(curTableFamily)
				curChainIdx = -1
				if curTableValid {
					snapshot.Tables = append(snapshot.Tables, NftablesTableState{
						Family: curTableFamily,
						Name:   curTableName,
						Handle: handle,
					})
				}
			case depth == 2 && curTableValid && len(fields) >= 2 && fields[0] == "chain":
				snapshot.Chains = append(snapshot.Chains, NftablesChainState{
					Family: curTableFamily,
					Table:  curTableName,
					Name:   fields[1],
					Handle: handle,
				})
				curChainIdx = len(snapshot.Chains) - 1
			default:
				// An unrelated block (set, map, nested object); track depth only.
				if depth == 2 {
					curChainIdx = -1
				}
			}
			continue
		}

		// Non-brace content line.
		if depth != 2 || curChainIdx < 0 {
			continue
		}
		if strings.HasPrefix(line, "type ") {
			applyNftChainDefinition(&snapshot.Chains[curChainIdx], line)
			continue
		}
		if strings.HasPrefix(line, "policy ") {
			continue
		}

		snapshot.Rules = append(snapshot.Rules, NftablesRuleState{
			Family:  curTableFamily,
			Table:   curTableName,
			Chain:   snapshot.Chains[curChainIdx].Name,
			Handle:  handle,
			Comment: extractNftComment(line),
		})
	}

	if err := snapshot.Validate(); err != nil {
		return NftablesSnapshot{}, err
	}

	return snapshot, nil
}

// stripNftHandleComment removes a trailing `# handle N` annotation (emitted by
// `nft -a`) and returns the cleaned line plus the parsed handle (0 when absent).
func stripNftHandleComment(line string) (string, uint64) {
	const marker = "# handle "
	index := strings.LastIndex(line, marker)
	if index < 0 {
		return line, 0
	}

	clean := strings.TrimSpace(line[:index])
	rest := strings.Fields(strings.TrimSpace(line[index+len(marker):]))
	if len(rest) == 0 {
		return clean, 0
	}

	handle, err := strconv.ParseUint(rest[0], 10, 64)
	if err != nil {
		return clean, 0
	}

	return clean, handle
}

// extractNftComment returns the value of a rule's `comment "..."` clause, or an
// empty string when no comment is present.
func extractNftComment(line string) string {
	const marker = `comment "`
	index := strings.Index(line, marker)
	if index < 0 {
		return ""
	}

	rest := line[index+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}

	return rest[:end]
}

// applyNftChainDefinition fills the chain type, hook, and numeric priority from
// a `type ... hook ... priority ...;` base-chain definition line. A symbolic
// priority keyword (for example "mangle") leaves the numeric priority at zero,
// which the snapshot comparison treats as "not comparable" rather than a
// mismatch.
func applyNftChainDefinition(chain *NftablesChainState, line string) {
	fields := strings.Fields(line)
	for index := 0; index+1 < len(fields); index++ {
		switch fields[index] {
		case "type":
			chain.Type = strings.TrimSuffix(fields[index+1], ";")
		case "hook":
			chain.Hook = strings.TrimSuffix(fields[index+1], ";")
		case "priority":
			if value, err := strconv.Atoi(strings.TrimSuffix(fields[index+1], ";")); err == nil {
				chain.Priority = value
			}
		}
	}
}
