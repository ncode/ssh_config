package specgen

import (
	"fmt"
	"regexp"
	"strings"
)

type keywordEntry struct {
	Name   string
	Opcode string
	Status string
}

type enumEntry struct {
	Key   string
	Value string
}

type opcodeInfo struct {
	ValueType   string
	Multistate  string
	OptionField string
	Multi       bool
}

func parseKeywords(readconf string) ([]keywordEntry, error) {
	start := strings.Index(readconf, "keywords[]")
	if start == -1 {
		return nil, fmt.Errorf("keywords[] not found")
	}
	block := readconf[start:]
	end := strings.Index(block, "{ NULL, oBadOption }")
	if end == -1 {
		return nil, fmt.Errorf("keywords[] terminator not found")
	}
	block = block[:end]

	re := regexp.MustCompile(`\{\s*"([^"]+)"\s*,\s*(o\w+)\s*\}`)
	matches := re.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no keywords found")
	}

	entries := make([]keywordEntry, 0, len(matches))
	for _, m := range matches {
		name := strings.ToLower(m[1])
		opcode := m[2]
		entries = append(entries, keywordEntry{
			Name:   name,
			Opcode: opcode,
			Status: opcodeStatus(opcode),
		})
	}
	return entries, nil
}

func opcodeStatus(opcode string) string {
	switch opcode {
	case "oDeprecated":
		return "deprecated"
	case "oUnsupported", "oIgnore":
		return "unsupported"
	default:
		return "supported"
	}
}

func parseMultistates(readconf string) (map[string][]enumEntry, error) {
	result := make(map[string][]enumEntry)
	reStart := regexp.MustCompile(`static const struct multistate\s+(\w+)\[]\s*=\s*\{`)
	lines := strings.Split(readconf, "\n")
	var current string
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if current == "" {
			if m := reStart.FindStringSubmatch(trim); m != nil {
				current = m[1]
				result[current] = []enumEntry{}
			}
			continue
		}
		if strings.HasPrefix(trim, "};") {
			current = ""
			continue
		}
		if strings.HasPrefix(trim, "{ NULL") {
			continue
		}
		if !strings.HasPrefix(trim, "{") {
			continue
		}
		fields := strings.SplitN(trim, ",", 3)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSpace(strings.TrimPrefix(fields[0], "{"))
		key = strings.Trim(key, "\" ")
		val := strings.TrimSpace(fields[1])
		val = strings.Trim(val, " }")
		if key == "" {
			continue
		}
		result[current] = append(result[current], enumEntry{Key: key, Value: val})
	}
	return result, nil
}

func parseOpcodeInfos(readconf string) (map[string]opcodeInfo, error) {
	infos := make(map[string]opcodeInfo)
	lines := strings.Split(readconf, "\n")
	caseRe := regexp.MustCompile(`case\s+(o\w+):`)
	multistateRe := regexp.MustCompile(`multistate_ptr\s*=\s*(multistate_\w+)`) // capture name
	optionFieldRe := regexp.MustCompile(`options->([a-zA-Z0-9_]+)`)             // heuristic

	var active []string
	lastWasCase := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if m := caseRe.FindStringSubmatch(trim); m != nil {
			if !lastWasCase {
				active = nil
			}
			active = append(active, m[1])
			for _, opcode := range active {
				if _, ok := infos[opcode]; !ok {
					infos[opcode] = opcodeInfo{ValueType: "string"}
				}
			}
			lastWasCase = true
			continue
		}
		if len(active) == 0 {
			if trim != "" {
				lastWasCase = false
			}
			continue
		}
		if trim != "" && !strings.HasPrefix(trim, "/*") && !strings.HasPrefix(trim, "//") {
			lastWasCase = false
		}
		if strings.Contains(trim, "goto parse_flag") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "yesno" })
		}
		if strings.Contains(trim, "goto parse_multistate") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "enum" })
		}
		if strings.Contains(trim, "goto parse_int") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "uint" })
		}
		if strings.Contains(trim, "goto parse_time") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "string" })
		}
		if strings.Contains(trim, "goto parse_string") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "string" })
		}
		if strings.Contains(trim, "goto parse_command") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "string" })
		}
		if strings.Contains(trim, "goto parse_char_array") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "list" })
		}
		if strings.Contains(trim, "goto parse_pubkey_algos") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "list" })
		}
		if strings.Contains(trim, "parse_forward(") || strings.Contains(trim, "add_local_forward") || strings.Contains(trim, "add_remote_forward") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.ValueType = "list" })
		}
		if m := multistateRe.FindStringSubmatch(trim); m != nil {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.Multistate = m[1] })
		}
		if m := optionFieldRe.FindStringSubmatch(trim); m != nil {
			field := m[1]
			if strings.HasPrefix(field, "num_") || strings.HasPrefix(field, "fwd_opts") {
				// skip counters and nested structs
			} else {
				applyOpcodeInfo(infos, active, func(info *opcodeInfo) {
					if info.OptionField == "" {
						info.OptionField = field
					}
				})
			}
		}
		if strings.Contains(trim, "add_identity_file") || strings.Contains(trim, "add_certificate_file") ||
			strings.Contains(trim, "add_local_forward") || strings.Contains(trim, "add_remote_forward") {
			applyOpcodeInfo(infos, active, func(info *opcodeInfo) { info.Multi = true })
		}
		if strings.HasPrefix(trim, "break;") {
			active = nil
			lastWasCase = false
		}
	}

	return infos, nil
}

func applyOpcodeInfo(infos map[string]opcodeInfo, opcodes []string, apply func(*opcodeInfo)) {
	for _, opcode := range opcodes {
		info := infos[opcode]
		apply(&info)
		infos[opcode] = info
	}
}

func parseDefaults(readconf string) (map[string]string, map[string][]string) {
	defaults := make(map[string]string)
	defaultLists := make(map[string][]string)

	body := extractFunctionBody(readconf, "fill_default_options")
	if body != "" {
		assignRe := regexp.MustCompile(`(?s)if\s*\(\s*options->(\w+)\s*==\s*[^\)]+\)\s*options->(\w+)\s*=\s*([^;]+);`)
		matches := assignRe.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			field := m[1]
			assignField := m[2]
			if field != assignField {
				continue
			}
			expr := strings.TrimSpace(m[3])
			if _, ok := defaults[field]; ok {
				continue
			}
			defaults[field] = normalizeExpr(expr)
		}

		identityRe := regexp.MustCompile(`add_identity_file\(options,\s*"~\/",\s*([A-Z0-9_]+),\s*0\)`)
		for _, m := range identityRe.FindAllStringSubmatch(body, -1) {
			defaultLists["identity_files"] = append(defaultLists["identity_files"], "~/"+m[1])
		}

		systemHostRe := regexp.MustCompile(`system_hostfiles\[.*?\]\s*=\s*xstrdup\(([^\)]+)\)`) // macros
		for _, m := range systemHostRe.FindAllStringSubmatch(body, -1) {
			defaultLists["system_hostfiles"] = append(defaultLists["system_hostfiles"], normalizeExpr(m[1]))
		}

		userHostRe := regexp.MustCompile(`user_hostfiles\[.*?\]\s*=\s*xstrdup\(([^\)]+)\)`) // macros
		for _, m := range userHostRe.FindAllStringSubmatch(body, -1) {
			defaultLists["user_hostfiles"] = append(defaultLists["user_hostfiles"], normalizeExpr(m[1]))
		}
	}

	canonBody := extractFunctionBody(readconf, "fill_default_options_for_canonicalization")
	if canonBody != "" {
		assignRe := regexp.MustCompile(`(?s)if\s*\(\s*options->(\w+)\s*==\s*[^\)]+\)\s*options->(\w+)\s*=\s*([^;]+);`)
		matches := assignRe.FindAllStringSubmatch(canonBody, -1)
		for _, m := range matches {
			field := m[1]
			assignField := m[2]
			if field != assignField {
				continue
			}
			expr := strings.TrimSpace(m[3])
			if _, ok := defaults[field]; ok {
				continue
			}
			defaults[field] = normalizeExpr(expr)
		}
	}

	return defaults, defaultLists
}

func extractFunctionBody(readconf, name string) string {
	idx := strings.Index(readconf, name+"(")
	if idx == -1 {
		return ""
	}
	snippet := readconf[idx:]
	braceIdx := strings.Index(snippet, "{")
	if braceIdx == -1 {
		return ""
	}
	start := idx + braceIdx + 1
	depth := 1
	for i := start; i < len(readconf); i++ {
		switch readconf[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return readconf[start:i]
			}
		}
	}
	return ""
}

func normalizeExpr(expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "xstrdup(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSuffix(strings.TrimPrefix(expr, "xstrdup("), ")")
		expr = strings.TrimSpace(expr)
	}
	return expr
}

func defaultValue(expr string, d DirectiveSpec, info opcodeInfo, multistates map[string][]enumEntry, macros macroResolver) (any, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, false
	}
	if strings.Contains(expr, "?") || strings.Contains(expr, "options->") {
		return nil, false
	}
	if strings.HasSuffix(expr, ")") && strings.HasPrefix(expr, "xstrdup(") {
		expr = strings.TrimSuffix(strings.TrimPrefix(expr, "xstrdup("), ")")
		expr = strings.TrimSpace(expr)
	}

	resolved := expr
	if strings.HasPrefix(resolved, "\"") && strings.HasSuffix(resolved, "\"") {
		resolved = strings.Trim(resolved, "\"")
	}
	if strings.HasPrefix(resolved, "$") {
		// keep literal env default
		return resolved, true
	}
	if isIdentifier(resolved) {
		if val := resolveMacroString(macros, resolved); val != "" {
			resolved = val
		}
	}
	if d.Type == "yesno" {
		switch resolved {
		case "1":
			return "yes", true
		case "0":
			return "no", true
		}
		if isIdentifier(resolved) {
			if val := mapEnumValue(info.Multistate, multistates, resolved); val != "" {
				return val, true
			}
		}
	}
	if d.Type == "enum" {
		if val := mapEnumValue(info.Multistate, multistates, resolved); val != "" {
			return val, true
		}
	}
	if d.Type == "uint" {
		if isNumber(resolved) {
			return resolved, true
		}
	}
	if d.Type == "string" || d.Type == "list" {
		if resolved != expr && resolved != "" {
			return resolved, true
		}
		if strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"") {
			return strings.Trim(expr, "\""), true
		}
		if isNumber(expr) {
			return expr, true
		}
		if isIdentifier(expr) {
			if val := resolveMacroString(macros, expr); val != "" {
				return val, true
			}
		}
	}
	return nil, false
}

func mapEnumValue(multistateName string, multistates map[string][]enumEntry, expr string) string {
	entries, ok := multistates[multistateName]
	if !ok {
		return ""
	}
	var matches []string
	for _, entry := range entries {
		if entry.Value == expr || entry.Key == expr {
			matches = append(matches, entry.Key)
		}
	}
	if len(matches) == 0 {
		return ""
	}
	for _, pref := range []string{"yes", "no"} {
		for _, match := range matches {
			if match == pref {
				return match
			}
		}
	}
	return matches[0]
}

func enumKeys(entries []enumEntry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Key)
	}
	return out
}

func resolveDefaultList(list []string, macros macroResolver) []string {
	resolved := make([]string, 0, len(list))
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "~/") {
			macro := strings.TrimPrefix(item, "~/")
			if isIdentifier(macro) {
				val := resolveMacroString(macros, macro)
				if val != "" {
					resolved = append(resolved, "~/"+strings.TrimPrefix(val, "./"))
					continue
				}
			}
			resolved = append(resolved, item)
			continue
		}
		if isIdentifier(item) {
			val := resolveMacroString(macros, item)
			if val != "" {
				resolved = append(resolved, val)
				continue
			}
		}
		if strings.HasPrefix(item, "\"") && strings.HasSuffix(item, "\"") {
			resolved = append(resolved, strings.Trim(item, "\""))
			continue
		}
		resolved = append(resolved, item)
	}
	return resolved
}

func isIdentifier(val string) bool {
	if val == "" {
		return false
	}
	for i, r := range val {
		if i == 0 {
			if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
				return false
			}
			continue
		}
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func isNumber(val string) bool {
	if val == "" {
		return false
	}
	for _, r := range val {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
