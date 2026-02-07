package specgen

import (
	"bufio"
	"bytes"
	"strings"
)

type macroDef struct {
	Raw string
}

type macroResolver map[string]macroDef

func parseMacros(files map[string][]byte) macroResolver {
	macros := make(macroResolver)
	for _, data := range files {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "#define ") {
				continue
			}
			line = strings.TrimPrefix(line, "#define ")
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			name := parts[0]
			if strings.Contains(name, "(") {
				continue
			}
			rest := strings.TrimSpace(line[len(name):])
			value := strings.TrimSpace(rest)
			if strings.HasSuffix(value, "\\") {
				value = strings.TrimSuffix(value, "\\")
				var continuation []string
				continuation = append(continuation, strings.TrimSpace(value))
				for scanner.Scan() {
					next := strings.TrimSpace(scanner.Text())
					if strings.HasSuffix(next, "\\") {
						next = strings.TrimSuffix(next, "\\")
						continuation = append(continuation, strings.TrimSpace(next))
						continue
					}
					continuation = append(continuation, strings.TrimSpace(next))
					break
				}
				value = strings.Join(continuation, " ")
			}
			value = stripComments(value)
			macros[name] = macroDef{Raw: strings.TrimSpace(value)}
		}
	}
	return macros
}

func resolveMacroString(macros macroResolver, name string) string {
	resolved, _ := resolveMacroStringWithStack(macros, name, map[string]bool{})
	return resolved
}

func resolveMacroStringWithStack(macros macroResolver, name string, visiting map[string]bool) (string, bool) {
	if visiting[name] {
		return "", false
	}
	def, ok := macros[name]
	if !ok {
		return "", false
	}
	visiting[name] = true
	resolved := resolveMacroValue(macros, def.Raw, visiting)
	visiting[name] = false
	if resolved == "" {
		return "", false
	}
	return resolved, true
}

func resolveMacroValue(macros macroResolver, raw string, visiting map[string]bool) string {
	tokens := tokenizeMacro(raw)
	if len(tokens) == 0 {
		return ""
	}
	var out strings.Builder
	for _, tok := range tokens {
		if tok.isString {
			out.WriteString(tok.value)
			continue
		}
		if val, ok := resolveMacroStringWithStack(macros, tok.value, visiting); ok {
			out.WriteString(val)
			continue
		}
		// Unknown identifiers are ignored to avoid emitting partial garbage.
	}
	return out.String()
}

type macroToken struct {
	value    string
	isString bool
}

func tokenizeMacro(raw string) []macroToken {
	var tokens []macroToken
	r := []rune(raw)
	for i := 0; i < len(r); {
		switch r[i] {
		case ' ', '\t', '\n', '\r':
			i++
			continue
		case '"':
			j := i + 1
			for j < len(r) && r[j] != '"' {
				j++
			}
			if j > i+1 {
				tokens = append(tokens, macroToken{value: string(r[i+1 : j]), isString: true})
			}
			if j < len(r) {
				j++
			}
			i = j
			continue
		default:
			if isIdentStart(r[i]) {
				j := i + 1
				for j < len(r) && isIdentContinue(r[j]) {
					j++
				}
				tokens = append(tokens, macroToken{value: string(r[i:j])})
				i = j
				continue
			}
			if r[i] >= '0' && r[i] <= '9' {
				j := i + 1
				for j < len(r) && r[j] >= '0' && r[j] <= '9' {
					j++
				}
				tokens = append(tokens, macroToken{value: string(r[i:j]), isString: true})
				i = j
				continue
			}
			i++
		}
	}
	return tokens
}

func isIdentStart(r rune) bool {
	return r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

func isIdentContinue(r rune) bool {
	return isIdentStart(r) || (r >= '0' && r <= '9')
}

func stripComments(value string) string {
	if idx := strings.Index(value, "/*"); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.Index(value, "//"); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}
