package specgen

import (
	"fmt"
	"regexp"
	"strings"
)

type tokenInfo struct {
	Tokens    map[string][]string
	AllTokens map[string]bool
}

type envSpec struct {
	UnixPathsOnly bool
}

func parseTokenEnvInfo(man string) (tokenInfo, map[string]envSpec, error) {
	tokens := tokenInfo{Tokens: make(map[string][]string), AllTokens: make(map[string]bool)}
	env := make(map[string]envSpec)

	lines := strings.Split(man, "\n")
	section := ""
	tokensReady := false
	pending := []string{}

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, ".Sh ") {
			switch strings.TrimSpace(strings.TrimPrefix(line, ".Sh ")) {
			case "TOKENS":
				section = "tokens"
				tokensReady = false
			case "ENVIRONMENT VARIABLES":
				section = "env"
			default:
				section = ""
			}
			pending = nil
			continue
		}
		if section == "tokens" && line == ".El" {
			tokensReady = true
			pending = nil
			continue
		}
		if section == "" {
			continue
		}
		if strings.HasPrefix(line, ".Cm ") {
			if section == "tokens" && !tokensReady {
				continue
			}
			name := parseDirectiveName(line)
			if name != "" {
				pending = append(pending, name)
			}
			continue
		}
		if len(pending) == 0 {
			continue
		}
		switch section {
		case "tokens":
			if strings.Contains(line, "accepts all tokens") {
				for _, name := range pending {
					tokens.AllTokens[name] = true
				}
				pending = nil
				continue
			}
			if strings.Contains(line, "accept the tokens") || strings.Contains(line, "accepts the tokens") || strings.Contains(line, "additionally accepts the tokens") {
				list := extractTokens(line)
				if len(list) == 0 {
					return tokens, env, fmt.Errorf("no tokens parsed from: %q", line)
				}
				for _, name := range pending {
					existing := tokens.Tokens[name]
					seen := make(map[string]bool, len(existing))
					for _, t := range existing {
						seen[t] = true
					}
					for _, t := range list {
						if !seen[t] {
							existing = append(existing, t)
							seen[t] = true
						}
					}
					tokens.Tokens[name] = existing
				}
				pending = nil
			}
		case "env":
			if strings.Contains(line, "support environment variables only for Unix domain socket paths") {
				for _, name := range pending {
					env[name] = envSpec{UnixPathsOnly: true}
				}
				pending = nil
				continue
			}
			if strings.Contains(line, "support environment variables") {
				for _, name := range pending {
					env[name] = envSpec{}
				}
				pending = nil
				continue
			}
		}
	}

	return tokens, env, nil
}

func parseDirectiveName(line string) string {
	name := strings.TrimSpace(strings.TrimPrefix(line, ".Cm"))
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ",")
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return strings.ToLower(name)
}

var tokenRe = regexp.MustCompile(`%[%A-Za-z]`)

func extractTokens(line string) []string {
	matches := tokenRe.FindAllString(line, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	seen := make(map[string]bool)
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
