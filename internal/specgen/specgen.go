package specgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Spec struct {
	OpenSSHVersion  string          `json:"opensshVersion"`
	Directives      []DirectiveSpec `json:"directives"`
	MatchExecTokens []string        `json:"matchExecTokens,omitempty"`
}

type DirectiveSpec struct {
	Name         string   `json:"name"`
	Canonical    string   `json:"canonical"`
	Status       string   `json:"status"`
	Type         string   `json:"type"`
	Multi        bool     `json:"multi"`
	Default      any      `json:"default,omitempty"`
	AliasFor     string   `json:"aliasFor,omitempty"`
	Enum         []string `json:"enum,omitempty"`
	Tokens       []string `json:"tokens,omitempty"`
	TokensAll    bool     `json:"tokensAll,omitempty"`
	Env          bool     `json:"env,omitempty"`
	EnvUnixPaths bool     `json:"envUnixPaths,omitempty"`
}

func Generate(openSSHDir string) (*Spec, error) {
	readconfPath := filepath.Join(openSSHDir, "readconf.c")
	manPath := filepath.Join(openSSHDir, "ssh_config.5")
	pathnamesPath := filepath.Join(openSSHDir, "pathnames.h")
	myproposalPath := filepath.Join(openSSHDir, "myproposal.h")
	versionPath := filepath.Join(openSSHDir, "version.h")
	sshPath := filepath.Join(openSSHDir, "ssh.h")

	readconfBytes, err := os.ReadFile(readconfPath)
	if err != nil {
		return nil, fmt.Errorf("read readconf.c: %w", err)
	}
	manBytes, err := os.ReadFile(manPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh_config.5: %w", err)
	}
	pathnamesBytes, err := os.ReadFile(pathnamesPath)
	if err != nil {
		return nil, fmt.Errorf("read pathnames.h: %w", err)
	}
	myproposalBytes, err := os.ReadFile(myproposalPath)
	if err != nil {
		return nil, fmt.Errorf("read myproposal.h: %w", err)
	}
	versionBytes, err := os.ReadFile(versionPath)
	if err != nil {
		return nil, fmt.Errorf("read version.h: %w", err)
	}
	sshBytes, err := os.ReadFile(sshPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh.h: %w", err)
	}

	macros := parseMacros(map[string][]byte{
		"pathnames.h":  pathnamesBytes,
		"myproposal.h": myproposalBytes,
		"version.h":    versionBytes,
		"ssh.h":        sshBytes,
	})

	keywords, err := parseKeywords(string(readconfBytes))
	if err != nil {
		return nil, err
	}
	multistates, err := parseMultistates(string(readconfBytes))
	if err != nil {
		return nil, err
	}
	opcodeInfos, err := parseOpcodeInfos(string(readconfBytes))
	if err != nil {
		return nil, err
	}
	defaults, defaultLists := parseDefaults(string(readconfBytes))

	tokenInfo, envInfo, err := parseTokenEnvInfo(string(manBytes))
	if err != nil {
		return nil, err
	}

	canonicalByOpcode := make(map[string]string)
	multiKeywords := map[string]bool{
		"identityfile":    true,
		"certificatefile": true,
		"localforward":    true,
		"remoteforward":   true,
		"dynamicforward":  true,
		"sendenv":         true,
	}

	for _, kw := range keywords {
		if canonicalByOpcode[kw.Opcode] == "" {
			if kw.Status == "supported" {
				canonicalByOpcode[kw.Opcode] = kw.Name
			}
		}
	}
	for _, kw := range keywords {
		if canonicalByOpcode[kw.Opcode] == "" {
			canonicalByOpcode[kw.Opcode] = kw.Name
		}
	}

	openSSHVersion := resolveMacroString(macros, "SSH_RELEASE")
	defaultPort := resolveMacroString(macros, "SSH_DEFAULT_PORT")
	algoDefaults := map[string]string{
		"ciphers":                     "KEX_CLIENT_ENCRYPT",
		"macs":                        "KEX_CLIENT_MAC",
		"kexalgorithms":               "KEX_CLIENT_KEX",
		"hostbasedacceptedalgorithms": "KEX_DEFAULT_PK_ALG",
		"pubkeyacceptedalgorithms":    "KEX_DEFAULT_PK_ALG",
		"casignaturealgorithms":       "SSH_ALLOWED_CA_SIGALGS",
	}
	typeOverrides := map[string]string{
		"port": "uint",
	}

	directives := make([]DirectiveSpec, 0, len(keywords))
	for _, kw := range keywords {
		info := opcodeInfos[kw.Opcode]
		if multiKeywords[kw.Name] {
			info.Multi = true
			opcodeInfos[kw.Opcode] = info
		}
		d := DirectiveSpec{
			Name:      kw.Name,
			Canonical: canonicalByOpcode[kw.Opcode],
			Status:    kw.Status,
			Type:      info.ValueType,
			Multi:     info.Multi,
		}
		if override, ok := typeOverrides[d.Name]; ok {
			d.Type = override
		}
		if d.Name != d.Canonical {
			d.AliasFor = d.Canonical
		}
		if info.ValueType == "enum" {
			if entries, ok := multistates[info.Multistate]; ok {
				d.Enum = enumKeys(entries)
			}
		}
		if tokens, ok := tokenInfo.Tokens[d.Name]; ok {
			d.Tokens = tokens
		}
		if tokenInfo.AllTokens[d.Name] {
			d.TokensAll = true
		}
		if env, ok := envInfo[d.Name]; ok {
			d.Env = true
			d.EnvUnixPaths = env.UnixPathsOnly
		}
		if d.Name == d.Canonical {
			if list, ok := defaultLists[info.OptionField]; ok && len(list) > 0 {
				if resolved := resolveDefaultList(list, macros); len(resolved) > 0 {
					d.Default = resolved
				}
			} else if expr, ok := defaults[info.OptionField]; ok {
				if val, ok := defaultValue(expr, d, info, multistates, macros); ok {
					d.Default = val
				}
			}
			if d.Default == nil {
				if macro, ok := algoDefaults[d.Name]; ok {
					if val := resolveMacroString(macros, macro); val != "" {
						d.Default = val
					}
				}
				if d.Name == "port" && defaultPort != "" {
					d.Default = defaultPort
				}
			}
		}
		directives = append(directives, d)
	}

	sort.Slice(directives, func(i, j int) bool {
		return directives[i].Name < directives[j].Name
	})

	spec := &Spec{
		OpenSSHVersion: openSSHVersion,
		Directives:     directives,
	}
	if tokens, ok := tokenInfo.Tokens["match exec"]; ok {
		spec.MatchExecTokens = tokens
	}

	return spec, nil
}

func GenerateBytes(openSSHDir string) ([]byte, error) {
	spec, err := Generate(openSSHDir)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(spec, "", "  ")
}
