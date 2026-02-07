package ssh_config

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	_ "embed"
)

//go:embed testdata/openssh_client_spec.json
var embeddedClientSpec []byte

var (
	clientSpecOnce sync.Once
	clientSpecErr  error
	clientSpecData *clientSpec
)

type clientSpec struct {
	OpenSSHVersion  string          `json:"opensshVersion"`
	Directives      []specDirective `json:"directives"`
	MatchExecTokens []string        `json:"matchExecTokens"`
	byName          map[string]*specDirective
}

type specDirective struct {
	Name         string      `json:"name"`
	Canonical    string      `json:"canonical"`
	Status       string      `json:"status"`
	Type         string      `json:"type"`
	Multi        bool        `json:"multi"`
	Default      interface{} `json:"default"`
	AliasFor     string      `json:"aliasFor"`
	Enum         []string    `json:"enum"`
	Tokens       []string    `json:"tokens"`
	TokensAll    bool        `json:"tokensAll"`
	Env          bool        `json:"env"`
	EnvUnixPaths bool        `json:"envUnixPaths"`
}

func loadClientSpec() (*clientSpec, error) {
	clientSpecOnce.Do(func() {
		var spec clientSpec
		if err := json.Unmarshal(embeddedClientSpec, &spec); err != nil {
			clientSpecErr = fmt.Errorf("ssh_config: decode client spec: %w", err)
			return
		}
		spec.byName = make(map[string]*specDirective, len(spec.Directives))
		for i := range spec.Directives {
			d := &spec.Directives[i]
			name := strings.ToLower(d.Name)
			spec.byName[name] = d
		}
		if len(spec.MatchExecTokens) == 0 {
			spec.MatchExecTokens = nil
		}
		clientSpecData = &spec
	})
	return clientSpecData, clientSpecErr
}

func (d *specDirective) defaultValues() []string {
	if d == nil || d.Default == nil {
		return nil
	}
	switch v := d.Default.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		if len(v) == 0 {
			return nil
		}
		return append([]string(nil), v...)
	default:
		return nil
	}
}
