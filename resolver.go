package ssh_config

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	osuser "os/user"
	"strings"
)

type resolveOptions struct {
	strict       bool
	finalPass    bool
	canonicalize func(string) (string, bool, error)
}

// Strict enables strict validation using the OpenSSH client spec.
func Strict() ResolveOption {
	return func(o *resolveOptions) {
		o.strict = true
	}
}

// FinalPass enables a final pass where Match final evaluates true.
func FinalPass() ResolveOption {
	return func(o *resolveOptions) {
		o.finalPass = true
	}
}

// Canonicalize provides a callback to perform host canonicalization.
func Canonicalize(fn func(host string) (canonical string, changed bool, err error)) ResolveOption {
	return func(o *resolveOptions) {
		o.canonicalize = fn
	}
}

type passType int

const (
	passInitial passType = iota
	passCanonical
	passFinal
)

// Resolve evaluates the Config with OpenSSH-like semantics.
func (c *Config) Resolve(ctx Context, opts ...ResolveOption) (*Result, error) {
	return resolveConfigs(ctx, opts, []*Config{c})
}

// Resolve evaluates user/system config files with OpenSSH-like semantics.
func (u *UserSettings) Resolve(ctx Context, opts ...ResolveOption) (*Result, error) {
	u.doLoadConfigs()
	if u.onceErr != nil && !u.IgnoreErrors {
		return nil, u.onceErr
	}
	var configs []*Config
	if u.customConfig != nil {
		configs = []*Config{u.customConfig}
	} else {
		if u.userConfig != nil {
			configs = append(configs, u.userConfig)
		}
		if u.systemConfig != nil {
			configs = append(configs, u.systemConfig)
		}
	}
	return resolveConfigs(ctx, opts, configs)
}

func resolveConfigs(ctx Context, opts []ResolveOption, configs []*Config) (*Result, error) {
	if ctx.HostArg == "" {
		return nil, errors.New("ssh_config: Context.HostArg is required")
	}
	spec, err := loadClientSpec()
	if err != nil {
		return nil, err
	}
	ctx = normalizeContext(ctx, spec)

	options := resolveOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	result, err := resolvePass(ctx, passInitial, configs, options, spec)
	if err != nil {
		return nil, err
	}

	if options.canonicalize != nil {
		canonical, changed, err := options.canonicalize(ctx.HostArg)
		if err != nil {
			return nil, err
		}
		if changed && canonical != "" {
			ctx.HostArg = canonical
			result, err = resolvePass(ctx, passCanonical, configs, options, spec)
			if err != nil {
				return nil, err
			}
		}
	}

	if options.finalPass {
		result, err = resolvePass(ctx, passFinal, configs, options, spec)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func resolvePass(ctx Context, pass passType, configs []*Config, options resolveOptions, spec *clientSpec) (*Result, error) {
	state := &resolveState{
		values: make(map[string][]string),
	}
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		if err := resolveConfig(cfg, ctx, pass, options, spec, state, false); err != nil {
			return nil, err
		}
	}
	applyDefaults(state, ctx, spec)
	return &Result{values: state.values}, nil
}

type resolveState struct {
	values        map[string][]string
	ignoreUnknown string
}

func resolveConfig(cfg *Config, ctx Context, pass passType, options resolveOptions, spec *clientSpec, state *resolveState, neverMatch bool) error {
	blocks := cfg.effectiveBlocks()
	for _, block := range blocks {
		switch b := block.(type) {
		case *Host:
			active := false
			if !neverMatch {
				active = b.Matches(ctx.HostArg)
			}
			if err := resolveNodes(b.Nodes, active, ctx, pass, options, spec, state, neverMatch); err != nil {
				return err
			}
		case *Match:
			active := false
			if !neverMatch {
				criteria, err := parseMatchCriteria(b.Criteria)
				if err != nil {
					if options.strict {
						return err
					}
					active = false
				} else {
					ok, err := evalMatch(criteria, ctx, pass, options, spec, state)
					if err != nil {
						return err
					}
					active = ok
				}
			}
			if err := resolveNodes(b.Nodes, active, ctx, pass, options, spec, state, neverMatch); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveNodes(nodes []Node, active bool, ctx Context, pass passType, options resolveOptions, spec *clientSpec, state *resolveState, neverMatch bool) error {
	for _, node := range nodes {
		switch n := node.(type) {
		case *Empty:
			continue
		case *KV:
			if err := applyDirective(n.Key, n.Value, active, ctx, pass, options, spec, state); err != nil {
				return err
			}
		case *Include:
			includeNeverMatch := neverMatch || !active
			for _, path := range n.matches {
				cfg := n.files[path]
				if cfg == nil {
					continue
				}
				if err := resolveConfig(cfg, ctx, pass, options, spec, state, includeNeverMatch); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("ssh_config: unknown Node type %T", n)
		}
	}
	return nil
}

func applyDirective(key, value string, active bool, ctx Context, pass passType, options resolveOptions, spec *clientSpec, state *resolveState) error {
	lkey := strings.ToLower(strings.TrimSpace(key))
	directive := spec.byName[lkey]
	if directive == nil {
		if options.strict {
			if matchesIgnoreUnknown(state.ignoreUnknown, lkey) {
				return nil
			}
			return fmt.Errorf("ssh_config: unknown directive %q", key)
		}
		return nil
	}
	if directive.Status == "unsupported" {
		if options.strict {
			return fmt.Errorf("ssh_config: unsupported directive %q", key)
		}
		return nil
	}
	if directive.Status == "deprecated" && directive.AliasFor == "" && options.strict {
		return fmt.Errorf("ssh_config: deprecated directive %q", key)
	}
	if options.strict {
		if err := validateValue(directive, value); err != nil {
			return err
		}
	}
	if !active {
		return nil
	}
	canonical := directive.Canonical
	if directive.AliasFor != "" {
		canonical = directive.AliasFor
	}
	canonical = strings.ToLower(canonical)
	if canonical == "ignoreunknown" {
		if _, ok := state.values[canonical]; !ok {
			state.values[canonical] = []string{value}
			state.ignoreUnknown = value
		}
		return nil
	}
	if directive.Multi {
		state.values[canonical] = append(state.values[canonical], value)
		return nil
	}
	if _, ok := state.values[canonical]; !ok {
		state.values[canonical] = []string{value}
	}
	return nil
}

func validateValue(directive *specDirective, value string) error {
	val := strings.TrimSpace(value)
	switch directive.Type {
	case "yesno":
		lower := strings.ToLower(val)
		if lower != "yes" && lower != "no" {
			return fmt.Errorf("ssh_config: value for %q must be yes or no", directive.Name)
		}
	case "uint":
		if val == "" {
			return fmt.Errorf("ssh_config: value for %q must be an unsigned integer", directive.Name)
		}
		for _, r := range val {
			if r < '0' || r > '9' {
				return fmt.Errorf("ssh_config: value for %q must be an unsigned integer", directive.Name)
			}
		}
	case "enum":
		if len(directive.Enum) == 0 {
			return nil
		}
		lower := strings.ToLower(val)
		for _, entry := range directive.Enum {
			if strings.ToLower(entry) == lower {
				return nil
			}
		}
		return fmt.Errorf("ssh_config: invalid value %q for %q", value, directive.Name)
	case "list":
		if val == "" {
			return fmt.Errorf("ssh_config: value for %q must be non-empty", directive.Name)
		}
	}
	return nil
}

func applyDefaults(state *resolveState, ctx Context, spec *clientSpec) {
	for i := range spec.Directives {
		d := &spec.Directives[i]
		if d.Name != d.Canonical {
			continue
		}
		if d.Status != "supported" {
			continue
		}
		key := strings.ToLower(d.Name)
		if _, ok := state.values[key]; ok {
			continue
		}
		defaults := d.defaultValues()
		if len(defaults) == 0 {
			continue
		}
		if d.Multi {
			state.values[key] = append([]string(nil), defaults...)
		} else {
			state.values[key] = []string{defaults[0]}
		}
	}
	if _, ok := state.values["hostname"]; !ok && ctx.HostArg != "" {
		state.values["hostname"] = []string{ctx.HostArg}
	}
	if _, ok := state.values["user"]; !ok && ctx.LocalUser != "" {
		state.values["user"] = []string{ctx.LocalUser}
	}
}

func normalizeContext(ctx Context, spec *clientSpec) Context {
	if ctx.OriginalHost == "" {
		ctx.OriginalHost = ctx.HostArg
	}
	if ctx.LocalUser == "" {
		ctx.LocalUser = currentUserName()
	}
	if ctx.Version == "" {
		ctx.Version = spec.OpenSSHVersion
	}
	if ctx.SessionType == "" {
		ctx.SessionType = "shell"
	}
	return ctx
}

func currentUserName() string {
	usr, err := osuser.Current()
	if err == nil && usr != nil && usr.Username != "" {
		if idx := strings.LastIndex(usr.Username, "\\"); idx >= 0 {
			return usr.Username[idx+1:]
		}
		return usr.Username
	}
	if env := os.Getenv("USER"); env != "" {
		return env
	}
	if env := os.Getenv("USERNAME"); env != "" {
		return env
	}
	return ""
}

func matchesIgnoreUnknown(patterns, key string) bool {
	if patterns == "" {
		return false
	}
	matched, _ := matchPatternList(key, patterns, true)
	return matched
}

// Match criteria handling.

type matchCriterion struct {
	name   string
	value  string
	negate bool
}

func parseMatchCriteria(raw string) ([]matchCriterion, error) {
	fields, err := tokenizeMatchCriteria(raw)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("ssh_config: Match requires criteria")
	}
	criteria := make([]matchCriterion, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		field := fields[i]
		negate := strings.HasPrefix(field, "!")
		if negate {
			field = strings.TrimPrefix(field, "!")
		}
		name := strings.ToLower(field)
		if name == "all" || name == "canonical" || name == "final" {
			criteria = append(criteria, matchCriterion{name: name, negate: negate})
			continue
		}
		arg := ""
		if strings.Contains(field, "=") {
			parts := strings.SplitN(field, "=", 2)
			name = strings.ToLower(parts[0])
			arg = parts[1]
		} else {
			if i+1 >= len(fields) {
				return nil, fmt.Errorf("ssh_config: missing argument for Match %q", name)
			}
			arg = fields[i+1]
			i++
		}
		criteria = append(criteria, matchCriterion{name: name, value: arg, negate: negate})
	}
	return criteria, nil
}

func tokenizeMatchCriteria(raw string) ([]string, error) {
	fields := make([]string, 0, 8)
	var field strings.Builder
	inQuotes := false
	escaped := false

	flush := func() {
		if field.Len() == 0 {
			return
		}
		fields = append(fields, field.String())
		field.Reset()
	}

	for _, r := range raw {
		if escaped {
			switch r {
			case ' ', '\t', '"', '\\':
				field.WriteRune(r)
			default:
				field.WriteRune('\\')
				field.WriteRune(r)
			}
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '"':
			inQuotes = !inQuotes
		case ' ', '\t':
			if inQuotes {
				field.WriteRune(r)
			} else {
				flush()
			}
		default:
			field.WriteRune(r)
		}
	}

	if escaped {
		field.WriteRune('\\')
	}
	if inQuotes {
		return nil, fmt.Errorf("ssh_config: unterminated quoted Match criterion")
	}

	flush()
	return fields, nil
}

func evalMatch(criteria []matchCriterion, ctx Context, pass passType, options resolveOptions, spec *clientSpec, state *resolveState) (bool, error) {
	if len(criteria) == 0 {
		return false, fmt.Errorf("ssh_config: Match requires criteria")
	}
	if err := validateMatchAll(criteria); err != nil {
		return false, err
	}
	result := true
	for _, c := range criteria {
		if !result && c.name == "exec" {
			continue
		}
		matched, err := evalCriterion(c, ctx, pass, options, spec, state)
		if err != nil {
			return false, err
		}
		if !matched {
			result = false
		}
	}
	return result, nil
}

func validateMatchAll(criteria []matchCriterion) error {
	for i, c := range criteria {
		if c.name != "all" {
			continue
		}
		if len(criteria) == 1 {
			return nil
		}
		if len(criteria) == 2 && i == 1 {
			if criteria[0].name == "canonical" || criteria[0].name == "final" {
				return nil
			}
		}
		return fmt.Errorf("ssh_config: Match all cannot be combined with other attributes")
	}
	return nil
}

func evalCriterion(c matchCriterion, ctx Context, pass passType, options resolveOptions, spec *clientSpec, state *resolveState) (bool, error) {
	negate := c.negate
	switch c.name {
	case "all":
		return applyNegation(true, negate), nil
	case "canonical":
		return applyNegation(pass == passCanonical, negate), nil
	case "final":
		return applyNegation(pass == passFinal, negate), nil
	case "host":
		host := effectiveHost(ctx, state)
		matched, err := matchPatternList(host, c.value, true)
		return applyNegation(matched, negate), err
	case "originalhost":
		matched, err := matchPatternList(ctx.OriginalHost, c.value, true)
		return applyNegation(matched, negate), err
	case "user":
		matched, err := matchPatternList(remoteUser(ctx, state), c.value, false)
		return applyNegation(matched, negate), err
	case "localuser":
		matched, err := matchPatternList(ctx.LocalUser, c.value, false)
		return applyNegation(matched, negate), err
	case "localnetwork":
		if ctx.LocalNetwork == nil {
			if options.strict {
				return false, fmt.Errorf("ssh_config: Match localnetwork requires LocalNetwork callback")
			}
			return false, nil
		}
		ok, err := ctx.LocalNetwork(c.value)
		if err != nil {
			if options.strict {
				return false, err
			}
			return false, nil
		}
		return applyNegation(ok, negate), nil
	case "version":
		matched, err := matchPatternList(ctx.Version, c.value, false)
		return applyNegation(matched, negate), err
	case "tagged":
		tag := firstValue(state.values, "tag")
		if tag == "" && c.value == "" {
			return applyNegation(true, negate), nil
		}
		matched, err := matchPatternList(tag, c.value, false)
		return applyNegation(matched, negate), err
	case "command":
		if ctx.Command == "" && c.value == "" {
			return applyNegation(true, negate), nil
		}
		matched, err := matchPatternList(ctx.Command, c.value, false)
		return applyNegation(matched, negate), err
	case "sessiontype":
		stype := sessionType(ctx, state)
		matched, err := matchPatternList(stype, c.value, false)
		return applyNegation(matched, negate), err
	case "exec":
		if ctx.Exec == nil {
			if options.strict {
				return false, fmt.Errorf("ssh_config: Match exec requires Exec callback")
			}
			return false, nil
		}
		cmd, err := expandMatchExec(c.value, ctx, state, spec)
		if err != nil {
			if options.strict {
				return false, err
			}
			return false, nil
		}
		ok, err := ctx.Exec(cmd)
		if err != nil {
			if options.strict {
				return false, err
			}
			return false, nil
		}
		return applyNegation(ok, negate), nil
	default:
		if options.strict {
			return false, fmt.Errorf("ssh_config: unsupported Match attribute %q", c.name)
		}
		return false, nil
	}
}

func applyNegation(value, negate bool) bool {
	if negate {
		return !value
	}
	return value
}

func remoteUser(ctx Context, state *resolveState) string {
	if user := firstValue(state.values, "user"); user != "" {
		return user
	}
	return ctx.LocalUser
}

func sessionType(ctx Context, state *resolveState) string {
	if st := firstValue(state.values, "sessiontype"); st != "" {
		return st
	}
	if ctx.Command != "" {
		return "exec"
	}
	return ctx.SessionType
}

func effectiveHost(ctx Context, state *resolveState) string {
	if hn := firstValue(state.values, "hostname"); hn != "" {
		return expandHostName(hn, ctx.HostArg)
	}
	return ctx.HostArg
}

func expandHostName(value, hostArg string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			b.WriteByte(value[i])
			continue
		}
		if i+1 >= len(value) {
			b.WriteByte('%')
			continue
		}
		switch value[i+1] {
		case '%':
			b.WriteByte('%')
		case 'h':
			b.WriteString(hostArg)
		default:
			b.WriteByte('%')
			b.WriteByte(value[i+1])
		}
		i++
	}
	return b.String()
}

func expandMatchExec(value string, ctx Context, state *resolveState, spec *clientSpec) (string, error) {
	localHost, _ := os.Hostname()
	shortHost := localHost
	if idx := strings.Index(localHost, "."); idx > 0 {
		shortHost = localHost[:idx]
	}
	port := resolvePort(state, spec)
	remote := remoteUser(ctx, state)
	jump := firstValue(state.values, "proxyjump")
	if strings.EqualFold(jump, "none") {
		jump = ""
	}
	host := effectiveHost(ctx, state)
	keyAlias := firstValue(state.values, "hostkeyalias")
	if keyAlias == "" {
		keyAlias = host
	}
	uid := currentUID()
	connHash := connectionHash(localHost, host, port, remote, jump)
	values := map[string]string{
		"%%": "%",
		"%C": connHash,
		"%L": shortHost,
		"%d": currentHomeDir(),
		"%h": host,
		"%k": keyAlias,
		"%l": localHost,
		"%n": ctx.OriginalHost,
		"%p": port,
		"%r": remote,
		"%u": ctx.LocalUser,
		"%i": uid,
		"%j": jump,
	}
	return expandTokens(value, values), nil
}

func connectionHash(localHost, host, port, user, jump string) string {
	h := sha1.New()
	h.Write([]byte(localHost))
	h.Write([]byte(host))
	h.Write([]byte(port))
	h.Write([]byte(user))
	h.Write([]byte(jump))
	return hex.EncodeToString(h.Sum(nil))
}

func expandTokens(value string, values map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			b.WriteByte(value[i])
			continue
		}
		if i+1 >= len(value) {
			b.WriteByte('%')
			continue
		}
		token := value[i : i+2]
		if repl, ok := values[token]; ok {
			b.WriteString(repl)
		} else {
			b.WriteString(token)
		}
		i++
	}
	return b.String()
}

func currentUID() string {
	usr, err := osuser.Current()
	if err == nil && usr != nil {
		return usr.Uid
	}
	return ""
}

func currentHomeDir() string {
	home, err := os.UserHomeDir()
	if err == nil {
		return home
	}
	return ""
}

func resolvePort(state *resolveState, spec *clientSpec) string {
	if port := firstValue(state.values, "port"); port != "" {
		return port
	}
	if spec != nil {
		if d := spec.byName["port"]; d != nil {
			if def := d.defaultValues(); len(def) > 0 {
				return def[0]
			}
		}
	}
	return "22"
}

func firstValue(values map[string][]string, key string) string {
	if values == nil {
		return ""
	}
	vals := values[strings.ToLower(key)]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func matchPatternList(value, patternList string, caseInsensitive bool) (bool, error) {
	valueToMatch := value
	if caseInsensitive {
		valueToMatch = strings.ToLower(value)
	}
	matched := false
	parts := splitPatternList(patternList)
	for _, part := range parts {
		if part == "" {
			continue
		}
		negate := strings.HasPrefix(part, "!")
		if negate {
			part = strings.TrimPrefix(part, "!")
		}
		pattern := part
		if caseInsensitive {
			pattern = strings.ToLower(pattern)
		}
		ok, err := matchPattern(valueToMatch, pattern)
		if err != nil {
			return false, err
		}
		if ok {
			if negate {
				return false, nil
			}
			matched = true
		}
	}
	return matched, nil
}

func splitPatternList(patterns string) []string {
	return strings.FieldsFunc(patterns, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
}

func matchPattern(value, pattern string) (bool, error) {
	if pattern == "" {
		return false, nil
	}
	pat, err := NewPattern(pattern)
	if err != nil {
		return false, err
	}
	return pat.regex.MatchString(value), nil
}
