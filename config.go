// Package ssh_config provides tools for parsing and resolving SSH config files.
//
// Importantly, this parser attempts to preserve comments in a given file, so
// you can manipulate a `ssh_config` file from a program, if your heart desires.
//
// For OpenSSH-accurate evaluation (including Match), use Resolve.
//
//	cfg, _ := ssh_config.Decode(strings.NewReader(config))
//	res, _ := cfg.Resolve(ssh_config.Context{HostArg: "example.com"})
//	port := res.Get("Port")
//
// You can also manipulate an SSH config file and then print it or write it back
// to disk.
//
//	f, _ := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "config"))
//	cfg, _ := ssh_config.Decode(f)
//	for _, host := range cfg.Hosts {
//		fmt.Println("patterns:", host.Patterns)
//		for _, node := range host.Nodes {
//			fmt.Println(node.String())
//		}
//	}
//
//	// Write the cfg back to disk:
//	fmt.Println(cfg.String())
//
// NOTE: Match directives are supported via Resolve.
package ssh_config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

const version = "0.0.1"

var _ = version

type configFinder func() string

// UserSettings checks ~/.ssh and /etc/ssh for configuration files. The config
// files are parsed and cached the first time Resolve is called.
type UserSettings struct {
	IgnoreErrors       bool
	customConfig       *Config
	customConfigFinder configFinder
	systemConfig       *Config
	systemConfigFinder configFinder
	userConfig         *Config
	userConfigFinder   configFinder
	loadConfigs        sync.Once
	onceErr            error
}

func homedir() string {
	user, err := osuser.Current()
	if err == nil {
		return user.HomeDir
	} else {
		return os.Getenv("HOME")
	}
}

func userConfigFinder() string {
	return filepath.Join(homedir(), ".ssh", "config")
}

// DefaultUserSettings is the default UserSettings used for resolving configs.
// It checks both $HOME/.ssh/config and /etc/ssh/ssh_config for keys, and it
// returns parse errors (if any) instead of swallowing them.
var DefaultUserSettings = &UserSettings{
	IgnoreErrors:       false,
	systemConfigFinder: systemConfigFinder,
	userConfigFinder:   userConfigFinder,
}

func systemConfigFinder() string {
	return filepath.Join("/", "etc", "ssh", "ssh_config")
}

// ConfigFinder will invoke f to try to find a ssh config file in a custom
// location on disk, instead of in /etc/ssh or $HOME/.ssh. f should return the
// name of a file containing SSH configuration.
//
// ConfigFinder must be invoked before any calls to Resolve and panics if f is
// nil. Most users should not need to use this function.
func (u *UserSettings) ConfigFinder(f func() string) {
	if f == nil {
		panic("cannot call ConfigFinder with nil function")
	}
	u.customConfigFinder = f
}

func (u *UserSettings) doLoadConfigs() {
	u.loadConfigs.Do(func() {
		var filename string
		var err error
		if u.customConfigFinder != nil {
			filename = u.customConfigFinder()
			u.customConfig, err = parseFile(filename)
			// IsNotExist should be returned because a user specified this
			// function - not existing likely means they made an error
			if err != nil {
				u.onceErr = err
			}
			return
		}
		if u.userConfigFinder == nil {
			filename = userConfigFinder()
		} else {
			filename = u.userConfigFinder()
		}
		u.userConfig, err = parseFile(filename)
		//lint:ignore S1002 I prefer it this way
		if err != nil && os.IsNotExist(err) == false {
			u.onceErr = err
			return
		}
		if u.systemConfigFinder == nil {
			filename = systemConfigFinder()
		} else {
			filename = u.systemConfigFinder()
		}
		u.systemConfig, err = parseFile(filename)
		//lint:ignore S1002 I prefer it this way
		if err != nil && os.IsNotExist(err) == false {
			u.onceErr = err
			return
		}
	})
}

func parseFile(filename string) (*Config, error) {
	return parseWithDepth(filename, 0)
}

func parseWithDepth(filename string, depth uint8) (*Config, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return decodeBytes(b, isSystem(filename), depth)
}

func isSystem(filename string) bool {
	// TODO: not sure this is the best way to detect a system repo
	return strings.HasPrefix(filepath.Clean(filename), "/etc/ssh")
}

// Decode reads r into a Config, or returns an error if r could not be parsed as
// an SSH config file.
func Decode(r io.Reader) (*Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return decodeBytes(b, false, 0)
}

// DecodeBytes reads b into a Config, or returns an error if r could not be
// parsed as an SSH config file.
func DecodeBytes(b []byte) (*Config, error) {
	return decodeBytes(b, false, 0)
}

func decodeBytes(b []byte, system bool, depth uint8) (c *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			if e, ok := r.(error); ok && e == ErrDepthExceeded {
				err = e
				return
			}
			err = errors.New(r.(string))
		}
	}()

	c = parseSSH(lexSSH(b), system, depth)
	return c, err
}

// Config represents an SSH config file.
type Config struct {
	// A list of hosts to match against. The file begins with an implicit
	// "Host *" declaration matching all hosts.
	Hosts    []*Host
	Blocks   []Block
	depth    uint8
	position Position
	hasMatch bool
}

// Context supplies data for Resolve, including Match evaluation.
type Context struct {
	HostArg      string
	OriginalHost string
	LocalUser    string
	Version      string
	SessionType  string
	Command      string
	Exec         func(cmd string) (bool, error)
	LocalNetwork func(cidr string) (bool, error)
}

// ResolveOption configures Resolve behavior.
type ResolveOption func(*resolveOptions)

// Result holds resolved configuration values.
type Result struct {
	values map[string][]string
}

// Get returns the effective value for key, or empty string if none.
func (r *Result) Get(key string) string {
	if r == nil {
		return ""
	}
	vals := r.GetAll(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// GetAll returns all effective values for key.
func (r *Result) GetAll(key string) []string {
	if r == nil {
		return nil
	}
	vals := r.values[strings.ToLower(key)]
	if len(vals) == 0 {
		return nil
	}
	out := make([]string, len(vals))
	copy(out, vals)
	return out
}

// String returns a string representation of the Config file.
func (c Config) String() string {
	return marshal(c).String()
}

func (c Config) MarshalText() ([]byte, error) {
	return marshal(c).Bytes(), nil
}

func (c Config) effectiveBlocks() []Block {
	if len(c.Blocks) > 0 {
		return c.Blocks
	}
	blocks := make([]Block, 0, len(c.Hosts))
	for _, host := range c.Hosts {
		blocks = append(blocks, host)
	}
	return blocks
}

func marshal(c Config) *bytes.Buffer {
	var buf bytes.Buffer
	blocks := c.effectiveBlocks()
	for i := range blocks {
		buf.WriteString(blocks[i].String())
	}
	return &buf
}

// Pattern is a pattern in a Host declaration. Patterns are read-only values;
// create a new one with NewPattern().
type Pattern struct {
	str   string // Its appearance in the file, not the value that gets compiled.
	regex *regexp.Regexp
	not   bool // True if this is a negated match
}

// String prints the string representation of the pattern.
func (p Pattern) String() string {
	return p.str
}

// Copied from regexp.go with * and ? removed.
var specialBytes = []byte(`\.+()|[]{}^$`)

func special(b byte) bool {
	return bytes.IndexByte(specialBytes, b) >= 0
}

// NewPattern creates a new Pattern for matching hosts. NewPattern("*") creates
// a Pattern that matches all hosts.
//
// From the manpage, a pattern consists of zero or more non-whitespace
// characters, `*' (a wildcard that matches zero or more characters), or `?' (a
// wildcard that matches exactly one character). For example, to specify a set
// of declarations for any host in the ".co.uk" set of domains, the following
// pattern could be used:
//
//	Host *.co.uk
//
// The following pattern would match any host in the 192.168.0.[0-9] network range:
//
//	Host 192.168.0.?
func NewPattern(s string) (*Pattern, error) {
	if s == "" {
		return nil, errors.New("ssh_config: empty pattern")
	}
	negated := false
	if s[0] == '!' {
		negated = true
		s = s[1:]
	}
	var buf bytes.Buffer
	buf.WriteByte('^')
	for i := 0; i < len(s); i++ {
		// A byte loop is correct because all metacharacters are ASCII.
		switch b := s[i]; b {
		case '*':
			buf.WriteString(".*")
		case '?':
			buf.WriteString(".?")
		default:
			// borrowing from QuoteMeta here.
			if special(b) {
				buf.WriteByte('\\')
			}
			buf.WriteByte(b)
		}
	}
	buf.WriteByte('$')
	r, err := regexp.Compile(buf.String())
	if err != nil {
		return nil, err
	}
	return &Pattern{str: s, regex: r, not: negated}, nil
}

// Host describes a Host directive and the keywords that follow it.
type Host struct {
	// A list of host patterns that should match this host.
	Patterns []*Pattern
	// A Node is either a key/value pair or a comment line.
	Nodes []Node
	// EOLComment is the comment (if any) terminating the Host line.
	EOLComment string
	// Whitespace if any between the Host declaration and a trailing comment.
	spaceBeforeComment string

	hasEquals    bool
	leadingSpace int // TODO: handle spaces vs tabs here.
	// The file starts with an implicit "Host *" declaration.
	implicit bool
	position Position
}

// Matches returns true if the Host matches for the given alias. For
// a description of the rules that provide a match, see the manpage for
// ssh_config.
func (h *Host) Matches(alias string) bool {
	found := false
	for i := range h.Patterns {
		if h.Patterns[i].regex.MatchString(alias) {
			if h.Patterns[i].not {
				// Negated match. "A pattern entry may be negated by prefixing
				// it with an exclamation mark (`!'). If a negated entry is
				// matched, then the Host entry is ignored, regardless of
				// whether any other patterns on the line match. Negated matches
				// are therefore useful to provide exceptions for wildcard
				// matches."
				return false
			}
			found = true
		}
	}
	return found
}

// Pos returns h's Position.
func (h *Host) Pos() Position {
	return h.position
}

func (h *Host) block() {}

// String prints h as it would appear in a config file. Minor tweaks may be
// present in the whitespace in the printed file.
func (h *Host) String() string {
	var buf strings.Builder
	//lint:ignore S1002 I prefer to write it this way
	if h.implicit == false {
		buf.WriteString(strings.Repeat(" ", int(h.leadingSpace)))
		buf.WriteString("Host")
		if h.hasEquals {
			buf.WriteString(" = ")
		} else {
			buf.WriteString(" ")
		}
		for i, pat := range h.Patterns {
			buf.WriteString(pat.String())
			if i < len(h.Patterns)-1 {
				buf.WriteString(" ")
			}
		}
		buf.WriteString(h.spaceBeforeComment)
		if h.EOLComment != "" {
			buf.WriteByte('#')
			buf.WriteString(h.EOLComment)
		}
		buf.WriteByte('\n')
	}
	for i := range h.Nodes {
		buf.WriteString(h.Nodes[i].String())
		buf.WriteByte('\n')
	}
	return buf.String()
}

// Block represents a top-level block in a Config.
type Block interface {
	Pos() Position
	String() string
	block()
}

// Node represents a line in a Config.
type Node interface {
	Pos() Position
	String() string
}

// Match describes a Match directive and the keywords that follow it.
type Match struct {
	// Criteria is the raw criteria string after the Match directive.
	Criteria string
	// A Node is either a key/value pair or a comment line.
	Nodes []Node
	// EOLComment is the comment (if any) terminating the Match line.
	EOLComment string
	// Whitespace if any between the Match declaration and a trailing comment.
	spaceBeforeComment string

	hasEquals    bool
	leadingSpace int // Space before the Match keyword.
	position     Position
}

// Pos returns m's Position.
func (m *Match) Pos() Position {
	return m.position
}

func (m *Match) block() {}

// String prints m as it would appear in a config file.
func (m *Match) String() string {
	if m == nil {
		return ""
	}
	var buf strings.Builder
	buf.WriteString(strings.Repeat(" ", int(m.leadingSpace)))
	buf.WriteString("Match")
	if m.hasEquals {
		buf.WriteString(" = ")
	} else {
		buf.WriteString(" ")
	}
	buf.WriteString(m.Criteria)
	buf.WriteString(m.spaceBeforeComment)
	if m.EOLComment != "" {
		buf.WriteByte('#')
		buf.WriteString(m.EOLComment)
	}
	buf.WriteByte('\n')
	for i := range m.Nodes {
		buf.WriteString(m.Nodes[i].String())
		buf.WriteByte('\n')
	}
	return buf.String()
}

// KV is a line in the config file that contains a key, a value, and possibly
// a comment.
type KV struct {
	Key   string
	Value string
	// Whitespace after the value but before any comment
	spaceAfterValue string
	Comment         string
	hasEquals       bool
	leadingSpace    int // Space before the key. TODO handle spaces vs tabs.
	position        Position
}

// Pos returns k's Position.
func (k *KV) Pos() Position {
	return k.position
}

// String prints k as it was parsed in the config file.
func (k *KV) String() string {
	if k == nil {
		return ""
	}
	equals := " "
	if k.hasEquals {
		equals = " = "
	}
	line := strings.Repeat(" ", int(k.leadingSpace)) + k.Key + equals + k.Value + k.spaceAfterValue
	if k.Comment != "" {
		line += "#" + k.Comment
	}
	return line
}

// Empty is a line in the config file that contains only whitespace or comments.
type Empty struct {
	Comment      string
	leadingSpace int // TODO handle spaces vs tabs.
	position     Position
}

// Pos returns e's Position.
func (e *Empty) Pos() Position {
	return e.position
}

// String prints e as it was parsed in the config file.
func (e *Empty) String() string {
	if e == nil {
		return ""
	}
	if e.Comment == "" {
		return ""
	}
	return fmt.Sprintf("%s#%s", strings.Repeat(" ", int(e.leadingSpace)), e.Comment)
}

// Include holds the result of an Include directive, including the config files
// that have been parsed as part of that directive. At most 5 levels of Include
// statements will be parsed.
type Include struct {
	// Comment is the contents of any comment at the end of the Include
	// statement.
	Comment string
	// an include directive can include several different files, and wildcards
	directives []string

	// 1:1 mapping between matches and keys in files array; matches preserves
	// ordering
	matches []string
	// actual filenames are listed here
	files        map[string]*Config
	leadingSpace int
	position     Position
	depth        uint8
	hasEquals    bool
}

const maxRecurseDepth = 5

// ErrDepthExceeded is returned if too many Include directives are parsed.
// Usually this indicates a recursive loop (an Include directive pointing to the
// file it contains).
var ErrDepthExceeded = errors.New("ssh_config: max recurse depth exceeded")

func removeDups(arr []string) []string {
	// Use map to record duplicates as we find them.
	encountered := make(map[string]bool, len(arr))
	result := make([]string, 0)

	for v := range arr {
		//lint:ignore S1002 I prefer it this way
		if encountered[arr[v]] == false {
			encountered[arr[v]] = true
			result = append(result, arr[v])
		}
	}
	return result
}

// NewInclude creates a new Include with a list of file globs to include.
// Configuration files are parsed greedily (e.g. as soon as this function runs).
// Any error encountered while parsing nested configuration files will be
// returned.
func NewInclude(directives []string, hasEquals bool, pos Position, comment string, system bool, depth uint8) (*Include, error) {
	if depth > maxRecurseDepth {
		return nil, ErrDepthExceeded
	}
	inc := &Include{
		Comment:      comment,
		directives:   directives,
		files:        make(map[string]*Config),
		position:     pos,
		leadingSpace: pos.Col - 1,
		depth:        depth,
		hasEquals:    hasEquals,
	}
	matches := make([]string, 0)
	for i := range directives {
		var path string
		if filepath.IsAbs(directives[i]) {
			path = directives[i]
		} else if system {
			path = filepath.Join("/etc/ssh", directives[i])
		} else {
			path = filepath.Join(homedir(), ".ssh", directives[i])
		}
		theseMatches, err := filepath.Glob(path)
		if err != nil {
			return nil, err
		}
		matches = append(matches, theseMatches...)
	}
	matches = removeDups(matches)
	inc.matches = matches
	for i := range matches {
		config, err := parseWithDepth(matches[i], depth)
		if err != nil {
			return nil, err
		}
		inc.files[matches[i]] = config
	}
	return inc, nil
}

// Pos returns the position of the Include directive in the larger file.
func (i *Include) Pos() Position {
	return i.position
}

// String prints out a string representation of this Include directive. Note
// included Config files are not printed as part of this representation.
func (inc *Include) String() string {
	equals := " "
	if inc.hasEquals {
		equals = " = "
	}
	line := fmt.Sprintf("%sInclude%s%s", strings.Repeat(" ", int(inc.leadingSpace)), equals, strings.Join(inc.directives, " "))
	if inc.Comment != "" {
		line += " #" + inc.Comment
	}
	return line
}

var matchAll *Pattern

func init() {
	var err error
	matchAll, err = NewPattern("*")
	if err != nil {
		panic(err)
	}
}

func newConfig() *Config {
	implicitHost := &Host{
		implicit: true,
		Patterns: []*Pattern{matchAll},
		Nodes:    make([]Node, 0),
		position: Position{1, 1},
	}
	return &Config{
		Hosts:  []*Host{implicitHost},
		Blocks: []Block{implicitHost},
		depth:  0,
	}
}
