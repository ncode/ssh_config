package ssh_config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var files = []string{
	"testdata/config1",
	"testdata/config2",
	"testdata/eol-comments",
}

func TestDecode(t *testing.T) {
	for _, filename := range files {
		data := loadFile(t, filename)
		cfg, err := Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		out := cfg.String()
		if out != string(data) {
			t.Errorf("%s out != data: got:\n%s\nwant:\n%s\n", filename, out, string(data))
		}
	}
}

func testConfigFinder(filename string) func() string {
	return func() string { return filename }
}

func nullConfigFinder() string {
	return ""
}

func resolveUserSettings(t *testing.T, us *UserSettings, host string, opts ...ResolveOption) *Result {
	t.Helper()
	res, err := us.Resolve(Context{HostArg: host}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestGet(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	res := resolveUserSettings(t, us, "wap")
	if got := res.Get("User"); got != "root" {
		t.Errorf("expected to find User root, got %q", got)
	}
}

func TestGetWithDefault(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	res := resolveUserSettings(t, us, "wap")
	if got := res.Get("Port"); got != "22" {
		t.Errorf("expected to get Port 22, got %q", got)
	}
}

func TestGetAllWithDefault(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	res := resolveUserSettings(t, us, "wap")
	val := res.GetAll("Port")
	if len(val) != 1 || val[0] != "22" {
		t.Errorf("expected to get Port 22, got %q", val)
	}
}

func TestGetIdentities(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/identities"),
	}

	res := resolveUserSettings(t, us, "hasidentity")
	val := res.GetAll("IdentityFile")
	if len(val) != 1 || val[0] != "file1" {
		t.Errorf(`expected ["file1"], got %v`, val)
	}

	res = resolveUserSettings(t, us, "has2identity")
	val = res.GetAll("IdentityFile")
	if len(val) != 2 || val[0] != "f1" || val[1] != "f2" {
		t.Errorf(`expected [\"f1\", \"f2\"], got %v`, val)
	}

	res = resolveUserSettings(t, us, "randomhost")
	val = res.GetAll("IdentityFile")
	if len(val) != 0 {
		t.Errorf("expected no IdentityFile defaults, got %v", val)
	}

	res = resolveUserSettings(t, us, "protocol1")
	val = res.GetAll("IdentityFile")
	if len(val) != 0 {
		t.Errorf("expected no IdentityFile defaults, got %v", val)
	}
}

func TestGetInvalidPort(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/invalid-port"),
	}

	_, err := us.Resolve(Context{HostArg: "test.test"}, Strict())
	if err == nil {
		t.Fatalf("expected non-nil err, got nil")
	}
	if !strings.Contains(err.Error(), "unsigned integer") {
		t.Errorf("wrong error: got %v", err)
	}
}

func TestGetNotFoundNoDefault(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	res := resolveUserSettings(t, us, "wap")
	if got := res.Get("CanonicalDomains"); got != "" {
		t.Errorf("expected to get CanonicalDomains '', got %q", got)
	}
}

func TestGetAllNotFoundNoDefault(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	res := resolveUserSettings(t, us, "wap")
	val := res.GetAll("CanonicalDomains")
	if len(val) != 0 {
		t.Errorf("expected to get CanonicalDomains '', got %q", val)
	}
}

func TestGetWildcard(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config3"),
	}

	res := resolveUserSettings(t, us, "bastion.stage.i.us.example.net")
	if got := res.Get("Port"); got != "22" {
		t.Errorf("expected to find Port 22, got %q", got)
	}

	res = resolveUserSettings(t, us, "bastion.net")
	if got := res.Get("Port"); got != "25" {
		t.Errorf("expected to find Port 25, got %q", got)
	}

	res = resolveUserSettings(t, us, "10.2.3.4")
	if got := res.Get("Port"); got != "23" {
		t.Errorf("expected to find Port 23, got %q", got)
	}
	res = resolveUserSettings(t, us, "101.2.3.4")
	if got := res.Get("Port"); got != "25" {
		t.Errorf("expected to find Port 25, got %q", got)
	}
	res = resolveUserSettings(t, us, "20.20.20.4")
	if got := res.Get("Port"); got != "24" {
		t.Errorf("expected to find Port 24, got %q", got)
	}
	res = resolveUserSettings(t, us, "20.20.20.20")
	if got := res.Get("Port"); got != "25" {
		t.Errorf("expected to find Port 25, got %q", got)
	}
}

func TestGetExtraSpaces(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/extraspace"),
	}

	res := resolveUserSettings(t, us, "test.test")
	if got := res.Get("Port"); got != "1234" {
		t.Errorf("expected to find Port 1234, got %q", got)
	}
}

func TestGetCaseInsensitive(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config1"),
	}

	res := resolveUserSettings(t, us, "wap")
	if got := res.Get("uSER"); got != "root" {
		t.Errorf("expected to find User root, got %q", got)
	}
}

func TestGetEmpty(t *testing.T) {
	us := &UserSettings{
		userConfigFinder:   nullConfigFinder,
		systemConfigFinder: nullConfigFinder,
	}
	res := resolveUserSettings(t, us, "wap")
	if got := res.Get("HostName"); got != "wap" {
		t.Errorf("expected to get HostName wap, got %q", got)
	}
}

func TestGetEqsign(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/eqsign"),
	}

	res := resolveUserSettings(t, us, "test.test")
	if got := res.Get("Port"); got != "1234" {
		t.Errorf("expected to find Port 1234, got %q", got)
	}
	if got := res.Get("Port2"); got != "" {
		t.Errorf("expected to ignore Port2, got %q", got)
	}
}

var includeFile = []byte(`
# This host should not exist, so we can use it for test purposes / it won't
# interfere with any other configurations.
Host kevinburke.ssh_config.test.example.com
    Port 4567
`)

func TestInclude(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fs write in short mode")
	}
	testPath := filepath.Join(homedir(), ".ssh", "kevinburke-ssh-config-test-file")
	err := os.WriteFile(testPath, includeFile, 0644)
	if err != nil {
		t.Skipf("couldn't write SSH config file: %v", err.Error())
	}
	defer os.Remove(testPath)
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/include"),
	}
	res := resolveUserSettings(t, us, "kevinburke.ssh_config.test.example.com")
	if got := res.Get("Port"); got != "4567" {
		t.Errorf("expected to find Port=4567 in included file, got %q", got)
	}
}

func TestIncludeSystem(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fs write in short mode")
	}
	testPath := filepath.Join("/", "etc", "ssh", "kevinburke-ssh-config-test-file")
	err := os.WriteFile(testPath, includeFile, 0644)
	if err != nil {
		t.Skipf("couldn't write SSH config file: %v", err.Error())
	}
	defer os.Remove(testPath)
	us := &UserSettings{
		systemConfigFinder: testConfigFinder("testdata/include"),
	}
	res := resolveUserSettings(t, us, "kevinburke.ssh_config.test.example.com")
	if got := res.Get("Port"); got != "4567" {
		t.Errorf("expected to find Port=4567 in included file, got %q", got)
	}
}

var recursiveIncludeFile = []byte(`
Host kevinburke.ssh_config.test.example.com
	Include kevinburke-ssh-config-recursive-include
`)

func TestIncludeRecursive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fs write in short mode")
	}
	testPath := filepath.Join(homedir(), ".ssh", "kevinburke-ssh-config-recursive-include")
	err := os.WriteFile(testPath, recursiveIncludeFile, 0644)
	if err != nil {
		t.Skipf("couldn't write SSH config file: %v", err.Error())
	}
	defer os.Remove(testPath)
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/include-recursive"),
	}
	_, err = us.Resolve(Context{HostArg: "kevinburke.ssh_config.test.example.com"})
	if err != ErrDepthExceeded {
		t.Errorf("Recursive include: expected ErrDepthExceeded, got %v", err)
	}
}

func TestIncludeString(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fs write in short mode")
	}
	data, err := os.ReadFile("testdata/include")
	if err != nil {
		log.Fatal(err)
	}
	c, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	s := c.String()
	if s != string(data) {
		t.Errorf("mismatch: got %q\nwant %q", s, string(data))
	}
}

var matchTests = []struct {
	in    []string
	alias string
	want  bool
}{
	{[]string{"*"}, "any.test", true},
	{[]string{"a", "b", "*", "c"}, "any.test", true},
	{[]string{"a", "b", "c"}, "any.test", false},
	{[]string{"any.test"}, "any1test", false},
	{[]string{"192.168.0.?"}, "192.168.0.1", true},
	{[]string{"192.168.0.?"}, "192.168.0.10", false},
	{[]string{"*.co.uk"}, "bbc.co.uk", true},
	{[]string{"*.co.uk"}, "subdomain.bbc.co.uk", true},
	{[]string{"*.*.co.uk"}, "bbc.co.uk", false},
	{[]string{"*.*.co.uk"}, "subdomain.bbc.co.uk", true},
	{[]string{"*.example.com", "!*.dialup.example.com", "foo.dialup.example.com"}, "foo.dialup.example.com", false},
	{[]string{"test.*", "!test.host"}, "test.host", false},
}

func TestMatches(t *testing.T) {
	for _, tt := range matchTests {
		patterns := make([]*Pattern, len(tt.in))
		for i := range tt.in {
			pat, err := NewPattern(tt.in[i])
			if err != nil {
				t.Fatalf("error compiling pattern %s: %v", tt.in[i], err)
			}
			patterns[i] = pat
		}
		host := &Host{
			Patterns: patterns,
		}
		got := host.Matches(tt.alias)
		if got != tt.want {
			t.Errorf("host(%q).Matches(%q): got %v, want %v", tt.in, tt.alias, got, tt.want)
		}
	}
}

func TestIndexInRange(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/config4"),
	}

	res := resolveUserSettings(t, us, "wap")
	if got := res.Get("User"); got != "root" {
		t.Errorf("expected User to be %q, got %q", "root", got)
	}
}

func TestDosLinesEndingsDecode(t *testing.T) {
	us := &UserSettings{
		userConfigFinder: testConfigFinder("testdata/dos-lines"),
	}

	res := resolveUserSettings(t, us, "wap")
	if got := res.Get("User"); got != "root" {
		t.Errorf("expected User to be %q, got %q", "root", got)
	}

	res = resolveUserSettings(t, us, "wap2")
	if got := res.Get("HostName"); got != "8.8.8.8" {
		t.Errorf("expected HostName to be %q, got %q", "8.8.8.8", got)
	}
}

func TestNoTrailingNewline(t *testing.T) {
	us := &UserSettings{
		userConfigFinder:   testConfigFinder("testdata/config-no-ending-newline"),
		systemConfigFinder: nullConfigFinder,
	}

	res := resolveUserSettings(t, us, "example")
	if got := res.Get("Port"); got != "4242" {
		t.Errorf("wrong port: got %q want 4242", got)
	}
}

func TestCustomFinder(t *testing.T) {
	us := &UserSettings{}
	us.ConfigFinder(func() string {
		return "testdata/config1"
	})

	res := resolveUserSettings(t, us, "wap")
	if got := res.Get("User"); got != "root" {
		t.Errorf("expected to find User root, got %q", got)
	}
}

func mustPattern(t *testing.T, raw string) *Pattern {
	t.Helper()
	pat, err := NewPattern(raw)
	if err != nil {
		t.Fatalf("NewPattern(%q): %v", raw, err)
	}
	return pat
}

func TestBlocksMutationAffectsResolveAndString(t *testing.T) {
	cfg, err := Decode(strings.NewReader("Host *\n  Port 22\n"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	host := &Host{
		Patterns: []*Pattern{mustPattern(t, "block.example.com")},
		Nodes: []Node{
			&KV{Key: "User", Value: "block-user", leadingSpace: 2},
		},
	}
	cfg.Blocks = append(cfg.Blocks, host)

	res, err := cfg.Resolve(Context{HostArg: "block.example.com", LocalUser: "local"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "block-user" {
		t.Fatalf("User got %q, want %q", got, "block-user")
	}

	out := cfg.String()
	if !strings.Contains(out, "Host block.example.com\n") {
		t.Fatalf("String() missing appended block host, got:\n%s", out)
	}
	if !strings.Contains(out, "User block-user\n") {
		t.Fatalf("String() missing appended block user, got:\n%s", out)
	}
}

func TestHostsOnlyMutationIgnoredWhenBlocksPresent(t *testing.T) {
	cfg, err := Decode(strings.NewReader("Host *\n  Port 22\n"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	cfg.Hosts = append(cfg.Hosts, &Host{
		Patterns: []*Pattern{mustPattern(t, "hostonly.example.com")},
		Nodes: []Node{
			&KV{Key: "User", Value: "hosts-only", leadingSpace: 2},
		},
	})

	res, err := cfg.Resolve(Context{HostArg: "hostonly.example.com", LocalUser: "local"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got == "hosts-only" {
		t.Fatalf("Hosts-only mutation unexpectedly affected Resolve result: %q", got)
	}

	out := cfg.String()
	if strings.Contains(out, "Host hostonly.example.com\n") {
		t.Fatalf("String() unexpectedly includes Hosts-only mutation:\n%s", out)
	}
}

func TestHostsFallbackWhenBlocksEmpty(t *testing.T) {
	cfg, err := Decode(strings.NewReader("Host *\n  Port 22\n"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	cfg.Blocks = nil
	cfg.Hosts = append(cfg.Hosts, &Host{
		Patterns: []*Pattern{mustPattern(t, "fallback.example.com")},
		Nodes: []Node{
			&KV{Key: "User", Value: "fallback-user", leadingSpace: 2},
		},
	})

	res, err := cfg.Resolve(Context{HostArg: "fallback.example.com", LocalUser: "local"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "fallback-user" {
		t.Fatalf("User got %q, want %q", got, "fallback-user")
	}

	out := cfg.String()
	if !strings.Contains(out, "Host fallback.example.com\n") {
		t.Fatalf("String() missing fallback Hosts mutation, got:\n%s", out)
	}
}
