package specgen

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var requiredSpecgenSourceFiles = []string{
	"readconf.c",
	"ssh_config.5",
	"pathnames.h",
	"myproposal.h",
	"version.h",
	"ssh.h",
}

func requireOpenSSHSources(t *testing.T, root string, requiredFiles ...string) string {
	t.Helper()
	opensshDir := filepath.Join(root, "openssh-portable")
	missing := make([]string, 0)
	for _, rel := range requiredFiles {
		path := filepath.Join(opensshDir, rel)
		_, err := os.Stat(path)
		if err == nil {
			continue
		}
		if os.IsNotExist(err) {
			missing = append(missing, rel)
			continue
		}
		t.Fatalf("stat %s: %v", path, err)
	}
	if len(missing) > 0 {
		t.Skipf("OpenSSH sources missing (%s). Provision openssh-portable/ at repo root, then rerun: go test ./internal/specgen", strings.Join(missing, ", "))
	}
	return opensshDir
}

func TestSpecDeterministic(t *testing.T) {
	root := repoRoot(t)
	opensshDir := requireOpenSSHSources(t, root, requiredSpecgenSourceFiles...)
	one, err := GenerateBytes(opensshDir)
	if err != nil {
		t.Fatalf("GenerateBytes: %v", err)
	}
	two, err := GenerateBytes(opensshDir)
	if err != nil {
		t.Fatalf("GenerateBytes: %v", err)
	}
	if !bytes.Equal(one, two) {
		t.Fatal("spec generator output is not deterministic")
	}
}

func TestSpecMatchesFixture(t *testing.T) {
	root := repoRoot(t)
	opensshDir := requireOpenSSHSources(t, root, requiredSpecgenSourceFiles...)
	got, err := GenerateBytes(opensshDir)
	if err != nil {
		t.Fatalf("GenerateBytes: %v", err)
	}
	fixturePath := filepath.Join(root, "testdata", "openssh_client_spec.json")
	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatalf("spec fixture is out of date; regenerate via cmd/openssh-specgen")
	}
}

func TestSpecKeywordSet(t *testing.T) {
	root := repoRoot(t)
	opensshDir := requireOpenSSHSources(t, root, "readconf.c")
	readconfPath := filepath.Join(opensshDir, "readconf.c")
	data, err := os.ReadFile(readconfPath)
	if err != nil {
		t.Fatalf("read readconf.c: %v", err)
	}
	keywords, err := parseKeywords(string(data))
	if err != nil {
		t.Fatalf("parseKeywords: %v", err)
	}
	fixturePath := filepath.Join(root, "testdata", "openssh_client_spec.json")
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var spec Spec
	if err := json.Unmarshal(fixture, &spec); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	want := make(map[string]bool, len(keywords))
	for _, kw := range keywords {
		want[kw.Name] = true
	}
	got := make(map[string]bool, len(spec.Directives))
	for _, d := range spec.Directives {
		got[d.Name] = true
	}
	for name := range want {
		if !got[name] {
			t.Fatalf("spec missing keyword %q", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Fatalf("spec includes unexpected keyword %q", name)
		}
	}
}

func repoRoot(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
