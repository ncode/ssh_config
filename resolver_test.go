package ssh_config

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestResolvePrecedenceSingleValue(t *testing.T) {
	input := "Host *\n  Port 2222\nHost foo\n  Port 2200\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{HostArg: "foo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("Port"); got != "2222" {
		t.Fatalf("Port got %q, want 2222", got)
	}
}

func TestResolveMultiValueAccumulation(t *testing.T) {
	input := "Host *\n  IdentityFile file1\nHost foo\n  IdentityFile file2\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{HostArg: "foo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	vals := res.GetAll("IdentityFile")
	if len(vals) != 2 || vals[0] != "file1" || vals[1] != "file2" {
		t.Fatalf("IdentityFile got %v, want [file1 file2]", vals)
	}
}

func TestResolveMatchNegation(t *testing.T) {
	input := "Match host=*.prod.example.com\n  User prod\nMatch !host=*.prod.example.com\n  User dev\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{HostArg: "db.dev.example.com"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "dev" {
		t.Fatalf("User got %q, want dev", got)
	}
}

func TestResolveMatchExecStrictMissingCallback(t *testing.T) {
	input := "Match exec echo\n  User test\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	_, err = cfg.Resolve(Context{HostArg: "example.com"}, Strict())
	if err == nil {
		t.Fatal("expected error for Match exec without Exec callback")
	}
}

func TestResolveCanonicalAndFinalPass(t *testing.T) {
	input := "Match canonical\n  User canon\nMatch final\n  User final\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{HostArg: "example.com"}, Canonicalize(func(host string) (string, bool, error) {
		return host, true, nil
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "canon" {
		t.Fatalf("User got %q, want canon", got)
	}

	res, err = cfg.Resolve(Context{HostArg: "example.com"}, Canonicalize(func(host string) (string, bool, error) {
		return host, true, nil
	}), FinalPass())
	if err != nil {
		t.Fatalf("Resolve final: %v", err)
	}
	if got := res.Get("User"); got != "final" {
		t.Fatalf("User got %q, want final", got)
	}
}

func TestResolveStrictValidation(t *testing.T) {
	input := "Host *\n  Compression maybe\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	_, err = cfg.Resolve(Context{HostArg: "example.com"}, Strict())
	if err == nil {
		t.Fatal("expected strict validation error")
	}
}

func TestResolveStrictUintValidation(t *testing.T) {
	input := "Host *\n  Port nope\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	_, err = cfg.Resolve(Context{HostArg: "example.com"}, Strict())
	if err == nil {
		t.Fatal("expected unsigned integer validation error")
	}
	if !strings.Contains(err.Error(), "unsigned integer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveDeprecatedAliasDirective(t *testing.T) {
	input := "Host *\n  PubkeyAcceptedKeyTypes ssh-ed25519\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{HostArg: "example.com"}, Strict())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("PubkeyAcceptedAlgorithms"); got != "ssh-ed25519" {
		t.Fatalf("PubkeyAcceptedAlgorithms got %q, want ssh-ed25519", got)
	}

	input = "Host *\n  Cipher 3des\n"
	cfg, err = Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	_, err = cfg.Resolve(Context{HostArg: "example.com"}, Strict())
	if err == nil {
		t.Fatal("expected error for deprecated directive without alias")
	}
}

func TestResolveContextDefaults(t *testing.T) {
	user := currentUserName()
	if user == "" || strings.ContainsAny(user, " \t") {
		t.Skip("no usable local user for test")
	}
	spec, err := loadClientSpec()
	if err != nil {
		t.Fatalf("loadClientSpec: %v", err)
	}
	version := spec.OpenSSHVersion
	if version == "" || strings.ContainsAny(version, " \t") {
		t.Skip("no usable version for test")
	}
	host := "example.com"
	input := fmt.Sprintf("Match originalhost=%s localuser=%s version=%s sessiontype=shell\n  User frommatch\n", host, user, version)
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{HostArg: host})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "frommatch" {
		t.Fatalf("User got %q, want frommatch", got)
	}
}

func TestResolveIgnoreUnknownStrict(t *testing.T) {
	input := "Host *\n  BadDirective foo\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if _, err := cfg.Resolve(Context{HostArg: "example.com"}, Strict()); err == nil {
		t.Fatal("expected error for unknown directive in strict mode")
	}

	input = "Host *\n  IgnoreUnknown foo*\n  FooBar baz\n  User ok\n"
	cfg, err = Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{HostArg: "example.com"}, Strict())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "ok" {
		t.Fatalf("User got %q, want ok", got)
	}
}

func TestResolveDefaultsFromSpec(t *testing.T) {
	spec, err := loadClientSpec()
	if err != nil {
		t.Fatalf("loadClientSpec: %v", err)
	}
	input := "Host *\n  User ok\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{HostArg: "example.com"}, Strict())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d := spec.byName["port"]; d != nil {
		if def := d.defaultValues(); len(def) > 0 {
			if got := res.Get("Port"); got != def[0] {
				t.Fatalf("Port got %q, want %q", got, def[0])
			}
		}
	}
	if d := spec.byName["identityfile"]; d != nil {
		if def := d.defaultValues(); len(def) > 0 {
			got := res.GetAll("IdentityFile")
			if len(got) != len(def) {
				t.Fatalf("IdentityFile got %v, want %v", got, def)
			}
			for i := range def {
				if got[i] != def[i] {
					t.Fatalf("IdentityFile[%d] got %q, want %q", i, got[i], def[i])
				}
			}
		}
	}
}

func TestResolveMatchExecTokenExpansion(t *testing.T) {
	var gotCmd string
	input := "Match exec echo-%h\n  User match\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{
		HostArg: "db.example.com",
		Exec: func(cmd string) (bool, error) {
			gotCmd = cmd
			return true, nil
		},
	}, Strict())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "match" {
		t.Fatalf("User got %q, want match", got)
	}
	if gotCmd != "echo-db.example.com" {
		t.Fatalf("Exec cmd got %q, want %q", gotCmd, "echo-db.example.com")
	}
}

func TestResolveMatchExecQuotedCommand(t *testing.T) {
	var gotCmd string
	input := "Match exec \"echo %h\"\n  User match\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{
		HostArg: "db.example.com",
		Exec: func(cmd string) (bool, error) {
			gotCmd = cmd
			return true, nil
		},
	}, Strict())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "match" {
		t.Fatalf("User got %q, want match", got)
	}
	if gotCmd != "echo db.example.com" {
		t.Fatalf("Exec cmd got %q, want %q", gotCmd, "echo db.example.com")
	}
}

func TestResolveMatchExecEscapedSpaceCommand(t *testing.T) {
	var gotCmd string
	input := "Match host=*.example.com exec echo\\ %h\n  User match\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	res, err := cfg.Resolve(Context{
		HostArg: "db.example.com",
		Exec: func(cmd string) (bool, error) {
			gotCmd = cmd
			return true, nil
		},
	}, Strict())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Get("User"); got != "match" {
		t.Fatalf("User got %q, want match", got)
	}
	if gotCmd != "echo db.example.com" {
		t.Fatalf("Exec cmd got %q, want %q", gotCmd, "echo db.example.com")
	}
}
