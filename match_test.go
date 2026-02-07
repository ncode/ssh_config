package ssh_config

import (
	"bytes"
	"strings"
	"testing"
)

func TestMatchParseBlocks(t *testing.T) {
	data := loadFile(t, "testdata/match-directive")
	cfg, err := Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !cfg.hasMatch {
		t.Fatal("expected config to record Match usage")
	}
	if len(cfg.Blocks) < 2 {
		t.Fatalf("expected Blocks to include Match, got %d", len(cfg.Blocks))
	}
	if _, ok := cfg.Blocks[1].(*Match); !ok {
		t.Fatalf("expected second block to be Match, got %T", cfg.Blocks[1])
	}
	expected := string(bytes.ReplaceAll(data, []byte("\t"), []byte(" ")))
	if got := cfg.String(); got != expected {
		t.Errorf("string mismatch:\n%q\nwant:\n%q", got, expected)
	}
}

func TestMatchStringPreservesWhitespace(t *testing.T) {
	input := "Match host=*.example.com   # comment\n\tPort 2222\n"
	cfg, err := Decode(bytes.NewReader([]byte(input)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	expected := strings.ReplaceAll(input, "\t", " ")
	if got := cfg.String(); got != expected {
		t.Errorf("string mismatch:\n%q\nwant:\n%q", got, expected)
	}
}
