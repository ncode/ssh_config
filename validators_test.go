package ssh_config

import "testing"

func TestDefault(t *testing.T) {
	if v := Default("Port"); v != "22" {
		t.Errorf("Default(%q): got %v, want '22'", "Port", v)
	}
	if v := Default("Cipher"); v != "" {
		t.Errorf("Default(%q): got %v, want ''", "Cipher", v)
	}
	if v := Default("notfound"); v != "" {
		t.Errorf("Default(%q): got %v, want ''", "notfound", v)
	}
}

func TestSupportsMultiple(t *testing.T) {
	if !SupportsMultiple("IdentityFile") {
		t.Errorf("SupportsMultiple(%q): got false, want true", "IdentityFile")
	}
	if !SupportsMultiple("IdentityFile2") {
		t.Errorf("SupportsMultiple(%q): got false, want true", "IdentityFile2")
	}
	if SupportsMultiple("Cipher") {
		t.Errorf("SupportsMultiple(%q): got true, want false", "Cipher")
	}
	if SupportsMultiple("notfound") {
		t.Errorf("SupportsMultiple(%q): got true, want false", "notfound")
	}
}
