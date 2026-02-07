package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ncode/ssh_config/internal/specgen"
)

func main() {
	var outPath string
	var opensshDir string
	flag.StringVar(&opensshDir, "openssh", "openssh-portable", "path to vendored OpenSSH directory")
	flag.StringVar(&outPath, "out", filepath.Join("testdata", "openssh_client_spec.json"), "output path")
	flag.Parse()

	if _, err := os.Stat(opensshDir); os.IsNotExist(err) {
		if err := cloneOpenSSH(opensshDir); err != nil {
			fmt.Fprintf(os.Stderr, "specgen clone: %v\n", err)
			os.Exit(1)
		}
	}

	bytes, err := specgen.GenerateBytes(opensshDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "specgen: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, bytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "specgen write: %v\n", err)
		os.Exit(1)
	}
}

func cloneOpenSSH(dir string) error {
	const repo = "https://github.com/openssh/openssh-portable.git"
	if err := runCommand("git", "clone", "--depth=1", repo, dir); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}
	return nil
}

var runCommand = func(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
