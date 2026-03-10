// Package binutil provides helpers for locating companion binaries.
package binutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Find looks for a binary in PATH, then in the current directory,
// then next to the running executable itself.
// On Linux, exec.LookPath does NOT check the current directory, so users placing
// dnstt-client next to the scanner get "not found". This fixes that.
func Find(name string) (string, error) {
	// Check PATH first
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	local := name
	if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
		local = name + ".exe"
	}

	// Check current directory
	if abs, err := filepath.Abs(local); err == nil {
		if info, err := os.Stat(abs); err == nil {
			if isExecutable(info) {
				return abs, nil
			}
		}
	}

	// Check directory where the running executable is located
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), local)
		if info, err := os.Stat(candidate); err == nil {
			if isExecutable(info) {
				return candidate, nil
			}
		}
	}

	hint := ""
	switch name {
	case "dnstt-client":
		hint = "\n\nDownload pre-built binary from findns releases:\n  https://github.com/SamNet-dev/findns/releases/latest\n\nOr install with Go:\n  go install www.bamsoftware.com/git/dnstt.git/dnstt-client@latest"
	case "slipstream-client":
		hint = "\n\nDownload from: https://github.com/Mygod/slipstream-rust/releases"
	}

	return "", fmt.Errorf("%s not found in PATH, current directory, or next to findns.%s\n\nIf already downloaded, either:\n  1. Place it next to the findns executable\n  2. Move it to a folder in PATH:  sudo mv %s /usr/local/bin/\n  3. Or add current directory to PATH:  export PATH=$PATH:$(pwd)", name, hint, name)
}
