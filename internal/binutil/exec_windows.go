//go:build windows

package binutil

import "os"

// isExecutable on Windows just checks the file exists (no Unix permission bits).
func isExecutable(info os.FileInfo) bool {
	return !info.IsDir()
}
