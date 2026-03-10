//go:build !windows

package binutil

import "os"

// isExecutable checks that the file has at least one execute permission bit set.
func isExecutable(info os.FileInfo) bool {
	return info.Mode()&0111 != 0
}
