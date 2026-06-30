//go:build !windows

package platform

import (
	"os"
	"runtime"

	"github.com/winharvest/winharvest/internal/core"
)

// DetectOS on non-Windows returns a placeholder so development and tests run.
func DetectOS() (*core.OSInfo, error) {
	host, _ := os.Hostname()
	return &core.OSInfo{
		ProductName:  "Non-Windows (dev stub)",
		BuildNumber:  "0",
		Architecture: runtime.GOARCH,
		SystemRoot:   `C:\Windows`,
		SystemDrive:  "C:",
		Hostname:     host,
	}, nil
}
