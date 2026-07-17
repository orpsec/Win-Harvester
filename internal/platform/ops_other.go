//go:build !windows

package platform

import (
	"os"
	"time"

	"github.com/winharvest/winharvest/internal/core"
)

// PortableOps is the non-Windows stub allowing the project to build and be
// unit-tested on Linux/macOS development hosts.
type PortableOps struct{}

func (PortableOps) FileTimes(info os.FileInfo, _ string) (created, modified, accessed time.Time) {
	return info.ModTime(), info.ModTime(), info.ModTime()
}

func (PortableOps) SetTimes(path string, _ , modified, accessed time.Time) error {
	return os.Chtimes(path, accessed, modified)
}

func (PortableOps) OwnerAndACL(string) (string, string, error) { return "", "", nil }

var _ core.PlatformOps = PortableOps{}

// NewOps returns the platform operations implementation for this build.
func NewOps() core.PlatformOps { return PortableOps{} }

// IsElevated is always false off-Windows.
func IsElevated() bool { return false }
