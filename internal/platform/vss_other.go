//go:build !windows

package platform

import (
	"context"
	"os"

	"github.com/winharvest/winharvest/internal/core"
)

// VSS stub for non-Windows builds: always passes paths through.
type VSS struct{ log core.Logger }

func NewVSS(_ context.Context, log core.Logger, _ string, _ bool) *VSS { return &VSS{log: log} }

func (v *VSS) Available() bool { return false }

func (v *VSS) Resolve(livePath string) (string, bool, error) {
	_, err := os.Stat(livePath)
	return livePath, false, err
}

func (v *VSS) Cleanup(context.Context) {}

var _ core.VSSResolver = (*VSS)(nil)
