//go:build !windows

package modules

import (
	"context"

	"github.com/winharvest/winharvest/internal/collect"
)

// extractRawMetafiles is a no-op on non-Windows development hosts.
func extractRawMetafiles(_ context.Context, h *collect.Helper, _ string) {
	h.Note("raw NTFS metafile extraction skipped (non-Windows build)")
}
