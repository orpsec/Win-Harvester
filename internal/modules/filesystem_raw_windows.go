//go:build windows

package modules

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
	"github.com/winharvest/winharvest/internal/hashing"
	"github.com/winharvest/winharvest/internal/rawio"
)

// extractRawMetafiles uses raw NTFS reads to reconstruct $MFT (record 0) and
// $LogFile (record 2), which cannot be opened through the normal filesystem.
func extractRawMetafiles(_ context.Context, h *collect.Helper, driveLetter string) {
	vol, err := rawio.OpenVolume(driveLetter)
	if err != nil {
		h.Errf("raw NTFS open failed (need admin): %v", err)
		return
	}
	defer vol.Close()

	targets := []struct {
		rec  uint64
		name string
	}{
		{0, "$MFT"},
		{2, "$LogFile"},
	}
	for _, t := range targets {
		dir, derr := h.Ctx().Writer.ModuleDir("FileSystem", "filesystem")
		if derr != nil {
			h.Errf("module dir: %v", derr)
			return
		}
		dest := filepath.Join(dir, t.name)
		out, ferr := os.Create(dest)
		if ferr != nil {
			h.Errf("create %s: %v", t.name, ferr)
			continue
		}
		n, eerr := vol.ExtractMetafile(t.rec, out)
		out.Close()
		if eerr != nil {
			h.Errf("extract %s: %v (wrote %d bytes)", t.name, eerr, n)
			continue
		}
		// Hash the reconstructed metafile and record metadata.
		hashes, _ := hashing.HashFile(dest)
		meta := core.ArtifactMeta{
			Module:       "filesystem",
			OriginalPath: driveLetter + `:\` + t.name,
			StoredPath:   dest,
			Size:         n,
			CollectedAt:  time.Now().UTC(),
			Source:       "rawio",
			Hashes:       hashes,
			Success:      true,
		}
		h.Result().Artifacts = append(h.Result().Artifacts, meta)
		h.Note("raw-extracted %s (%d bytes) sha256=%s", t.name, n, hashes.SHA256)
	}
}
