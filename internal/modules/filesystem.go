package modules

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
	"github.com/winharvest/winharvest/internal/parsers/mft"
)

// filesystemModule collects NTFS filesystem metadata: $MFT, $LogFile (raw),
// $UsnJrnl (via fsutil), the Recycle Bin, Alternate Data Streams, and Volume
// Shadow Copy metadata.
type filesystemModule struct{}

func (filesystemModule) Name() string        { return "filesystem" }
func (filesystemModule) Category() string    { return "FileSystem" }
func (filesystemModule) Description() string { return "$MFT, $LogFile, $UsnJrnl, Recycle Bin, ADS, VSS metadata" }

func (m filesystemModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	drive := collect.SystemDrive(cc.OS) // "C:"
	driveLetter := drive[:1]

	// 1) Raw NTFS metafiles ($MFT, $LogFile) — platform specific extraction.
	extractRawMetafiles(ctx, h, driveLetter)

	// 2) $UsnJrnl change journal export via fsutil (read-only query).
	h.RunToFile(ctx, "usnjrnl_queryjournal.txt", 60*time.Second, "fsutil", "usn", "queryjournal", drive)
	h.RunToFile(ctx, "usnjrnl_readjournal.csv", 5*time.Minute, "fsutil", "usn", "readjournal", drive, "csv")

	// 3) Recycle Bin (deleted file metadata: $I records + $R payloads).
	recycle := drive + `\$Recycle.Bin`
	n := h.CopyTree(recycle, nil)
	h.Note("collected %d Recycle Bin entries", n)

	// 4) Alternate Data Streams enumeration over high-risk directories.
	h.PowerShellToFile(ctx, "alternate_data_streams.txt", 4*time.Minute, adsScript(drive))

	// 5) Reparse points / junctions / hardlinks enumeration.
	h.RunToFile(ctx, "reparse_points.txt", 3*time.Minute, "cmd", "/c",
		`dir /a:l /s `+drive+`\ 2>nul`)

	// 6) Volume Shadow Copy metadata.
	h.RunToFile(ctx, "vss_list.txt", 60*time.Second, "vssadmin", "list", "shadows")
	h.RunToFile(ctx, "vss_storage.txt", 60*time.Second, "vssadmin", "list", "shadowstorage")

	// 7) Parse the extracted $MFT into a readable CSV bodyfile.
	m.parseMFT(h)

	return h.Result(), nil
}

// parseMFT streams the extracted $MFT into a readable CSV (one row per file
// record with $SI / $FN MAC timestamps). Written directly to avoid holding a
// multi-hundred-MB $MFT in memory.
func (m filesystemModule) parseMFT(h *collect.Helper) {
	dir, err := h.ModuleDir()
	if err != nil {
		return
	}
	mftPath := filepath.Join(dir, "$MFT")
	if !collect.Exists(mftPath) {
		return
	}
	outDir := filepath.Join(dir, "parsed")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		h.Errf("mkdir parsed: %v", err)
		return
	}
	out, err := os.Create(filepath.Join(outDir, "mft.csv"))
	if err != nil {
		h.Errf("create mft.csv: %v", err)
		return
	}
	defer out.Close()
	w := csv.NewWriter(out)
	defer w.Flush()
	_ = w.Write([]string{
		"record", "in_use", "is_dir", "name", "parent_ref", "size",
		"si_created", "si_modified", "si_accessed", "si_mft_changed",
		"fn_created", "fn_modified",
	})
	count := 0
	_ = mft.ParseFile(mftPath, func(r mft.Record) {
		_ = w.Write([]string{
			itoa(int(r.RecordNumber)), b2s(r.InUse), b2s(r.IsDir), r.Name,
			itoa(int(r.ParentRef)), itoa(int(r.Size)),
			tfmt(r.SICreated), tfmt(r.SIModified), tfmt(r.SIAccessed), tfmt(r.SIChanged),
			tfmt(r.FNCreated), tfmt(r.FNModified),
		})
		count++
	})
	h.Note("parsed $MFT -> %d records in parsed/mft.csv", count)
}

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func tfmt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// adsScript lists files carrying alternate data streams under common abuse
// locations (Downloads, Temp, user profiles). Zone.Identifier is included as it
// is forensically meaningful (mark-of-the-web).
func adsScript(drive string) string {
	return `$roots = @('` + drive + `\Users','` + drive + `\ProgramData','` + drive + `\Windows\Temp')
foreach($r in $roots){
  if(Test-Path $r){
    Get-ChildItem -Path $r -Recurse -File -Force -ErrorAction SilentlyContinue |
      ForEach-Object {
        $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
          Where-Object { $_.Stream -ne ':$DATA' }
        foreach($s in $streams){ "{0} :: {1} ({2} bytes)" -f $_.FullName, $s.Stream, $s.Length }
      }
  }
}`
}

func recyclePath(drive string) string { return filepath.Join(drive+`\`, "$Recycle.Bin") }

func init() { core.Register(filesystemModule{}) }
