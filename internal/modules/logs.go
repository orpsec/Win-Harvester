package modules

import (
	"context"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// logsModule collects servicing/setup logs, Defender logs, and crash dump
// metadata (CBS, DISM, Panther, WER, MEMORY.DMP).
type logsModule struct{}

func (logsModule) Name() string        { return "logs" }
func (logsModule) Category() string    { return "System" }
func (logsModule) Description() string { return "CBS/DISM/Panther/Defender logs, crash dump metadata" }

func (m logsModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	win := collect.SystemRoot(cc.OS)
	drive := collect.SystemDrive(cc.OS)
	progData := collect.ProgramData(cc.OS)

	// Servicing logs.
	h.CopyGlob(filepath.Join(win, "Logs", "CBS", "CBS.log"))
	h.CopyGlob(filepath.Join(win, "Logs", "CBS", "*.log"))
	h.CopyGlob(filepath.Join(win, "Logs", "DISM", "*.log"))
	h.CopyFile(filepath.Join(win, "DISM", "dism.log"))

	// Windows Update logs (ETL on Win10/11; render via Get-WindowsUpdateLog).
	h.CopyGlob(filepath.Join(win, "Logs", "WindowsUpdate", "*.etl"))
	h.PowerShellToFile(ctx, "windowsupdate_rendered.txt", 3*time.Minute,
		`$o="$env:TEMP\wulog_winharvest.txt"; Get-WindowsUpdateLog -LogPath $o 2>$null; if(Test-Path $o){Get-Content $o; Remove-Item $o -Force}`)

	// Panther (setup/upgrade) logs.
	h.CopyTree(filepath.Join(win, "Panther"), func(n string) bool {
		return filepath.Ext(n) == ".log" || filepath.Ext(n) == ".xml" || filepath.Ext(n) == ".etl"
	})
	h.CopyTree(filepath.Join(drive+`\`, "$WINDOWS.~BT", "Sources", "Panther"), func(n string) bool {
		return filepath.Ext(n) == ".log"
	})

	// Windows Defender support/operational logs.
	h.CopyTree(filepath.Join(progData, `Microsoft\Windows Defender\Support`), nil)
	h.CopyGlob(filepath.Join(progData, `Microsoft\Windows Defender\Scans\History\Service\DetectionHistory`, "*", "*"))

	// Crash dumps (collect MiniDumps fully; only metadata for huge MEMORY.DMP).
	h.CopyGlob(filepath.Join(win, "Minidump", "*.dmp"))
	m.dumpMetadata(h, filepath.Join(win, "MEMORY.DMP"))
	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		h.CopyGlob(filepath.Join(u.ProfilePath, `AppData\Local\CrashDumps`, "*.dmp"))
	}

	return h.Result(), nil
}

// dumpMetadata records size/timestamps of a large crash dump without copying it.
func (m logsModule) dumpMetadata(h *collect.Helper, path string) {
	if !collect.Exists(path) {
		return
	}
	h.PowerShellToFile(context.Background(), "memory_dmp_metadata.txt", 30*time.Second,
		`$f=Get-Item '`+path+`' -ErrorAction SilentlyContinue; if($f){ $f | Format-List FullName,Length,CreationTime,LastWriteTime,LastAccessTime }`)
	h.Note("MEMORY.DMP present at %s — metadata only (full dump not copied; copy manually if required)", path)
}

func init() { core.Register(logsModule{}) }
