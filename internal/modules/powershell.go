package modules

import (
	"context"
	"path/filepath"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// powershellModule collects PowerShell history, transcripts and module/
// scriptblock logging evidence.
type powershellModule struct{}

func (powershellModule) Name() string        { return "powershell" }
func (powershellModule) Category() string    { return "System" }
func (powershellModule) Description() string { return "PSReadLine history, transcripts, console history" }

func (m powershellModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())

	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		// PSReadLine ConsoleHost_history.txt — every interactive command typed.
		psr := filepath.Join(u.ProfilePath, `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`)
		h.CopyGlob(filepath.Join(psr, "*.txt"))

		// User transcript default locations.
		h.CopyTree(filepath.Join(u.ProfilePath, "Documents"), func(n string) bool {
			return len(n) > 14 && n[:14] == "powershell_tra"
		})
	}

	// Machine-wide transcripts (if Transcription policy redirects here).
	h.CopyTree(filepath.Join(collect.SystemDrive(cc.OS)+`\`, "Transcripts"), nil)

	// ScriptBlock & Module logging live in the PowerShell/Operational EVTX,
	// collected raw by the eventlogs module; note the cross-reference.
	h.Note("ScriptBlock (4104) & Module (4103) logs are in %s (see EventLogs)",
		"Microsoft-Windows-PowerShell%4Operational.evtx")

	return h.Result(), nil
}

func init() { core.Register(powershellModule{}) }
