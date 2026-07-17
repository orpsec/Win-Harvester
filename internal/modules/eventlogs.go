package modules

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// eventLogsModule copies the raw EVTX files. Raw collection (not export) keeps
// the original binary format with full fidelity for downstream tools.
type eventLogsModule struct{}

func (eventLogsModule) Name() string        { return "eventlogs" }
func (eventLogsModule) Category() string    { return "EventLogs" }
func (eventLogsModule) Description() string { return "Raw EVTX event log files (winevt\\Logs)" }

func (m eventLogsModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	logsDir := filepath.Join(collect.Win32(cc.OS), "winevt", "Logs")

	// Copy every .evtx (Operational/Analytic/Debug channels are all *.evtx).
	n := h.CopyTree(logsDir, func(name string) bool {
		return filepathExt(name) == ".evtx"
	})
	h.Note("collected %d EVTX files from %s", n, logsDir)

	if n == 0 {
		h.Errf("no EVTX files collected from %s (locked? not elevated?)", logsDir)
	}

	// Readable export: render the highest-value channels to JSON via Get-WinEvent
	// so the events can be analyzed directly without an EVTX parser.
	m.exportReadable(ctx, h)

	return h.Result(), nil
}

// importantChannels are rendered to JSON for immediate analysis. Each is capped
// to keep output sizes reasonable; the raw EVTX retains the full record set.
var importantChannels = []string{
	"Security",
	"System",
	"Application",
	"Microsoft-Windows-Sysmon/Operational",
	"Microsoft-Windows-PowerShell/Operational",
	"Windows PowerShell",
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
	"Microsoft-Windows-WinRM/Operational",
	"Microsoft-Windows-WMI-Activity/Operational",
	"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
	"Microsoft-Windows-Bits-Client/Operational",
	"Microsoft-Windows-DNS-Client/Operational",
	"Microsoft-Windows-AppLocker/EXE and DLL",
	"Microsoft-Windows-CodeIntegrity/Operational",
	"Microsoft-Windows-DriverFrameworks-UserMode/Operational",
}

func (m eventLogsModule) exportReadable(ctx context.Context, h *collect.Helper) {
	const maxEvents = 20000
	exported := 0
	for _, ch := range importantChannels {
		safe := sanitizeChannel(ch)
		// Select the fields most useful for triage; ConvertTo-Json depth keeps
		// nested data. -MaxEvents bounds very large channels like Security.
		// Note: the whole script is passed to powershell.exe -Command, so it must
		// avoid literal double-quotes that would clash with Go/shell quoting. The
		// error branch emits a plain '# ERROR: ...' line instead of JSON to keep
		// the quoting simple and robust (this was a v1.0.0 bug).
		script := `try {
  Get-WinEvent -LogName '` + ch + `' -MaxEvents ` + itoa(maxEvents) + ` -ErrorAction Stop |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, UserId, Message |
    ConvertTo-Json -Depth 4
} catch { Write-Output ('# ERROR: ' + $_.Exception.Message) }`
		out := h.PowerShellToFile(ctx, "parsed/"+safe+".json", 4*time.Minute, script)
		if out != "" && !startsWithErr(out) {
			exported++
		}
	}
	h.Note("rendered %d/%d event channels to parsed/*.json", exported, len(importantChannels))
}

func sanitizeChannel(ch string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", " ", "_")
	return r.Replace(ch)
}

func startsWithErr(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "# ERROR:") {
		return true
	}
	return strings.HasPrefix(s, `{"error"`)
}

func filepathExt(name string) string { return filepath.Ext(name) }

func init() { core.Register(eventLogsModule{}) }
