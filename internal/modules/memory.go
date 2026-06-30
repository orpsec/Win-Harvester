package modules

import (
	"context"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// memoryModule captures volatile state metadata (no full RAM dump): processes,
// threads, DLLs, handles, drivers, sessions, environment and connections.
type memoryModule struct{}

func (memoryModule) Name() string        { return "memory" }
func (memoryModule) Category() string    { return "Memory" }
func (memoryModule) Description() string { return "Process/thread/DLL/handle/driver/session volatile metadata" }

func (m memoryModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	t := 90 * time.Second

	// Process list with command lines, parent PID, owner, path & hashes.
	h.PowerShellToFile(ctx, "processes.txt", t, processScript)
	h.RunToFile(ctx, "tasklist_v.csv", t, "tasklist", "/v", "/fo", "csv")
	h.RunToFile(ctx, "tasklist_svc.csv", t, "tasklist", "/svc", "/fo", "csv")

	// Loaded DLLs / modules per process.
	h.RunToFile(ctx, "loaded_modules.csv", t, "tasklist", "/m", "/fo", "csv")

	// Drivers currently loaded in the kernel.
	h.RunToFile(ctx, "loaded_drivers.csv", t, "driverquery", "/v", "/fo", "csv")

	// Handles overview (object counts) via PowerShell.
	h.PowerShellToFile(ctx, "process_handles.txt", t,
		`Get-Process | Select Name,Id,Handles,@{n='Threads';e={$_.Threads.Count}},WS,CPU,Path | Sort Handles -Descending | Format-Table -Auto`)

	// Logon sessions and currently logged-on users.
	h.RunToFile(ctx, "logon_sessions.txt", t, "query", "user")
	h.RunToFile(ctx, "logon_sessions_quser.txt", t, "quser")
	h.PowerShellToFile(ctx, "logon_sessions_wmi.txt", t,
		`Get-CimInstance Win32_LogonSession | Format-List *; Get-CimInstance Win32_LoggedOnUser | Format-List *`)

	// Open network connections (volatile, correlate to processes).
	h.PowerShellToFile(ctx, "connections.txt", t,
		`Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -Auto`)

	// Environment variables (machine + current process).
	h.PowerShellToFile(ctx, "environment.txt", t,
		`"=== Machine ==="; [Environment]::GetEnvironmentVariables('Machine') | Format-Table -Auto; `+
			`"=== User ==="; [Environment]::GetEnvironmentVariables('User') | Format-Table -Auto`)

	h.Note("volatile metadata captured (no full RAM image — use a dedicated imager if needed)")
	return h.Result(), nil
}

const processScript = `
Get-CimInstance Win32_Process | ForEach-Object {
  $owner = try { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue) } catch { $null }
  [PSCustomObject]@{
    Name=$_.Name; PID=$_.ProcessId; PPID=$_.ParentProcessId
    Path=$_.ExecutablePath; CmdLine=$_.CommandLine
    Owner= if($owner){ "$($owner.Domain)\$($owner.User)" } else { "" }
    Created=$_.CreationDate
  }
} | Format-List
`

func init() { core.Register(memoryModule{}) }
