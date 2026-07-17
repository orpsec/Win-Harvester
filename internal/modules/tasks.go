package modules

import (
	"context"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// tasksModule collects Scheduled Tasks: XML definitions, the TaskCache registry
// (collected as raw via SYSTEM hive elsewhere; exported here), and live listing.
type tasksModule struct{}

func (tasksModule) Name() string        { return "tasks" }
func (tasksModule) Category() string    { return "Tasks" }
func (tasksModule) Description() string { return "Scheduled Tasks XML, TaskCache, task listing/history" }

func (m tasksModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	sys32 := collect.Win32(cc.OS)

	// 1) On-disk task XML definitions.
	n := h.CopyTree(filepath.Join(sys32, "Tasks"), nil)
	h.Note("collected %d scheduled task XML files", n)

	// 2) TaskCache registry tree (Tree/Tasks GUID mapping, hidden tasks).
	h.RunToFile(ctx, "taskcache_tree.txt", 60*time.Second, "reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`, "/s")
	h.RunToFile(ctx, "taskcache_tasks.txt", 60*time.Second, "reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`, "/s")

	// 3) Live enumeration (catches in-memory/registered tasks).
	h.RunToFile(ctx, "schtasks_verbose.csv", 90*time.Second, "schtasks", "/query", "/fo", "CSV", "/v")
	h.PowerShellToFile(ctx, "scheduled_tasks.txt", 90*time.Second,
		`Get-ScheduledTask | Get-ScheduledTaskInfo 2>$null | Format-Table -Auto; `+
			`Get-ScheduledTask | Select TaskName,TaskPath,State,@{n='Actions';e={($_.Actions|Out-String)}} | Format-List`)

	return h.Result(), nil
}

func init() { core.Register(tasksModule{}) }
