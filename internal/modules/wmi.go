package modules

import (
	"context"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// wmiModule collects the WMI repository and enumerates permanent event
// subscriptions (filters, consumers, bindings) — a classic fileless
// persistence mechanism.
type wmiModule struct{}

func (wmiModule) Name() string        { return "wmi" }
func (wmiModule) Category() string    { return "WMI" }
func (wmiModule) Description() string { return "WMI repository + permanent event subscription persistence" }

func (m wmiModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	repo := filepath.Join(collect.Win32(cc.OS), "wbem", "Repository")

	// Raw repository (OBJECTS.DATA, INDEX.BTR, MAPPING*.MAP).
	n := h.CopyTree(repo, nil)
	h.Note("collected %d WMI repository files", n)

	// __EventFilter / *EventConsumer / __FilterToConsumerBinding — persistence.
	h.PowerShellToFile(ctx, "event_filters.txt", 90*time.Second,
		`Get-WmiObject -Namespace root\subscription -Class __EventFilter 2>$null | Format-List *`)
	h.PowerShellToFile(ctx, "event_consumers.txt", 90*time.Second,
		`Get-WmiObject -Namespace root\subscription -Class __EventConsumer 2>$null | Format-List *; `+
			`Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer 2>$null | Format-List *; `+
			`Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer 2>$null | Format-List *`)
	h.PowerShellToFile(ctx, "filter_consumer_bindings.txt", 90*time.Second,
		`Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding 2>$null | Format-List *`)

	return h.Result(), nil
}

func init() { core.Register(wmiModule{}) }
