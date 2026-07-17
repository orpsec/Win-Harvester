package core

import (
	"context"
	"sort"
	"sync"
	"time"
)

// registry is the global plugin registry of collector modules. Modules register
// themselves from their package init() functions, keeping main() decoupled from
// the concrete module list (the plugin pattern).
var (
	regMu    sync.Mutex
	registry = map[string]Collector{}
)

// Register adds a collector to the global registry. Intended to be called from
// init(). Duplicate names overwrite (last wins) but are logged at runtime.
func Register(c Collector) {
	regMu.Lock()
	registry[c.Name()] = c
	regMu.Unlock()
}

// Registered returns all registered collectors sorted by name.
func Registered() []Collector {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]Collector, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Manager runs the enabled collectors with bounded concurrency and aggregates
// their results.
type Manager struct {
	cc  *Context
	log Logger
}

// NewManager constructs a Manager.
func NewManager(cc *Context, log Logger) *Manager { return &Manager{cc: cc, log: log} }

// Run executes all enabled collectors. Each module runs in its own goroutine,
// limited by cfg.Concurrency. A panic in one module never aborts the others.
func (m *Manager) Run(ctx context.Context) []*ModuleResult {
	cfg := m.cc.Config
	all := Registered()
	var enabled []Collector
	for _, c := range all {
		if cfg.ModuleEnabled(c.Name()) {
			enabled = append(enabled, c)
		} else {
			m.log.Debugf("module %q disabled by config", c.Name())
		}
	}

	m.log.Infof("running %d collector module(s) with concurrency %d", len(enabled), cfg.Concurrency)

	sem := make(chan struct{}, cfg.Concurrency)
	results := make([]*ModuleResult, len(enabled))
	var wg sync.WaitGroup

	for i, c := range enabled {
		wg.Add(1)
		go func(idx int, col Collector) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = m.runOne(ctx, col)
		}(i, c)
	}
	wg.Wait()
	return results
}

func (m *Manager) runOne(ctx context.Context, col Collector) (res *ModuleResult) {
	start := time.Now()
	m.log.Infof("[%s] starting (%s)", col.Name(), col.Description())
	defer func() {
		if r := recover(); r != nil {
			m.log.Errorf("[%s] PANIC recovered: %v", col.Name(), r)
			if res == nil {
				res = &ModuleResult{Module: col.Name(), StartedAt: start, EndedAt: time.Now()}
			}
			res.Errors = append(res.Errors, "panic: "+toStr(r))
		}
	}()

	r, err := col.Collect(ctx, m.cc)
	if r == nil {
		r = &ModuleResult{Module: col.Name(), StartedAt: start}
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = start
	}
	r.EndedAt = time.Now()
	if err != nil {
		m.log.Errorf("[%s] failed: %v", col.Name(), err)
		r.Errors = append(r.Errors, err.Error())
	}
	// Fold any timeline events the module exposed into the shared sink.
	if tp, ok := col.(TimelineProvider); ok {
		m.cc.AddTimeline(tp.TimelineEvents()...)
	}
	m.log.Infof("[%s] done in %s — %d artifact(s), %d error(s)",
		col.Name(), r.Duration().Round(time.Millisecond), len(r.Artifacts), len(r.Errors))
	return r
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return "unknown"
}
