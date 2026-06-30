// Package core defines the shared types, interfaces and the collection context
// used across every collector module in WinHarvest.
package core

import (
	"context"
	"sync"
	"time"
)

// FileHashes holds the three hashes computed for every collected file.
type FileHashes struct {
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1"`
	MD5    string `json:"md5"`
}

// ArtifactMeta is the per-file metadata record produced for every collected
// file, satisfying the forensic chain-of-custody requirements.
type ArtifactMeta struct {
	Module       string     `json:"module"`
	OriginalPath string     `json:"original_path"`
	StoredPath   string     `json:"stored_path"` // path inside the Collection output
	Size         int64      `json:"size"`
	CreatedTime  time.Time  `json:"created_time"`
	ModifiedTime time.Time  `json:"modified_time"`
	AccessedTime time.Time  `json:"accessed_time"`
	Owner        string     `json:"owner,omitempty"`
	ACL          string     `json:"acl,omitempty"`
	Hashes       FileHashes `json:"hashes"`
	CollectedAt  time.Time  `json:"collected_at"`
	Source       string     `json:"source"` // "live", "vss", "rawio"
	Success      bool       `json:"success"`
	Error        string     `json:"error,omitempty"`
}

// ModuleResult is the summary returned by a collector after it runs.
type ModuleResult struct {
	Module    string         `json:"module"`
	StartedAt time.Time      `json:"started_at"`
	EndedAt   time.Time      `json:"ended_at"`
	Artifacts []ArtifactMeta `json:"artifacts"`
	Errors    []string       `json:"errors"`
	Notes     []string       `json:"notes"`
}

// Duration is a helper for reports.
func (r ModuleResult) Duration() time.Duration { return r.EndedAt.Sub(r.StartedAt) }

// TimelineEvent is a single normalized entry on the unified super timeline.
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`      // MFT, Registry, EVTX, Prefetch...
	EventType   string    `json:"event_type"`  // Execution, Logon, USBInsert...
	Description string    `json:"description"`
	Details     string    `json:"details,omitempty"`
	Module      string    `json:"module"`
}

// Collector is the interface every artifact module must implement. New modules
// are added simply by implementing this interface and registering them.
type Collector interface {
	// Name is the unique module identifier (also used as the output subfolder).
	Name() string
	// Category groups the module under one of the output top-level folders.
	Category() string
	// Description is a human readable summary shown in reports/logs.
	Description() string
	// Collect performs the collection. It must never modify source evidence.
	Collect(ctx context.Context, cc *Context) (*ModuleResult, error)
}

// TimelineProvider is an optional interface; modules that can contribute
// normalized timeline events implement it.
type TimelineProvider interface {
	TimelineEvents() []TimelineEvent
}

// Context carries everything a collector needs: configuration, OS details,
// output sink, logger and the VSS resolver. It is safe for concurrent use.
type Context struct {
	OutputDir string
	OS        *OSInfo
	Config    *Config
	Log       Logger
	Writer    *OutputWriter
	VSS       VSSResolver
	Timeline  *TimelineSink

	mu     sync.Mutex
	events []TimelineEvent
}

// AddTimeline appends timeline events in a concurrency-safe way.
func (c *Context) AddTimeline(events ...TimelineEvent) {
	if c.Timeline != nil {
		c.Timeline.Add(events...)
		return
	}
	c.mu.Lock()
	c.events = append(c.events, events...)
	c.mu.Unlock()
}

// Logger is the minimal logging surface used by collectors.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// VSSResolver maps a live path to a readable path, transparently routing
// through a Volume Shadow Copy snapshot when the live file is locked.
type VSSResolver interface {
	// Resolve returns a path that can be opened read-only. If the live file is
	// accessible it is returned unchanged; otherwise a shadow-copy path is
	// returned. The bool reports whether a shadow copy was used.
	Resolve(livePath string) (resolved string, viaShadow bool, err error)
	// Available reports whether shadow-copy fallback is usable at all.
	Available() bool
}
