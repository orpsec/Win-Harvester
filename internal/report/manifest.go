// Package report builds the run manifest and renders it as JSON, CSV, HTML and
// Markdown, then optionally packages the whole collection into a ZIP archive.
package report

import (
	"time"

	"github.com/winharvest/winharvest/internal/core"
)

// Manifest is the complete, self-describing record of a collection run.
type Manifest struct {
	Tool          string              `json:"tool"`
	Version       string              `json:"version"`
	CaseName      string              `json:"case_name,omitempty"`
	Examiner      string              `json:"examiner,omitempty"`
	Hostname      string              `json:"hostname"`
	StartedAt     time.Time           `json:"started_at"`
	EndedAt       time.Time           `json:"ended_at"`
	Elevated      bool                `json:"elevated"`
	VSSUsed       bool                `json:"vss_used"`
	OS            *core.OSInfo        `json:"os"`
	Config        *core.Config        `json:"config"`
	Modules       []*core.ModuleResult `json:"modules"`
	Artifacts     []core.ArtifactMeta `json:"artifacts"`
	Timeline      []core.TimelineEvent `json:"timeline"`
	TotalFiles    int                 `json:"total_files"`
	TotalBytes    int64               `json:"total_bytes"`
	FailedFiles   int                 `json:"failed_files"`
	TotalErrors   int                 `json:"total_errors"`
}

// Summarize fills the aggregate counters from the collected data.
func (m *Manifest) Summarize() {
	var bytes int64
	failed := 0
	for _, a := range m.Artifacts {
		if a.Success {
			bytes += a.Size
		} else {
			failed++
		}
	}
	m.TotalFiles = len(m.Artifacts)
	m.TotalBytes = bytes
	m.FailedFiles = failed
	errs := 0
	for _, mod := range m.Modules {
		errs += len(mod.Errors)
	}
	m.TotalErrors = errs
}

// Duration returns the wall-clock duration of the run.
func (m *Manifest) Duration() time.Duration { return m.EndedAt.Sub(m.StartedAt) }
