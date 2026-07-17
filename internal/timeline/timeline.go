// Package timeline builds a unified, sorted super-timeline from collected
// artifact metadata and module-contributed events.
package timeline

import (
	"sort"

	"github.com/winharvest/winharvest/internal/core"
)

// Build merges file MAC times from artifact metadata with the events modules
// pushed to the shared sink, then returns them sorted chronologically.
//
// Each successfully collected file contributes up to three filesystem events
// (Modified / Created / Accessed) so the analyst gets a baseline timeline even
// before deep-parsing $MFT, EVTX, etc. with downstream tooling.
func Build(artifacts []core.ArtifactMeta, sink *core.TimelineSink) []core.TimelineEvent {
	var events []core.TimelineEvent

	for _, a := range artifacts {
		if !a.Success {
			continue
		}
		if !a.ModifiedTime.IsZero() {
			events = append(events, core.TimelineEvent{
				Timestamp:   a.ModifiedTime.UTC(),
				Source:      "FileSystem",
				EventType:   "FileModified",
				Module:      a.Module,
				Description: a.OriginalPath,
				Details:     "M (last write)",
			})
		}
		if !a.CreatedTime.IsZero() {
			events = append(events, core.TimelineEvent{
				Timestamp:   a.CreatedTime.UTC(),
				Source:      "FileSystem",
				EventType:   "FileCreated",
				Module:      a.Module,
				Description: a.OriginalPath,
				Details:     "B (birth)",
			})
		}
		if !a.AccessedTime.IsZero() {
			events = append(events, core.TimelineEvent{
				Timestamp:   a.AccessedTime.UTC(),
				Source:      "FileSystem",
				EventType:   "FileAccessed",
				Module:      a.Module,
				Description: a.OriginalPath,
				Details:     "A (last access)",
			})
		}
	}

	if sink != nil {
		events = append(events, sink.Events()...)
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	return events
}
