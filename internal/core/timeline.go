package core

import "sync"

// TimelineSink is a concurrency-safe accumulator for timeline events shared by
// all modules during a run.
type TimelineSink struct {
	mu     sync.Mutex
	events []TimelineEvent
}

// NewTimelineSink creates an empty sink.
func NewTimelineSink() *TimelineSink { return &TimelineSink{} }

// Add appends events.
func (s *TimelineSink) Add(events ...TimelineEvent) {
	s.mu.Lock()
	s.events = append(s.events, events...)
	s.mu.Unlock()
}

// Events returns a copy of all accumulated events.
func (s *TimelineSink) Events() []TimelineEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TimelineEvent, len(s.events))
	copy(out, s.events)
	return out
}

// Len reports the number of accumulated events.
func (s *TimelineSink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}
