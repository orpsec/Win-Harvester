// Package collect provides reusable helpers for collector modules: copying
// files (with VSS fallback), running commands to files, globbing and user
// profile enumeration. These keep individual modules small and consistent.
package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/winharvest/winharvest/internal/core"
	"github.com/winharvest/winharvest/internal/platform"
)

// Helper wraps a collection Context with convenience methods bound to a module.
type Helper struct {
	cc       *core.Context
	module   string
	category string
	res      *core.ModuleResult
}

// New creates a Helper and an associated ModuleResult for a module.
func New(cc *core.Context, module, category string) *Helper {
	return &Helper{
		cc:       cc,
		module:   module,
		category: category,
		res: &core.ModuleResult{
			Module:    module,
			StartedAt: time.Now(),
		},
	}
}

// Result returns the accumulated module result.
func (h *Helper) Result() *core.ModuleResult { return h.res }

// Note records a free-form note on the result.
func (h *Helper) Note(format string, args ...any) {
	h.res.Notes = append(h.res.Notes, sprintf(format, args...))
}

// Errf records an error on the result and logs it.
func (h *Helper) Errf(format string, args ...any) {
	msg := sprintf(format, args...)
	h.res.Errors = append(h.res.Errors, msg)
	h.cc.Log.Warnf("[%s] %s", h.module, msg)
}

// CopyFile copies a single file with transparent VSS fallback for locked files.
func (h *Helper) CopyFile(origPath string) (core.ArtifactMeta, bool) {
	resolved, viaShadow, err := h.cc.VSS.Resolve(origPath)
	if err != nil {
		// Record a failed metadata entry so the omission is auditable.
		meta := core.ArtifactMeta{
			Module:       h.module,
			OriginalPath: origPath,
			CollectedAt:  time.Now().UTC(),
			Success:      false,
			Error:        err.Error(),
		}
		h.res.Artifacts = append(h.res.Artifacts, meta)
		h.cc.Log.Debugf("[%s] cannot access %s: %v", h.module, origPath, err)
		return meta, false
	}
	source := "live"
	if viaShadow {
		source = "vss"
	}
	meta, err := h.cc.Writer.CopyFile(h.module, h.category, origPath, resolved, source)
	h.res.Artifacts = append(h.res.Artifacts, meta)
	if err != nil {
		h.cc.Log.Debugf("[%s] copy failed %s: %v", h.module, origPath, err)
		return meta, false
	}
	h.cc.Log.Debugf("[%s] collected %s (%s)", h.module, origPath, source)
	return meta, true
}

// CopyMany copies a list of paths; missing files are silently skipped (debug
// logged) so optional artifacts don't generate noise.
func (h *Helper) CopyMany(paths []string) int {
	n := 0
	for _, p := range paths {
		if _, ok := h.CopyFile(p); ok {
			n++
		}
	}
	return n
}

// CopyGlob expands a glob pattern and copies every match.
func (h *Helper) CopyGlob(pattern string) int {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		h.Errf("glob %s: %v", pattern, err)
		return 0
	}
	return h.CopyMany(matches)
}

// CopyTree recursively copies a directory subtree, optionally filtered by a
// predicate over the (lowercased) filename.
func (h *Helper) CopyTree(root string, keep func(name string) bool) int {
	n := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep walking
		}
		if d.IsDir() {
			return nil
		}
		if keep != nil && !keep(strings.ToLower(d.Name())) {
			return nil
		}
		if _, ok := h.CopyFile(path); ok {
			n++
		}
		return nil
	})
	return n
}

// SaveText writes generated text (command output, parsed data) to a named file.
func (h *Helper) SaveText(name, content string) {
	meta, err := h.cc.Writer.WriteData(h.module, h.category, name, []byte(content))
	h.res.Artifacts = append(h.res.Artifacts, meta)
	if err != nil {
		h.Errf("write %s: %v", name, err)
	}
}

// SaveBytes writes generated binary data to a named file.
func (h *Helper) SaveBytes(name string, data []byte) {
	meta, err := h.cc.Writer.WriteData(h.module, h.category, name, data)
	h.res.Artifacts = append(h.res.Artifacts, meta)
	if err != nil {
		h.Errf("write %s: %v", name, err)
	}
}

// RunToFile runs a command and saves its output (stdout, or stderr if empty) to
// outName. Returns the trimmed combined output for further parsing.
func (h *Helper) RunToFile(ctx context.Context, outName string, timeout time.Duration, name string, args ...string) string {
	res := platform.RunContext(ctx, timeout, name, args...)
	body := res.Combined()
	if res.Err != nil {
		body += "\n\n[command error] " + res.Err.Error()
	}
	h.SaveText(outName, body)
	return strings.TrimSpace(res.Stdout)
}

// PowerShellToFile runs a PowerShell snippet and stores its output.
func (h *Helper) PowerShellToFile(ctx context.Context, outName string, timeout time.Duration, script string) string {
	res := platform.PowerShell(ctx, timeout, script)
	body := res.Combined()
	if res.Err != nil {
		body += "\n\n[powershell error] " + res.Err.Error()
	}
	h.SaveText(outName, body)
	return strings.TrimSpace(res.Stdout)
}

// Timeline adds events to the shared timeline.
func (h *Helper) Timeline(events ...core.TimelineEvent) { h.cc.AddTimeline(events...) }

// OS returns the detected OS info.
func (h *Helper) OS() *core.OSInfo { return h.cc.OS }

// ModuleDir returns (creating if needed) this module's output directory, so a
// module can post-process the raw files it just collected.
func (h *Helper) ModuleDir() (string, error) {
	return h.cc.Writer.ModuleDir(h.category, h.module)
}

// SaveJSON marshals v to indented JSON and stores it under parsed/<name>.
func (h *Helper) SaveJSON(name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		h.Errf("marshal %s: %v", name, err)
		return
	}
	h.SaveText("parsed/"+name, string(b))
}

// WalkCollected invokes fn for every file already collected into this module's
// output directory whose lowercased name passes the optional filter. Used by
// the readable-output parsers that run after raw collection.
func (h *Helper) WalkCollected(filter func(lowerName string) bool, fn func(path string)) {
	dir, err := h.ModuleDir()
	if err != nil {
		return
	}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Skip our own generated parsed/ outputs.
		if strings.Contains(filepath.ToSlash(path), "/parsed/") {
			return nil
		}
		if filter == nil || filter(strings.ToLower(d.Name())) {
			fn(path)
		}
		return nil
	})
}

// Ctx returns the collection context.
func (h *Helper) Ctx() *core.Context { return h.cc }
