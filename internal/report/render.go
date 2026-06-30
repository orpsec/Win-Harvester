package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/winharvest/winharvest/internal/core"
)

// Write renders the manifest in all requested formats into reportsDir.
func Write(reportsDir string, m *Manifest, formats []string) error {
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return err
	}
	m.Summarize()
	for _, f := range formats {
		var err error
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "json":
			err = writeJSON(reportsDir, m)
		case "csv":
			err = writeCSV(reportsDir, m)
		case "html":
			err = writeHTML(reportsDir, m)
		case "md", "markdown":
			err = writeMarkdown(reportsDir, m)
		}
		if err != nil {
			return fmt.Errorf("render %s: %w", f, err)
		}
	}
	return nil
}

func writeJSON(dir string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644)
}

func writeCSV(dir string, m *Manifest) error {
	// artifacts.csv — one row per collected file (chain of custody).
	af, err := os.Create(filepath.Join(dir, "artifacts.csv"))
	if err != nil {
		return err
	}
	defer af.Close()
	w := csv.NewWriter(af)
	_ = w.Write([]string{
		"module", "original_path", "stored_path", "size", "source",
		"created", "modified", "accessed", "owner",
		"sha256", "sha1", "md5", "collected_at", "success", "error",
	})
	for _, a := range m.Artifacts {
		_ = w.Write([]string{
			a.Module, a.OriginalPath, a.StoredPath, strconv.FormatInt(a.Size, 10), a.Source,
			tf(a.CreatedTime), tf(a.ModifiedTime), tf(a.AccessedTime), a.Owner,
			a.Hashes.SHA256, a.Hashes.SHA1, a.Hashes.MD5,
			tf(a.CollectedAt), strconv.FormatBool(a.Success), a.Error,
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}

	// timeline.csv — normalized super-timeline.
	tf2, err := os.Create(filepath.Join(dir, "timeline.csv"))
	if err != nil {
		return err
	}
	defer tf2.Close()
	tw := csv.NewWriter(tf2)
	_ = tw.Write([]string{"timestamp", "source", "event_type", "module", "description", "details"})
	for _, e := range m.Timeline {
		_ = tw.Write([]string{tf(e.Timestamp), e.Source, e.EventType, e.Module, e.Description, e.Details})
	}
	tw.Flush()
	return tw.Error()
}

func writeMarkdown(dir string, m *Manifest) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# WinHarvest Collection Report\n\n")
	fmt.Fprintf(&b, "- **Tool**: %s %s\n", m.Tool, m.Version)
	if m.CaseName != "" {
		fmt.Fprintf(&b, "- **Case**: %s\n", m.CaseName)
	}
	if m.Examiner != "" {
		fmt.Fprintf(&b, "- **Examiner**: %s\n", m.Examiner)
	}
	fmt.Fprintf(&b, "- **Host**: %s\n", m.Hostname)
	fmt.Fprintf(&b, "- **OS**: %s\n", m.OS.VersionString())
	fmt.Fprintf(&b, "- **Started**: %s\n", tf(m.StartedAt))
	fmt.Fprintf(&b, "- **Ended**: %s\n", tf(m.EndedAt))
	fmt.Fprintf(&b, "- **Duration**: %s\n", m.Duration().Round(time.Second))
	fmt.Fprintf(&b, "- **Elevated**: %v | **VSS used**: %v\n", m.Elevated, m.VSSUsed)
	fmt.Fprintf(&b, "- **Files collected**: %d (%.1f MB), failed: %d, errors: %d\n\n",
		m.TotalFiles, float64(m.TotalBytes)/1048576.0, m.FailedFiles, m.TotalErrors)

	fmt.Fprintf(&b, "## Modules\n\n| Module | Artifacts | Errors | Duration | Notes |\n|---|---|---|---|---|\n")
	for _, mod := range sortedModules(m.Modules) {
		fmt.Fprintf(&b, "| %s | %d | %d | %s | %s |\n",
			mod.Module, len(mod.Artifacts), len(mod.Errors),
			mod.Duration().Round(time.Millisecond), strings.Join(mod.Notes, "; "))
	}

	fmt.Fprintf(&b, "\n## Errors\n\n")
	any := false
	for _, mod := range m.Modules {
		for _, e := range mod.Errors {
			fmt.Fprintf(&b, "- **%s**: %s\n", mod.Module, e)
			any = true
		}
	}
	if !any {
		fmt.Fprintf(&b, "_No errors recorded._\n")
	}
	return os.WriteFile(filepath.Join(dir, "report.md"), []byte(b.String()), 0o644)
}

func writeHTML(dir string, m *Manifest) error {
	var rows bytes.Buffer
	for _, mod := range sortedModules(m.Modules) {
		fmt.Fprintf(&rows, "<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td></tr>",
			esc(mod.Module), len(mod.Artifacts), len(mod.Errors),
			mod.Duration().Round(time.Millisecond), esc(strings.Join(mod.Notes, "; ")))
	}
	var tl bytes.Buffer
	max := len(m.Timeline)
	if max > 5000 {
		max = 5000 // keep HTML manageable; full data is in timeline.csv
	}
	for i := 0; i < max; i++ {
		e := m.Timeline[i]
		fmt.Fprintf(&tl, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			tf(e.Timestamp), esc(e.Source), esc(e.EventType), esc(e.Module), esc(e.Description))
	}
	html := fmt.Sprintf(htmlTemplate,
		esc(m.Hostname), esc(m.OS.VersionString()), esc(m.CaseName), esc(m.Examiner),
		tf(m.StartedAt), tf(m.EndedAt), m.Duration().Round(time.Second),
		m.Elevated, m.VSSUsed, m.TotalFiles, float64(m.TotalBytes)/1048576.0,
		m.FailedFiles, m.TotalErrors, rows.String(), len(m.Timeline), tl.String())
	return os.WriteFile(filepath.Join(dir, "report.html"), []byte(html), 0o644)
}

func sortedModules(mods []*core.ModuleResult) []*core.ModuleResult {
	out := make([]*core.ModuleResult, len(mods))
	copy(out, mods)
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out
}

func tf(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

const htmlTemplate = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>WinHarvest Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#0f1115;color:#e6e6e6}
h1{color:#4fa3ff}h2{color:#7fb2ff;border-bottom:1px solid #333;padding-bottom:4px}
table{border-collapse:collapse;width:100%%;margin:12px 0;font-size:13px}
th,td{border:1px solid #2a2f3a;padding:6px 8px;text-align:left}
th{background:#1a1f2b}tr:nth-child(even){background:#161a22}
.kv{display:grid;grid-template-columns:200px 1fr;gap:4px;max-width:700px}
.kv div{padding:3px 0}.b{color:#9aa7bd}
</style></head><body>
<h1>WinHarvest Forensic Collection Report</h1>
<div class="kv">
<div class="b">Host</div><div>%s</div>
<div class="b">OS</div><div>%s</div>
<div class="b">Case</div><div>%s</div>
<div class="b">Examiner</div><div>%s</div>
<div class="b">Started</div><div>%s</div>
<div class="b">Ended</div><div>%s</div>
<div class="b">Duration</div><div>%v</div>
<div class="b">Elevated</div><div>%v</div>
<div class="b">VSS used</div><div>%v</div>
<div class="b">Files collected</div><div>%d (%.1f MB)</div>
<div class="b">Failed files</div><div>%d</div>
<div class="b">Errors</div><div>%d</div>
</div>
<h2>Modules</h2>
<table><tr><th>Module</th><th>Artifacts</th><th>Errors</th><th>Duration</th><th>Notes</th></tr>%s</table>
<h2>Timeline (%d events; showing up to 5000 — full data in timeline.csv)</h2>
<table><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Module</th><th>Description</th></tr>%s</table>
</body></html>`
