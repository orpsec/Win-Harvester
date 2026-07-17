package modules

import (
	"context"
	"os"
	"path/filepath"
	"strconv"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
	"github.com/winharvest/winharvest/internal/parsers/lnk"
	"github.com/winharvest/winharvest/internal/parsers/prefetch"
	"github.com/winharvest/winharvest/internal/parsers/regf"
)

func itoa(i int) string { return strconv.Itoa(i) }

func pick(opts ...string) string {
	for _, o := range opts {
		if o != "" {
			return o
		}
	}
	return ""
}

// executionModule collects program-execution artifacts: Prefetch, Amcache,
// SRUM, Jump Lists, LNK files, Recent items and WER crash reports.
type executionModule struct{}

func (executionModule) Name() string        { return "execution" }
func (executionModule) Category() string    { return "FileSystem" }
func (executionModule) Description() string { return "Prefetch, Amcache, SRUM, JumpLists, LNK, Recent, WER" }

func (m executionModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	win := collect.SystemRoot(cc.OS)
	sys32 := collect.Win32(cc.OS)

	// Prefetch (*.pf) — first/last run times & run counts.
	pf := h.CopyGlob(filepath.Join(win, "Prefetch", "*.pf"))
	h.CopyGlob(filepath.Join(win, "Prefetch", "*.db")) // ReadyBoot etc.
	h.Note("collected %d prefetch files", pf)

	// Amcache.hve and its transaction logs.
	amDir := filepath.Join(sys32, "config", "..", "..", "AppCompat", "Programs")
	amDir = filepath.Clean(amDir)
	h.CopyFile(filepath.Join(amDir, "Amcache.hve"))
	h.CopyGlob(filepath.Join(amDir, "Amcache.hve.LOG*"))
	h.CopyGlob(filepath.Join(amDir, "RecentFileCache.bcf"))

	// SRUM (System Resource Usage Monitor) database + its registry hive piece.
	h.CopyFile(filepath.Join(sys32, "sru", "SRUDB.dat"))
	h.CopyGlob(filepath.Join(sys32, "sru", "SRU*.log"))

	// Per-user execution artifacts: JumpLists, LNK, Recent.
	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		recent := filepath.Join(u.ProfilePath, `AppData\Roaming\Microsoft\Windows\Recent`)
		h.CopyGlob(filepath.Join(recent, "*.lnk"))
		h.CopyGlob(filepath.Join(recent, `AutomaticDestinations`, "*"))
		h.CopyGlob(filepath.Join(recent, `CustomDestinations`, "*"))

		// Office/Explorer recent LNKs.
		h.CopyGlob(filepath.Join(u.ProfilePath, `AppData\Roaming\Microsoft\Office\Recent`, "*.lnk"))

		// Start Menu / Desktop LNKs (often launch points).
		h.CopyTree(filepath.Join(u.ProfilePath, `AppData\Roaming\Microsoft\Windows\Start Menu`),
			func(n string) bool { return filepath.Ext(n) == ".lnk" })
	}

	// Windows Error Reporting — crash evidence (process names, modules).
	progData := collect.ProgramData(cc.OS)
	h.CopyTree(filepath.Join(progData, `Microsoft\Windows\WER`), nil)
	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		h.CopyTree(filepath.Join(u.ProfilePath, `AppData\Local\Microsoft\Windows\WER`), nil)
	}

	// Readable, analyst/AI-friendly parsed outputs from the raw files just
	// collected (written under parsed/).
	m.parsePrefetch(h)
	m.parseLNK(h)
	m.parseAmcache(h)

	return h.Result(), nil
}

// parsePrefetch decodes every collected .pf into JSON and adds execution events.
func (m executionModule) parsePrefetch(h *collect.Helper) {
	var all []*prefetch.Prefetch
	h.WalkCollected(func(n string) bool { return filepath.Ext(n) == ".pf" }, func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		pf, err := prefetch.Parse(raw)
		if err != nil {
			h.Ctx().Log.Debugf("[execution] prefetch parse %s: %v", path, err)
			return
		}
		all = append(all, pf)
		for _, t := range pf.LastRunTimes {
			h.Timeline(core.TimelineEvent{
				Timestamp:   t,
				Source:      "Prefetch",
				EventType:   "Execution",
				Module:      "execution",
				Description: pf.Executable,
				Details:     "run_count=" + itoa(int(pf.RunCount)),
			})
		}
	})
	if len(all) > 0 {
		h.SaveJSON("prefetch.json", all)
		h.Note("parsed %d prefetch files -> parsed/prefetch.json", len(all))
	}
}

// parseLNK decodes collected .lnk files into JSON with their target paths.
func (m executionModule) parseLNK(h *collect.Helper) {
	type entry struct {
		Source string    `json:"lnk_file"`
		Link   *lnk.Link `json:"link"`
	}
	var all []entry
	h.WalkCollected(func(n string) bool { return filepath.Ext(n) == ".lnk" }, func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		l, err := lnk.Parse(raw)
		if err != nil {
			return
		}
		all = append(all, entry{Source: filepath.Base(path), Link: l})
		if !l.TargetModified.IsZero() {
			h.Timeline(core.TimelineEvent{
				Timestamp:   l.TargetModified,
				Source:      "LNK",
				EventType:   "FileOpened",
				Module:      "execution",
				Description: pick(l.LocalBasePath, l.RelativePath, l.Name),
				Details:     "args=" + l.Arguments,
			})
		}
	})
	if len(all) > 0 {
		h.SaveJSON("lnk.json", all)
		h.Note("parsed %d LNK files -> parsed/lnk.json", len(all))
	}
}

// parseAmcache decodes the collected Amcache.hve into a program inventory JSON.
func (m executionModule) parseAmcache(h *collect.Helper) {
	h.WalkCollected(func(n string) bool { return n == "amcache.hve" }, func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		hive, err := regf.Open(data)
		if err != nil {
			return
		}
		root, err := hive.Root()
		if err != nil {
			return
		}
		entries := regf.Amcache(root)
		if len(entries) > 0 {
			h.SaveJSON("amcache.json", entries)
			h.Note("parsed Amcache.hve -> %d entries in parsed/amcache.json", len(entries))
		}
	})
}

func init() { core.Register(executionModule{}) }
