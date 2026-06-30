// Command winharvest is a comprehensive, modular Windows forensic artifact
// collector for DFIR, malware analysis and threat hunting on Windows 10/11.
//
// It runs strictly read-only: source evidence is never modified, timestamps are
// preserved on copies, locked files are read through a Volume Shadow Copy, and
// every collected file is hashed (SHA256/SHA1/MD5) with full chain-of-custody
// metadata. Reports are emitted as JSON/CSV/HTML/Markdown and the whole
// collection is optionally packaged into a ZIP.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/winharvest/winharvest/internal/core"
	"github.com/winharvest/winharvest/internal/hashing"
	"github.com/winharvest/winharvest/internal/logging"
	"github.com/winharvest/winharvest/internal/platform"
	"github.com/winharvest/winharvest/internal/report"
	"github.com/winharvest/winharvest/internal/timeline"

	// Blank import registers all collector modules via their init() functions
	// (the plugin pattern). Adding a new module only requires adding a file to
	// the modules package — no change here.
	_ "github.com/winharvest/winharvest/internal/modules"
)

const version = "1.0.0"

func main() {
	cfg, listOnly := parseFlags()

	if listOnly {
		printModules()
		return
	}

	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func parseFlags() (*core.Config, bool) {
	var (
		configPath  = flag.String("config", "", "path to YAML config file")
		outputDir   = flag.String("output", ".", "output directory for the Collection tree")
		modules     = flag.String("modules", "", "comma-separated module allow-list (default: all)")
		exclude     = flag.String("exclude", "", "comma-separated module deny-list")
		concurrency = flag.Int("concurrency", 4, "number of modules to run in parallel")
		useVSS      = flag.Bool("vss", true, "use Volume Shadow Copy for locked files")
		noHash      = flag.Bool("no-hash", false, "disable SHA256/SHA1/MD5 hashing")
		noACL       = flag.Bool("no-acl", false, "disable owner/ACL collection")
		noZip       = flag.Bool("no-zip", false, "do not package the collection into a ZIP")
		maxSize     = flag.Int64("max-file-size", 0, "skip files larger than N bytes (0 = unlimited)")
		caseName    = flag.String("case", "", "case name recorded in the manifest")
		examiner    = flag.String("examiner", "", "examiner name recorded in the manifest")
		volume      = flag.String("volume", `C:\`, "target volume root")
		verbose     = flag.Bool("verbose", false, "enable debug logging")
		listMods    = flag.Bool("list", false, "list available modules and exit")
	)
	flag.Parse()

	var cfg *core.Config
	if *configPath != "" {
		c, err := core.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config error:", err)
			os.Exit(1)
		}
		cfg = c
	} else {
		cfg = core.DefaultConfig()
	}

	// CLI flags override config-file values when explicitly provided.
	visitOverrides(cfg, map[string]func(){
		"output":        func() { cfg.OutputDir = *outputDir },
		"modules":       func() { cfg.Modules = splitCSV(*modules) },
		"exclude":       func() { cfg.ExcludeModules = splitCSV(*exclude) },
		"concurrency":   func() { cfg.Concurrency = *concurrency },
		"vss":           func() { cfg.UseVSS = *useVSS },
		"no-hash":       func() { cfg.ComputeHashes = !*noHash },
		"no-acl":        func() { cfg.CollectACL = !*noACL },
		"no-zip":        func() { cfg.Zip = !*noZip },
		"max-file-size": func() { cfg.MaxFileSize = *maxSize },
		"case":          func() { cfg.CaseName = *caseName },
		"examiner":      func() { cfg.Examiner = *examiner },
		"volume":        func() { cfg.TargetVolume = *volume },
		"verbose":       func() { cfg.Verbose = *verbose },
	})

	return cfg, *listMods
}

// visitOverrides applies a setter only for flags the user explicitly set.
func visitOverrides(_ *core.Config, setters map[string]func()) {
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, fn := range setters {
		if set[name] {
			fn()
		}
	}
}

func run(cfg *core.Config) error {
	startedAt := time.Now()

	// 1) Build the timestamped Collection output tree.
	stamp := startedAt.Format("20060102_150405")
	host, _ := os.Hostname()
	collDir := filepath.Join(cfg.OutputDir, fmt.Sprintf("Collection_%s_%s", sanitize(host), stamp))
	if err := os.MkdirAll(collDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// 2) Logger (console + persistent file).
	level := logging.LevelInfo
	if cfg.Verbose {
		level = logging.LevelDebug
	}
	log, err := logging.New(level, filepath.Join(collDir, "collection.log"))
	if err != nil {
		return err
	}
	defer log.Close()

	log.Infof("WinHarvest %s starting — output: %s", version, collDir)
	elevated := platform.IsElevated()
	if !elevated {
		log.Warnf("NOT running with administrative privileges — many artifacts (SAM/SECURITY, $MFT, locked EVTX) will be unavailable")
	}

	// 3) Detect the operating system and resolve artifact paths.
	osi, err := platform.DetectOS()
	if err != nil {
		log.Warnf("OS detection partial: %v", err)
	}
	log.Infof("detected OS: %s (Win11=%v, arch=%s)", osi.VersionString(), osi.Win11(), osi.Architecture)

	// 4) Signal handling for graceful cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		log.Warnf("interrupt received — cancelling collection (partial results will be saved)")
		cancel()
	}()

	// 5) Volume Shadow Copy resolver (locked-file fallback).
	vss := platform.NewVSS(ctx, log, cfg.TargetVolume, cfg.UseVSS)
	defer vss.Cleanup(ctx)

	// 6) Output writer (copies, hashing, metadata, timestamp preservation).
	writer := core.NewOutputWriter(collDir, cfg, log, osi, hashing.HashReader, platform.NewOps())

	// 7) Shared collection context.
	sink := core.NewTimelineSink()
	cc := &core.Context{
		OutputDir: collDir,
		OS:        osi,
		Config:    cfg,
		Log:       log,
		Writer:    writer,
		VSS:       vss,
		Timeline:  sink,
	}

	// 8) Run all enabled modules with bounded concurrency.
	mgr := core.NewManager(cc, log)
	results := mgr.Run(ctx)

	endedAt := time.Now()

	// 9) Assemble the manifest + unified timeline.
	artifacts := writer.Metas()
	tl := timeline.Build(artifacts, sink)
	man := &report.Manifest{
		Tool:      "WinHarvest",
		Version:   version,
		CaseName:  cfg.CaseName,
		Examiner:  cfg.Examiner,
		Hostname:  osi.Hostname,
		StartedAt: startedAt,
		EndedAt:   endedAt,
		Elevated:  elevated,
		VSSUsed:   vss.Available(),
		OS:        osi,
		Config:    cfg,
		Modules:   results,
		Artifacts: artifacts,
		Timeline:  tl,
	}

	// 10) Render reports into Collection/Reports.
	reportsDir := filepath.Join(collDir, "Reports")
	if err := report.Write(reportsDir, man, cfg.ReportFormats); err != nil {
		log.Errorf("report generation failed: %v", err)
	} else {
		log.Infof("reports written to %s (%v)", reportsDir, cfg.ReportFormats)
	}

	log.Infof("collection complete: %d files (%.1f MB), %d failed, %d errors, %d timeline events in %s",
		man.TotalFiles, float64(man.TotalBytes)/1048576.0, man.FailedFiles, man.TotalErrors,
		len(tl), man.Duration().Round(time.Second))

	// 11) Optional ZIP packaging (written alongside, not inside, the tree).
	if cfg.Zip {
		// Clean up the VSS before zipping so partial shadow handles don't linger.
		vss.Cleanup(ctx)
		zipPath := collDir + ".zip"
		log.Infof("packaging collection into %s ...", zipPath)
		if err := report.ZipDir(collDir, zipPath); err != nil {
			log.Errorf("zip failed: %v", err)
		} else {
			log.Infof("ZIP archive created: %s", zipPath)
		}
	}

	return nil
}

func printModules() {
	fmt.Printf("WinHarvest %s — available collector modules:\n\n", version)
	for _, c := range core.Registered() {
		fmt.Printf("  %-14s [%-10s] %s\n", c.Name(), c.Category(), c.Description())
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sanitize(s string) string {
	r := strings.NewReplacer(" ", "_", "\\", "_", "/", "_", ":", "_")
	if s == "" {
		return "host"
	}
	return r.Replace(s)
}
