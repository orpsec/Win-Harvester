package core

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config controls the behaviour of a collection run. It can be loaded from a
// YAML file or constructed from CLI flags.
type Config struct {
	// OutputDir is the parent directory where the Collection/ tree is created.
	OutputDir string `yaml:"output_dir"`

	// Modules, if non-empty, is an allow-list of module names to run. Empty
	// means "all registered modules".
	Modules []string `yaml:"modules"`

	// ExcludeModules is a deny-list applied after the allow-list.
	ExcludeModules []string `yaml:"exclude_modules"`

	// Concurrency is the number of modules run in parallel.
	Concurrency int `yaml:"concurrency"`

	// UseVSS enables Volume Shadow Copy fallback for locked files.
	UseVSS bool `yaml:"use_vss"`

	// MaxFileSize caps the size (bytes) of any single collected file. 0 = no cap.
	MaxFileSize int64 `yaml:"max_file_size"`

	// ComputeHashes toggles SHA256/SHA1/MD5 computation.
	ComputeHashes bool `yaml:"compute_hashes"`

	// CollectACL toggles owner/ACL extraction (slower).
	CollectACL bool `yaml:"collect_acl"`

	// Zip packages the whole collection into a single archive when done.
	Zip bool `yaml:"zip"`

	// ReportFormats selects which reports to emit: json, csv, html, md.
	ReportFormats []string `yaml:"report_formats"`

	// CaseName / Examiner are recorded in the run manifest.
	CaseName string `yaml:"case_name"`
	Examiner string `yaml:"examiner"`

	// Verbose enables debug logging.
	Verbose bool `yaml:"verbose"`

	// TargetVolume is the drive letter root to collect from (default C:\).
	TargetVolume string `yaml:"target_volume"`
}

// DefaultConfig returns a sane production default.
func DefaultConfig() *Config {
	return &Config{
		OutputDir:     ".",
		Concurrency:   4,
		UseVSS:        true,
		MaxFileSize:   0,
		ComputeHashes: true,
		CollectACL:    true,
		Zip:           true,
		ReportFormats: []string{"json", "csv", "html", "md"},
		TargetVolume:  `C:\`,
	}
}

// LoadConfig reads a YAML config file, falling back to defaults for unset fields.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.TargetVolume == "" {
		cfg.TargetVolume = `C:\`
	}
	return cfg, nil
}

// ModuleEnabled applies the allow/deny lists to decide if a module runs.
func (c *Config) ModuleEnabled(name string) bool {
	for _, ex := range c.ExcludeModules {
		if ex == name {
			return false
		}
	}
	if len(c.Modules) == 0 {
		return true
	}
	for _, m := range c.Modules {
		if m == name {
			return true
		}
	}
	return false
}
