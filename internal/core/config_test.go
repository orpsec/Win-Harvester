package core

import "testing"

func TestModuleEnabled(t *testing.T) {
	cases := []struct {
		name    string
		allow   []string
		deny    []string
		module  string
		want    bool
	}{
		{"empty allow = all", nil, nil, "registry", true},
		{"deny overrides", nil, []string{"registry"}, "registry", false},
		{"allow list hit", []string{"registry", "system"}, nil, "system", true},
		{"allow list miss", []string{"registry"}, nil, "network", false},
		{"deny beats allow", []string{"registry"}, []string{"registry"}, "registry", false},
	}
	for _, c := range cases {
		cfg := &Config{Modules: c.allow, ExcludeModules: c.deny}
		if got := cfg.ModuleEnabled(c.module); got != c.want {
			t.Errorf("%s: ModuleEnabled(%q) = %v, want %v", c.name, c.module, got, c.want)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.Concurrency <= 0 {
		t.Error("default concurrency must be positive")
	}
	if !c.ComputeHashes {
		t.Error("hashing should be on by default")
	}
	if len(c.ReportFormats) == 0 {
		t.Error("default report formats must be set")
	}
}
