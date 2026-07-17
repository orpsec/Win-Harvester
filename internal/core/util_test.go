package core

import (
	"path/filepath"
	"testing"
)

func TestSanitizeRel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`C:\Windows\System32\config\SYSTEM`, filepath.Join("C", "Windows", "System32", "config", "SYSTEM")},
		{`C:\Users\alice\NTUSER.DAT`, filepath.Join("C", "Users", "alice", "NTUSER.DAT")},
		{`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\foo`, filepath.Join("Windows", "foo")},
		{`D:\path\with:bad*chars?.txt`, filepath.Join("D", "path", "with_bad_chars_.txt")},
	}
	for _, c := range cases {
		if got := sanitizeRel(c.in); got != c.want {
			t.Errorf("sanitizeRel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeRelNeverEscapes(t *testing.T) {
	// Path traversal components must be stripped.
	got := sanitizeRel(`C:\..\..\etc\passwd`)
	if filepath.IsAbs(got) {
		t.Errorf("result must be relative, got %q", got)
	}
	for _, part := range []string{"..", "."} {
		if got == part {
			t.Errorf("traversal not stripped: %q", got)
		}
	}
}
