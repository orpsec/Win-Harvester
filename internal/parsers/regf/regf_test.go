package regf

import "testing"

func TestRot13(t *testing.T) {
	cases := map[string]string{
		"Hello":                     "Uryyb",
		"{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\notepad.exe":
		                            "{S38OS404-1Q43-42S2-9305-67QR0O28SP23}\\abgrcnq.rkr",
	}
	for in, want := range cases {
		if got := rot13(in); got != want {
			t.Errorf("rot13(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTypeName(t *testing.T) {
	if TypeName(RegSZ) != "REG_SZ" || TypeName(RegDWORD) != "REG_DWORD" {
		t.Error("TypeName mapping wrong")
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	if _, err := Open(make([]byte, 10)); err == nil {
		t.Error("expected error on tiny buffer")
	}
	big := make([]byte, baseBlockLen)
	if _, err := Open(big); err == nil {
		t.Error("expected error on bad signature")
	}
}
