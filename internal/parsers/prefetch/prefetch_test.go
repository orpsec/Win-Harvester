package prefetch

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestParseSCCAv30(t *testing.T) {
	d := make([]byte, 0x100)
	binary.LittleEndian.PutUint32(d[0:4], 30) // version
	copy(d[4:8], []byte("SCCA"))
	// exe name at 0x10
	name := "NOTEPAD.EXE"
	for i, c := range utf16.Encode([]rune(name)) {
		binary.LittleEndian.PutUint16(d[0x10+i*2:], c)
	}
	binary.LittleEndian.PutUint32(d[0x4C:0x50], 0xABCDEF01) // hash
	// one last-run time at 0x80 (a valid FILETIME ~2021)
	binary.LittleEndian.PutUint64(d[0x80:0x88], 132514560000000000)
	binary.LittleEndian.PutUint32(d[0xD0:0xD4], 7) // run count

	p, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Version != 30 {
		t.Errorf("Version = %d, want 30", p.Version)
	}
	if p.Executable != "NOTEPAD.EXE" {
		t.Errorf("Executable = %q", p.Executable)
	}
	if p.RunCount != 7 {
		t.Errorf("RunCount = %d, want 7", p.RunCount)
	}
	if len(p.LastRunTimes) != 1 {
		t.Errorf("LastRunTimes = %d, want 1", len(p.LastRunTimes))
	}
}

func TestParseRejectsBadSig(t *testing.T) {
	d := make([]byte, 0x60)
	binary.LittleEndian.PutUint32(d[0:4], 30)
	copy(d[4:8], []byte("XXXX"))
	if _, err := Parse(d); err == nil {
		t.Error("expected error on bad SCCA signature")
	}
}
