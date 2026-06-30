package lnk

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestParseMinimalUnicodeName(t *testing.T) {
	d := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(d[0:4], headerSize)
	copy(d[4:20], linkCLSID)
	// flags: HasName | IsUnicode
	binary.LittleEndian.PutUint32(d[0x14:0x18], hasName|isUnicode)
	// target size
	binary.LittleEndian.PutUint32(d[0x34:0x38], 4096)

	// StringData: NAME_STRING = "hi"
	name := "hi"
	u := utf16.Encode([]rune(name))
	sd := make([]byte, 2+len(u)*2)
	binary.LittleEndian.PutUint16(sd[0:2], uint16(len(u)))
	for i, c := range u {
		binary.LittleEndian.PutUint16(sd[2+i*2:], c)
	}
	d = append(d, sd...)

	l, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if l.Name != "hi" {
		t.Errorf("Name = %q, want %q", l.Name, "hi")
	}
	if l.TargetSize != 4096 {
		t.Errorf("TargetSize = %d, want 4096", l.TargetSize)
	}
}

func TestParseRejectsBadCLSID(t *testing.T) {
	d := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(d[0:4], headerSize)
	if _, err := Parse(d); err == nil {
		t.Error("expected error on bad CLSID")
	}
}
