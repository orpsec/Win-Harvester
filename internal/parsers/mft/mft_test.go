package mft

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestParseRecordFileName(t *testing.T) {
	rec := make([]byte, recordSize)
	copy(rec[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(rec[0x04:], 0x30) // USA offset
	binary.LittleEndian.PutUint16(rec[0x06:], 3)    // USA count
	binary.LittleEndian.PutUint16(rec[0x14:], 0x38) // first attribute offset
	binary.LittleEndian.PutUint16(rec[0x16:], 0x01) // flags: in-use

	attr := 0x38
	binary.LittleEndian.PutUint32(rec[attr:], 0x30)        // type $FILE_NAME
	binary.LittleEndian.PutUint32(rec[attr+4:], 0x70)      // attr length
	rec[attr+8] = 0                                         // resident
	binary.LittleEndian.PutUint16(rec[attr+0x14:], 0x18)   // content offset

	content := attr + 0x18
	binary.LittleEndian.PutUint64(rec[content:], 5)        // parent ref
	binary.LittleEndian.PutUint64(rec[content+8:], 132514560000000000)  // created
	binary.LittleEndian.PutUint64(rec[content+16:], 132514560000000000) // modified
	binary.LittleEndian.PutUint64(rec[content+48:], 1234)  // real size
	name := "test.txt"
	u := utf16.Encode([]rune(name))
	rec[content+64] = byte(len(u)) // name length
	rec[content+65] = 1            // namespace Win32
	for i, c := range u {
		binary.LittleEndian.PutUint16(rec[content+66+i*2:], c)
	}
	// terminator
	binary.LittleEndian.PutUint32(rec[attr+0x70:], 0xFFFFFFFF)

	r, ok := parseRecord(rec, 42)
	if !ok {
		t.Fatal("parseRecord returned ok=false")
	}
	if r.Name != "test.txt" {
		t.Errorf("Name = %q, want test.txt", r.Name)
	}
	if r.ParentRef != 5 {
		t.Errorf("ParentRef = %d, want 5", r.ParentRef)
	}
	if r.Size != 1234 {
		t.Errorf("Size = %d, want 1234", r.Size)
	}
	if !r.InUse {
		t.Error("InUse should be true")
	}
	if r.FNCreated.IsZero() {
		t.Error("FNCreated should be set")
	}
}
