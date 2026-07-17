package rawio

import "testing"

func TestReadSignedLE(t *testing.T) {
	cases := []struct {
		b    []byte
		want int64
	}{
		{[]byte{0x05}, 5},
		{[]byte{0xFF}, -1},
		{[]byte{0x00, 0x01}, 256},
		{[]byte{0x00, 0xFF}, -256},
	}
	for _, c := range cases {
		if got := readSignedLE(c.b); got != c.want {
			t.Errorf("readSignedLE(%v) = %d, want %d", c.b, got, c.want)
		}
	}
}

func TestParseDataRuns(t *testing.T) {
	// 0x21 0x18 0x00 0x01 => length=0x18 (1 len byte), offset delta=0x0100 (2 bytes)
	// then 0x00 terminator.
	runs := parseDataRuns([]byte{0x21, 0x18, 0x00, 0x01, 0x00})
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}
	if runs[0].lengthClusters != 0x18 {
		t.Errorf("length = %d, want 24", runs[0].lengthClusters)
	}
	if runs[0].startCluster != 0x100 {
		t.Errorf("startCluster = %d, want 256", runs[0].startCluster)
	}
}

func TestParseDataRunsSparse(t *testing.T) {
	// 0x01 0x05 => length=5, offset size 0 => sparse run.
	runs := parseDataRuns([]byte{0x01, 0x05, 0x00})
	if len(runs) != 1 || !runs[0].sparse {
		t.Fatalf("expected 1 sparse run, got %+v", runs)
	}
}

func TestApplyFixupRoundTrip(t *testing.T) {
	// Build a minimal 2-sector (1024 byte) record with a valid USA.
	bps := uint32(512)
	rec := make([]byte, 1024)
	copy(rec[0:4], []byte("FILE"))
	usaOff := 0x30
	rec[0x04], rec[0x05] = byte(usaOff), 0   // USA offset
	rec[0x06], rec[0x07] = 3, 0              // USA count (1 USN + 2 fixups)
	// USN value
	rec[usaOff], rec[usaOff+1] = 0xAA, 0xBB
	// Fixup values to restore
	rec[usaOff+2], rec[usaOff+3] = 0x11, 0x22
	rec[usaOff+4], rec[usaOff+5] = 0x33, 0x44
	// Place USN at the end of each sector
	rec[512-2], rec[512-1] = 0xAA, 0xBB
	rec[1024-2], rec[1024-1] = 0xAA, 0xBB

	if err := applyFixup(rec, bps); err != nil {
		t.Fatalf("applyFixup: %v", err)
	}
	if rec[512-2] != 0x11 || rec[512-1] != 0x22 {
		t.Errorf("sector 1 not fixed up: %x %x", rec[512-2], rec[512-1])
	}
	if rec[1024-2] != 0x33 || rec[1024-1] != 0x44 {
		t.Errorf("sector 2 not fixed up: %x %x", rec[1024-2], rec[1024-1])
	}
}
