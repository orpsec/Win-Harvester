// Package mft parses an extracted NTFS $MFT into readable records (a bodyfile /
// CSV timeline). Pure Go, read-only, streamed record-by-record so very large
// $MFT files do not need to be held in memory all at once.
package mft

import (
	"encoding/binary"
	"io"
	"os"
	"time"
	"unicode/utf16"
)

// Record is one parsed MFT entry with the forensically relevant fields.
type Record struct {
	RecordNumber uint32    `json:"record"`
	InUse        bool      `json:"in_use"`
	IsDir        bool      `json:"is_dir"`
	Name         string    `json:"name"`
	ParentRef    uint64    `json:"parent_ref"`
	Size         uint64    `json:"size"`
	SICreated    time.Time `json:"si_created"`
	SIModified   time.Time `json:"si_modified"`
	SIAccessed   time.Time `json:"si_accessed"`
	SIChanged    time.Time `json:"si_mft_changed"`
	FNCreated    time.Time `json:"fn_created"`
	FNModified   time.Time `json:"fn_modified"`
}

const recordSize = 1024

// ParseFile streams an extracted $MFT file, invoking fn for each valid record.
// Errors on individual records are skipped so a corrupt entry doesn't abort the
// whole parse.
func ParseFile(path string, fn func(Record)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, recordSize)
	var recNo uint32
	for {
		_, err := io.ReadFull(f, buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
		if rec, ok := parseRecord(buf, recNo); ok {
			fn(rec)
		}
		recNo++
	}
	return nil
}

func parseRecord(b []byte, recNo uint32) (Record, bool) {
	if len(b) < 0x38 || string(b[0:4]) != "FILE" {
		return Record{}, false
	}
	applyFixup(b)
	flags := binary.LittleEndian.Uint16(b[0x16:0x18])
	rec := Record{
		RecordNumber: recNo,
		InUse:        flags&0x01 != 0,
		IsDir:        flags&0x02 != 0,
	}

	attrOff := int(binary.LittleEndian.Uint16(b[0x14:0x16]))
	bestNameNS := byte(0xFF)
	for off := attrOff; off+8 <= len(b); {
		atype := binary.LittleEndian.Uint32(b[off:])
		if atype == 0xFFFFFFFF {
			break
		}
		alen := int(binary.LittleEndian.Uint32(b[off+4:]))
		if alen <= 0 || off+alen > len(b) {
			break
		}
		nonResident := b[off+8]
		if nonResident == 0 { // resident attribute
			contentOff := off + int(binary.LittleEndian.Uint16(b[off+0x14:]))
			switch atype {
			case 0x10: // $STANDARD_INFORMATION
				if contentOff+32 <= len(b) {
					rec.SICreated = ft(b[contentOff:])
					rec.SIModified = ft(b[contentOff+8:])
					rec.SIChanged = ft(b[contentOff+16:])
					rec.SIAccessed = ft(b[contentOff+24:])
				}
			case 0x30: // $FILE_NAME
				if contentOff+66 <= len(b) {
					parent := binary.LittleEndian.Uint64(b[contentOff:]) & 0x0000FFFFFFFFFFFF
					fnCreated := ft(b[contentOff+8:])
					fnModified := ft(b[contentOff+16:])
					realSize := binary.LittleEndian.Uint64(b[contentOff+48:])
					nameLen := int(b[contentOff+64])
					ns := b[contentOff+65]
					nameStart := contentOff + 66
					if nameStart+nameLen*2 <= len(b) {
						name := utf16le(b[nameStart : nameStart+nameLen*2])
						// Prefer Win32 (1) / POSIX (0) names over DOS (2).
						if ns < bestNameNS {
							rec.Name = name
							rec.ParentRef = parent
							rec.FNCreated = fnCreated
							rec.FNModified = fnModified
							rec.Size = realSize
							bestNameNS = ns
						}
					}
				}
			}
		}
		off += alen
	}
	if rec.Name == "" {
		return Record{}, false
	}
	return rec, true
}

func applyFixup(rec []byte) {
	usaOff := int(binary.LittleEndian.Uint16(rec[0x04:]))
	usaCount := int(binary.LittleEndian.Uint16(rec[0x06:]))
	if usaCount == 0 || usaOff+2 > len(rec) {
		return
	}
	const bytesPerSector = 512
	for i := 1; i < usaCount; i++ {
		sectorEnd := i*bytesPerSector - 2
		fixIdx := usaOff + i*2
		if sectorEnd+2 > len(rec) || fixIdx+2 > len(rec) {
			break
		}
		rec[sectorEnd] = rec[fixIdx]
		rec[sectorEnd+1] = rec[fixIdx+1]
	}
}

func ft(b []byte) time.Time {
	if len(b) < 8 {
		return time.Time{}
	}
	v := binary.LittleEndian.Uint64(b)
	if v == 0 {
		return time.Time{}
	}
	const ticksToUnix = 116444736000000000
	if v < ticksToUnix {
		return time.Time{}
	}
	return time.Unix(0, int64(v-ticksToUnix)*100).UTC()
}

func utf16le(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}
