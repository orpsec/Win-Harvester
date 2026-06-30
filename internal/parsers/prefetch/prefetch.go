// Package prefetch parses Windows Prefetch (.pf) files into a readable form.
//
// Windows 10/11 prefetch files are compressed with the MAM (Xpress Huffman)
// container; decompression is platform-specific (see decompress_*.go). After
// decompression the SCCA structure (version 30 = Win10, 31 = Win11) is parsed
// for the executable name, run count, last-run times and referenced files.
package prefetch

import (
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"
)

// Prefetch is the parsed content of a .pf file.
type Prefetch struct {
	Version       uint32      `json:"version"`
	Executable    string      `json:"executable"`
	Hash          string      `json:"hash"`
	RunCount      uint32      `json:"run_count"`
	LastRunTimes  []time.Time `json:"last_run_times"`
	VolumeCount   uint32      `json:"volume_count"`
	ReferencedFiles []string  `json:"referenced_files,omitempty"`
}

// Parse decodes a .pf file's raw bytes, transparently decompressing the MAM
// container when present.
func Parse(raw []byte) (*Prefetch, error) {
	data := raw
	if len(raw) >= 4 && string(raw[0:3]) == "MAM" {
		dec, err := decompressMAM(raw)
		if err != nil {
			return nil, err
		}
		data = dec
	}
	return parseSCCA(data)
}

func parseSCCA(d []byte) (*Prefetch, error) {
	if len(d) < 0x54 {
		return nil, errors.New("prefetch: too small")
	}
	if string(d[4:8]) != "SCCA" {
		return nil, errors.New("prefetch: bad SCCA signature")
	}
	p := &Prefetch{Version: binary.LittleEndian.Uint32(d[0:4])}
	p.Executable = utf16z(d[0x10:0x4C])
	p.Hash = hexU32(binary.LittleEndian.Uint32(d[0x4C:0x50]))

	// Only versions 30 (Win10) and 31 (Win11) are handled with these offsets.
	if p.Version != 30 && p.Version != 31 {
		return p, nil // header fields still useful
	}

	// File information section begins at 0x54. Field offsets below are absolute.
	if len(d) >= 0x6C {
		fnOff := int(binary.LittleEndian.Uint32(d[0x64:0x68]))
		fnSize := int(binary.LittleEndian.Uint32(d[0x68:0x6C]))
		if fnOff > 0 && fnSize > 0 && fnOff+fnSize <= len(d) {
			p.ReferencedFiles = splitUTF16Z(d[fnOff : fnOff+fnSize])
		}
	}
	if len(d) >= 0x74 {
		p.VolumeCount = binary.LittleEndian.Uint32(d[0x70:0x74])
	}
	// 8 last-run FILETIMEs at 0x80.
	if len(d) >= 0xC0 {
		for i := 0; i < 8; i++ {
			ft := binary.LittleEndian.Uint64(d[0x80+i*8 : 0x88+i*8])
			if t := filetime(ft); !t.IsZero() {
				p.LastRunTimes = append(p.LastRunTimes, t)
			}
		}
	}
	// Run count at 0xD0 (sanity-checked).
	if len(d) >= 0xD4 {
		rc := binary.LittleEndian.Uint32(d[0xD0:0xD4])
		if rc < 1000000 {
			p.RunCount = rc
		}
	}
	return p, nil
}

func filetime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksToUnix = 116444736000000000
	if ft < ticksToUnix {
		return time.Time{}
	}
	return time.Unix(0, int64(ft-ticksToUnix)*100).UTC()
}

// utf16z decodes a null-terminated UTF-16LE string from a fixed buffer.
func utf16z(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		c := binary.LittleEndian.Uint16(b[i*2:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// splitUTF16Z splits a buffer of null-separated UTF-16LE strings.
func splitUTF16Z(b []byte) []string {
	n := len(b) / 2
	var out []string
	var cur []uint16
	for i := 0; i < n; i++ {
		c := binary.LittleEndian.Uint16(b[i*2:])
		if c == 0 {
			if len(cur) > 0 {
				out = append(out, string(utf16.Decode(cur)))
				cur = nil
			}
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, string(utf16.Decode(cur)))
	}
	return out
}

const hexDigits = "0123456789ABCDEF"

func hexU32(v uint32) string {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = hexDigits[v&0xF]
		v >>= 4
	}
	return strings.TrimLeft(string(b), "0") + ""
}
