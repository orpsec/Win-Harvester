// Package lnk parses Windows Shell Link (.lnk) files into a readable structure.
// Pure Go, read-only. Implements the MS-SHLLINK header, LinkInfo (local base
// path) and the StringData section (name, relative path, working dir, args).
package lnk

import (
	"encoding/binary"
	"errors"
	"time"
	"unicode/utf16"
)

// Link is the parsed content of a .lnk file.
type Link struct {
	TargetCreated  time.Time `json:"target_created"`
	TargetAccessed time.Time `json:"target_accessed"`
	TargetModified time.Time `json:"target_modified"`
	TargetSize     uint32    `json:"target_size"`
	LocalBasePath  string    `json:"local_base_path,omitempty"`
	Name           string    `json:"name,omitempty"`
	RelativePath   string    `json:"relative_path,omitempty"`
	WorkingDir     string    `json:"working_dir,omitempty"`
	Arguments      string    `json:"arguments,omitempty"`
	IconLocation   string    `json:"icon_location,omitempty"`
	DriveType      string    `json:"drive_type,omitempty"`
	VolumeLabel    string    `json:"volume_label,omitempty"`
	VolumeSerial   string    `json:"volume_serial,omitempty"`
}

const headerSize = 0x4C

var linkCLSID = []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// Flags bits we care about.
const (
	hasLinkTargetIDList = 1 << 0
	hasLinkInfo         = 1 << 1
	hasName             = 1 << 2
	hasRelativePath     = 1 << 3
	hasWorkingDir       = 1 << 4
	hasArguments        = 1 << 5
	hasIconLocation     = 1 << 6
	isUnicode           = 1 << 7
)

// Parse decodes a .lnk file's bytes.
func Parse(d []byte) (*Link, error) {
	if len(d) < headerSize {
		return nil, errors.New("lnk: too small")
	}
	if binary.LittleEndian.Uint32(d[0:4]) != headerSize {
		return nil, errors.New("lnk: bad header size")
	}
	for i := 0; i < 16; i++ {
		if d[4+i] != linkCLSID[i] {
			return nil, errors.New("lnk: bad CLSID")
		}
	}
	l := &Link{}
	flags := binary.LittleEndian.Uint32(d[0x14:0x18])
	l.TargetSize = binary.LittleEndian.Uint32(d[0x34:0x38])
	l.TargetCreated = filetime(binary.LittleEndian.Uint64(d[0x1C:0x24]))
	l.TargetAccessed = filetime(binary.LittleEndian.Uint64(d[0x24:0x2C]))
	l.TargetModified = filetime(binary.LittleEndian.Uint64(d[0x2C:0x34]))

	pos := headerSize

	// Skip LinkTargetIDList if present (2-byte size prefix + payload).
	if flags&hasLinkTargetIDList != 0 {
		if pos+2 > len(d) {
			return l, nil
		}
		idSize := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
		pos += 2 + idSize
	}

	// LinkInfo (local base path, volume info).
	if flags&hasLinkInfo != 0 && pos+4 <= len(d) {
		liStart := pos
		liSize := int(binary.LittleEndian.Uint32(d[pos : pos+4]))
		if liStart+liSize <= len(d) && liSize >= 0x20 {
			li := d[liStart : liStart+liSize]
			localPathOff := int(binary.LittleEndian.Uint32(li[0x10:0x14]))
			volIDOff := int(binary.LittleEndian.Uint32(li[0x0C:0x10]))
			if localPathOff > 0 && localPathOff < len(li) {
				l.LocalBasePath = cstr(li[localPathOff:])
			}
			if volIDOff > 0 && volIDOff+0x10 <= len(li) {
				vol := li[volIDOff:]
				dt := binary.LittleEndian.Uint32(vol[0x04:0x08])
				l.DriveType = driveType(dt)
				serial := binary.LittleEndian.Uint32(vol[0x08:0x0C])
				l.VolumeSerial = hexU32(serial)
				labelOff := int(binary.LittleEndian.Uint32(vol[0x0C:0x10]))
				if labelOff > 0 && labelOff < len(vol) {
					l.VolumeLabel = cstr(vol[labelOff:])
				}
			}
		}
		pos = liStart + liSize
	}

	// StringData section: each is [uint16 charCount][chars].
	uni := flags&isUnicode != 0
	read := func() string {
		if pos+2 > len(d) {
			return ""
		}
		count := int(binary.LittleEndian.Uint16(d[pos : pos+2]))
		pos += 2
		if uni {
			n := count * 2
			if pos+n > len(d) {
				return ""
			}
			s := utf16le(d[pos : pos+n])
			pos += n
			return s
		}
		if pos+count > len(d) {
			return ""
		}
		s := string(d[pos : pos+count])
		pos += count
		return s
	}
	if flags&hasName != 0 {
		l.Name = read()
	}
	if flags&hasRelativePath != 0 {
		l.RelativePath = read()
	}
	if flags&hasWorkingDir != 0 {
		l.WorkingDir = read()
	}
	if flags&hasArguments != 0 {
		l.Arguments = read()
	}
	if flags&hasIconLocation != 0 {
		l.IconLocation = read()
	}
	return l, nil
}

func driveType(t uint32) string {
	switch t {
	case 0:
		return "UNKNOWN"
	case 1:
		return "NO_ROOT_DIR"
	case 2:
		return "REMOVABLE"
	case 3:
		return "FIXED"
	case 4:
		return "REMOTE"
	case 5:
		return "CDROM"
	case 6:
		return "RAMDISK"
	default:
		return "?"
	}
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

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func utf16le(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	s := string(utf16.Decode(u))
	for i, c := range s {
		if c == 0 {
			return s[:i]
		}
	}
	return s
}

const hexDigits = "0123456789ABCDEF"

func hexU32(v uint32) string {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = hexDigits[v&0xF]
		v >>= 4
	}
	return string(b)
}
