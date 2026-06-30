package regf

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Registry value type constants.
const (
	RegNone        = 0
	RegSZ          = 1
	RegExpandSZ    = 2
	RegBinary      = 3
	RegDWORD       = 4
	RegDWORDBE     = 5
	RegLink        = 6
	RegMultiSZ     = 7
	RegQWORD       = 11
)

// TypeName returns a human label for a registry value type.
func TypeName(t uint32) string {
	switch t {
	case RegNone:
		return "REG_NONE"
	case RegSZ:
		return "REG_SZ"
	case RegExpandSZ:
		return "REG_EXPAND_SZ"
	case RegBinary:
		return "REG_BINARY"
	case RegDWORD:
		return "REG_DWORD"
	case RegDWORDBE:
		return "REG_DWORD_BIG_ENDIAN"
	case RegLink:
		return "REG_LINK"
	case RegMultiSZ:
		return "REG_MULTI_SZ"
	case RegQWORD:
		return "REG_QWORD"
	default:
		return "REG_UNKNOWN"
	}
}

// String decodes the value as a UTF-16LE string (REG_SZ/REG_EXPAND_SZ).
func (v Value) String() string {
	if len(v.Data) == 0 {
		return ""
	}
	return strings.TrimRight(utf16le(v.Data), "\x00")
}

// DWORD decodes a REG_DWORD value.
func (v Value) DWORD() uint32 {
	if len(v.Data) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(v.Data[:4])
}

// QWORD decodes a REG_QWORD value.
func (v Value) QWORD() uint64 {
	if len(v.Data) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(v.Data[:8])
}

// MultiSZ decodes a REG_MULTI_SZ value into its component strings.
func (v Value) MultiSZ() []string {
	s := utf16le(v.Data)
	parts := strings.Split(s, "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// utf16le decodes little-endian UTF-16 bytes into a Go string.
func utf16le(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func equalFold(a, b string) bool { return strings.EqualFold(a, b) }
