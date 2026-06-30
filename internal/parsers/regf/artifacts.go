package regf

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
)

// Node is a JSON-friendly representation of a registry key subtree.
type Node struct {
	Name        string      `json:"name"`
	LastWritten time.Time   `json:"last_written"`
	Values      []ValueJSON `json:"values,omitempty"`
	Subkeys     []*Node     `json:"subkeys,omitempty"`
}

// ValueJSON is a decoded value rendered for JSON output.
type ValueJSON struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data any    `json:"data"`
}

// DumpKey renders a key subtree to a JSON-friendly Node up to maxDepth levels
// (maxDepth < 0 means unlimited). Value data is decoded by type; binary data is
// hex-encoded so it stays readable and lossless.
func DumpKey(k *Key, maxDepth int) *Node {
	n := &Node{Name: k.Name, LastWritten: k.LastWritten}
	for _, v := range k.Values() {
		n.Values = append(n.Values, decodeValueJSON(v))
	}
	if maxDepth == 0 {
		return n
	}
	for _, sub := range k.Subkeys() {
		n.Subkeys = append(n.Subkeys, DumpKey(sub, maxDepth-1))
	}
	return n
}

func decodeValueJSON(v Value) ValueJSON {
	out := ValueJSON{Name: v.Name, Type: TypeName(v.Type)}
	switch v.Type {
	case RegSZ, RegExpandSZ, RegLink:
		out.Data = v.String()
	case RegDWORD, RegDWORDBE:
		out.Data = v.DWORD()
	case RegQWORD:
		out.Data = v.QWORD()
	case RegMultiSZ:
		out.Data = v.MultiSZ()
	default:
		out.Data = hex.EncodeToString(v.Data)
	}
	return out
}

// --- Specific high-value artifact extractors ---

// UserAssistEntry is one decoded UserAssist program-execution record.
type UserAssistEntry struct {
	Name        string    `json:"name"`
	RunCount    uint32    `json:"run_count"`
	LastRun     time.Time `json:"last_run"`
	FocusCount  uint32    `json:"focus_count"`
}

// UserAssist parses HKCU\...\Explorer\UserAssist\{GUID}\Count from an NTUSER hive.
// Value names are ROT13-encoded; data is the 72-byte modern record.
func UserAssist(root *Key) []UserAssistEntry {
	var out []UserAssistEntry
	ua, ok := root.Down("Software", "Microsoft", "Windows", "CurrentVersion", "Explorer", "UserAssist")
	if !ok {
		return out
	}
	for _, guid := range ua.Subkeys() {
		count, ok := guid.Subkey("Count")
		if !ok {
			continue
		}
		for _, v := range count.Values() {
			e := UserAssistEntry{Name: rot13(v.Name)}
			d := v.Data
			if len(d) >= 68 {
				e.RunCount = binary.LittleEndian.Uint32(d[4:8])
				e.FocusCount = binary.LittleEndian.Uint32(d[8:12])
				e.LastRun = filetime(binary.LittleEndian.Uint64(d[60:68]))
			}
			out = append(out, e)
		}
	}
	return out
}

// ShimCacheEntry is one AppCompatCache (ShimCache) record.
type ShimCacheEntry struct {
	Path         string    `json:"path"`
	LastModified time.Time `json:"last_modified"`
}

// ShimCache parses the Win10/11 AppCompatCache from a SYSTEM hive.
func ShimCache(system *Key) []ShimCacheEntry {
	var out []ShimCacheEntry
	// Locate the active ControlSet\Control\Session Manager\AppCompatCache.
	for _, cs := range []string{"ControlSet001", "ControlSet002", "CurrentControlSet"} {
		k, ok := system.Down(cs, "Control", "Session Manager", "AppCompatCache")
		if !ok {
			continue
		}
		v, ok := k.Value("AppCompatCache")
		if !ok {
			continue
		}
		out = append(out, parseShimWin10(v.Data)...)
		if len(out) > 0 {
			break
		}
	}
	return out
}

// parseShimWin10 decodes the "10ts"-signature ShimCache entries (Win8.1/10/11).
func parseShimWin10(d []byte) []ShimCacheEntry {
	var out []ShimCacheEntry
	if len(d) < 0x30 {
		return out
	}
	// Header length is at offset 0 for Win10 (usually 0x30 or 0x34).
	off := int(binary.LittleEndian.Uint32(d[0:4]))
	if off != 0x30 && off != 0x34 {
		off = 0x30
	}
	for off+12 < len(d) {
		if string(d[off:off+4]) != "10ts" {
			break
		}
		// off+4: unknown(4); off+8: cellSize(4); off+12: pathLen(2)
		if off+14 > len(d) {
			break
		}
		pathLen := int(binary.LittleEndian.Uint16(d[off+12 : off+14]))
		p := off + 14
		if p+pathLen > len(d) {
			break
		}
		path := utf16le(d[p : p+pathLen])
		p += pathLen
		if p+8 > len(d) {
			break
		}
		ts := filetime(binary.LittleEndian.Uint64(d[p : p+8]))
		out = append(out, ShimCacheEntry{Path: path, LastModified: ts})
		// dataLen at p+8 (4 bytes) then data; advance by cellSize from off+8.
		cellSize := int(binary.LittleEndian.Uint32(d[off+8 : off+12]))
		next := off + 12 + cellSize
		if next <= off {
			break
		}
		off = next
	}
	return out
}

// AmcacheEntry is one program file inventory record from Amcache.hve.
type AmcacheEntry struct {
	Path        string    `json:"path"`
	SHA1        string    `json:"sha1,omitempty"`
	ProductName string    `json:"product_name,omitempty"`
	Publisher   string    `json:"publisher,omitempty"`
	Size        uint64    `json:"size,omitempty"`
	LinkDate    string    `json:"link_date,omitempty"`
	KeyWritten  time.Time `json:"key_written"`
}

// Amcache parses Root\InventoryApplicationFile from an Amcache.hve root key.
func Amcache(root *Key) []AmcacheEntry {
	var out []AmcacheEntry
	iaf, ok := root.Down("Root", "InventoryApplicationFile")
	if !ok {
		// Older format: Root\File\{volume}\{fileref}
		return amcacheLegacy(root)
	}
	for _, e := range iaf.Subkeys() {
		entry := AmcacheEntry{KeyWritten: e.LastWritten}
		if v, ok := e.Value("LowerCaseLongPath"); ok {
			entry.Path = v.String()
		}
		if v, ok := e.Value("FileId"); ok {
			s := v.String()
			if len(s) > 4 { // FileId is "0000" + SHA1
				entry.SHA1 = strings.TrimPrefix(s, "0000")
			}
		}
		if v, ok := e.Value("ProductName"); ok {
			entry.ProductName = v.String()
		}
		if v, ok := e.Value("Publisher"); ok {
			entry.Publisher = v.String()
		}
		if v, ok := e.Value("Size"); ok {
			entry.Size = v.QWORD()
		}
		if v, ok := e.Value("LinkDate"); ok {
			entry.LinkDate = v.String()
		}
		out = append(out, entry)
	}
	return out
}

func amcacheLegacy(root *Key) []AmcacheEntry {
	var out []AmcacheEntry
	fileKey, ok := root.Down("Root", "File")
	if !ok {
		return out
	}
	for _, vol := range fileKey.Subkeys() {
		for _, e := range vol.Subkeys() {
			entry := AmcacheEntry{KeyWritten: e.LastWritten}
			if v, ok := e.Value("15"); ok { // full path
				entry.Path = v.String()
			}
			if v, ok := e.Value("101"); ok { // SHA1
				entry.SHA1 = strings.TrimPrefix(v.String(), "0000")
			}
			if v, ok := e.Value("0"); ok {
				entry.ProductName = v.String()
			}
			out = append(out, entry)
		}
	}
	return out
}

// USBDevice is one USBSTOR enumerated device.
type USBDevice struct {
	DeviceClass  string    `json:"device_class"`
	SerialNumber string    `json:"serial_number"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	LastWritten  time.Time `json:"last_written"`
}

// USBStor parses HKLM\SYSTEM\...\Enum\USBSTOR from a SYSTEM hive.
func USBStor(system *Key) []USBDevice {
	var out []USBDevice
	for _, cs := range []string{"ControlSet001", "CurrentControlSet"} {
		k, ok := system.Down(cs, "Enum", "USBSTOR")
		if !ok {
			continue
		}
		for _, cls := range k.Subkeys() {
			for _, inst := range cls.Subkeys() {
				d := USBDevice{
					DeviceClass:  cls.Name,
					SerialNumber: inst.Name,
					LastWritten:  inst.LastWritten,
				}
				if v, ok := inst.Value("FriendlyName"); ok {
					d.FriendlyName = v.String()
				}
				out = append(out, d)
			}
		}
		if len(out) > 0 {
			break
		}
	}
	return out
}

// rot13 decodes a ROT13-encoded string (used by UserAssist value names).
func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}
