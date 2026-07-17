// Package regf is a read-only parser for Windows registry hive files (the
// "regf" on-disk format used by SYSTEM, SOFTWARE, NTUSER.DAT, Amcache.hve etc.).
//
// It is pure Go (no OS dependency) so collected hives can be parsed offline on
// any platform and rendered to analyst/AI-readable JSON. It never writes to the
// source file.
package regf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	regfMagic    = 0x66676572 // "regf"
	hbinMagic    = 0x6e696268 // "hbin"
	baseBlockLen = 0x1000     // 4096
	hbinHeader   = 0x20
)

// Hive is a parsed registry hive backed by an in-memory copy of the file bytes.
type Hive struct {
	data     []byte
	rootCell int32
}

// Open parses the hive bytes. The caller supplies the full file contents.
func Open(data []byte) (*Hive, error) {
	if len(data) < baseBlockLen {
		return nil, errors.New("regf: file too small")
	}
	if binary.LittleEndian.Uint32(data[0:4]) != regfMagic {
		return nil, errors.New("regf: bad signature")
	}
	root := int32(binary.LittleEndian.Uint32(data[0x24:0x28]))
	return &Hive{data: data, rootCell: root}, nil
}

// cell returns the bytes of the cell at the given offset (relative to the first
// hbin, i.e. file offset = baseBlockLen + cellOffset + 4 for the data). The
// 4-byte size prefix is stripped.
func (h *Hive) cell(off int32) ([]byte, bool) {
	if off < 0 {
		return nil, false
	}
	pos := int(baseBlockLen) + int(off)
	if pos+4 > len(h.data) {
		return nil, false
	}
	size := int32(binary.LittleEndian.Uint32(h.data[pos : pos+4]))
	if size < 0 {
		size = -size // allocated cell
	}
	if size < 4 || pos+int(size) > len(h.data) {
		return nil, false
	}
	return h.data[pos+4 : pos+int(size)], true
}

// Root returns the hive's root key.
func (h *Hive) Root() (*Key, error) {
	c, ok := h.cell(h.rootCell)
	if !ok {
		return nil, errors.New("regf: cannot read root cell")
	}
	return h.parseKey(c)
}

// Key is a parsed key node (nk record).
type Key struct {
	h           *Hive
	Name        string
	LastWritten time.Time
	subkeyList  int32
	numSubkeys  uint32
	valueList   int32
	numValues   uint32
}

func (h *Hive) parseKey(c []byte) (*Key, error) {
	if len(c) < 0x50 || c[0] != 'n' || c[1] != 'k' {
		return nil, errors.New("regf: not an nk cell")
	}
	k := &Key{h: h}
	k.LastWritten = filetime(binary.LittleEndian.Uint64(c[0x04:0x0C]))
	k.numSubkeys = binary.LittleEndian.Uint32(c[0x14:0x18])
	k.subkeyList = int32(binary.LittleEndian.Uint32(c[0x1C:0x20]))
	k.numValues = binary.LittleEndian.Uint32(c[0x24:0x28])
	k.valueList = int32(binary.LittleEndian.Uint32(c[0x28:0x2C]))
	nameLen := int(binary.LittleEndian.Uint16(c[0x48:0x4A]))
	flags := binary.LittleEndian.Uint16(c[0x02:0x04])
	if 0x4C+nameLen <= len(c) {
		raw := c[0x4C : 0x4C+nameLen]
		if flags&0x20 != 0 { // ASCII (compressed) name
			k.Name = string(raw)
		} else {
			k.Name = utf16le(raw)
		}
	}
	return k, nil
}

// Subkeys returns the immediate child keys.
func (k *Key) Subkeys() []*Key {
	var out []*Key
	k.walkSubkeyList(k.subkeyList, &out)
	return out
}

func (k *Key) walkSubkeyList(off int32, out *[]*Key) {
	if off == -1 || off == 0 {
		return
	}
	c, ok := k.h.cell(off)
	if !ok || len(c) < 4 {
		return
	}
	sig := string(c[0:2])
	switch sig {
	case "lf", "lh": // fast leaf: pairs of (offset, hash)
		count := int(binary.LittleEndian.Uint16(c[2:4]))
		for i := 0; i < count; i++ {
			base := 4 + i*8
			if base+4 > len(c) {
				break
			}
			koff := int32(binary.LittleEndian.Uint32(c[base : base+4]))
			if kc, ok := k.h.cell(koff); ok {
				if sub, err := k.h.parseKey(kc); err == nil {
					*out = append(*out, sub)
				}
			}
		}
	case "li": // index leaf: list of offsets
		count := int(binary.LittleEndian.Uint16(c[2:4]))
		for i := 0; i < count; i++ {
			base := 4 + i*4
			if base+4 > len(c) {
				break
			}
			koff := int32(binary.LittleEndian.Uint32(c[base : base+4]))
			if kc, ok := k.h.cell(koff); ok {
				if sub, err := k.h.parseKey(kc); err == nil {
					*out = append(*out, sub)
				}
			}
		}
	case "ri": // index root: list of subkey-list offsets
		count := int(binary.LittleEndian.Uint16(c[2:4]))
		for i := 0; i < count; i++ {
			base := 4 + i*4
			if base+4 > len(c) {
				break
			}
			sub := int32(binary.LittleEndian.Uint32(c[base : base+4]))
			k.walkSubkeyList(sub, out)
		}
	}
}

// Subkey returns the named child key (case-insensitive), if present.
func (k *Key) Subkey(name string) (*Key, bool) {
	for _, s := range k.Subkeys() {
		if equalFold(s.Name, name) {
			return s, true
		}
	}
	return nil, false
}

// Down descends a path of subkey names, returning the final key.
func (k *Key) Down(path ...string) (*Key, bool) {
	cur := k
	for _, p := range path {
		next, ok := cur.Subkey(p)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// Value is a parsed value (vk record).
type Value struct {
	Name string
	Type uint32
	Data []byte
}

// Values returns all values of the key.
func (k *Key) Values() []Value {
	var out []Value
	if k.numValues == 0 || k.valueList == -1 || k.valueList == 0 {
		return out
	}
	list, ok := k.h.cell(k.valueList)
	if !ok {
		return out
	}
	for i := 0; i < int(k.numValues); i++ {
		base := i * 4
		if base+4 > len(list) {
			break
		}
		voff := int32(binary.LittleEndian.Uint32(list[base : base+4]))
		vc, ok := k.h.cell(voff)
		if !ok || len(vc) < 0x14 || vc[0] != 'v' || vc[1] != 'k' {
			continue
		}
		out = append(out, k.h.parseValue(vc))
	}
	return out
}

func (h *Hive) parseValue(c []byte) Value {
	nameLen := int(binary.LittleEndian.Uint16(c[0x02:0x04]))
	dataLen := binary.LittleEndian.Uint32(c[0x04:0x08])
	dataOff := int32(binary.LittleEndian.Uint32(c[0x08:0x0C]))
	typ := binary.LittleEndian.Uint32(c[0x0C:0x10])
	flags := binary.LittleEndian.Uint16(c[0x10:0x12])

	v := Value{Type: typ}
	if nameLen > 0 && 0x14+nameLen <= len(c) {
		raw := c[0x14 : 0x14+nameLen]
		if flags&0x01 != 0 {
			v.Name = string(raw)
		} else {
			v.Name = utf16le(raw)
		}
	}

	const inlineBit = 0x80000000
	size := dataLen &^ inlineBit
	if dataLen&inlineBit != 0 {
		// Data stored inline in the data-offset field (<= 4 bytes).
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(dataOff))
		if size > 4 {
			size = 4
		}
		v.Data = buf[:size]
		return v
	}
	dc, ok := h.cell(dataOff)
	if !ok {
		return v
	}
	if int(size) <= len(dc) {
		v.Data = dc[:size]
	} else {
		v.Data = dc // big-data (db) not fully reassembled; return first chunk
	}
	return v
}

// Value returns the named value of the key (case-insensitive). The default
// (unnamed) value is matched with the empty string.
func (k *Key) Value(name string) (Value, bool) {
	for _, v := range k.Values() {
		if equalFold(v.Name, name) {
			return v, true
		}
	}
	return Value{}, false
}

// filetime converts a Windows FILETIME (100ns since 1601) to time.Time.
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

func (h *Hive) String() string { return fmt.Sprintf("regf hive (%d bytes)", len(h.data)) }
