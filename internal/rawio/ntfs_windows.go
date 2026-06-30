//go:build windows

// Package rawio implements raw NTFS volume reading to extract locked system
// metadata files ($MFT, $LogFile, $Boot) that cannot be opened through the
// normal filesystem API. It parses the NTFS boot sector, locates the MFT, and
// reconstructs a metafile from its $DATA attribute data runs — all read-only.
package rawio

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// Volume represents an opened raw NTFS volume handle plus parsed geometry.
type Volume struct {
	f                 *os.File
	bytesPerSector    uint32
	sectorsPerCluster uint32
	bytesPerCluster   uint64
	mftStartOffset    uint64
	recordSize        uint32
}

// OpenVolume opens \\.\<drive>: (e.g. drive "C") read-only and parses the boot
// sector. Requires administrative privileges.
func OpenVolume(drive string) (*Volume, error) {
	path := `\\.\` + drive + ":"
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open volume %s: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	v := &Volume{f: f}
	if err := v.parseBoot(); err != nil {
		f.Close()
		return nil, err
	}
	return v, nil
}

// Close releases the volume handle.
func (v *Volume) Close() error { return v.f.Close() }

func (v *Volume) parseBoot() error {
	boot := make([]byte, 512)
	if _, err := v.f.ReadAt(boot, 0); err != nil {
		return fmt.Errorf("read boot sector: %w", err)
	}
	if string(boot[3:7]) != "NTFS" {
		return fmt.Errorf("not an NTFS volume (oem=%q)", string(boot[3:11]))
	}
	v.bytesPerSector = uint32(binary.LittleEndian.Uint16(boot[0x0B:]))
	v.sectorsPerCluster = uint32(boot[0x0D])
	v.bytesPerCluster = uint64(v.bytesPerSector) * uint64(v.sectorsPerCluster)
	mftCluster := binary.LittleEndian.Uint64(boot[0x30:])
	v.mftStartOffset = mftCluster * v.bytesPerCluster

	// Clusters-per-file-record-segment: positive => clusters, negative => 2^|x|.
	cpr := int8(boot[0x40])
	if cpr > 0 {
		v.recordSize = uint32(cpr) * uint32(v.bytesPerCluster)
	} else {
		v.recordSize = 1 << uint(-cpr)
	}
	if v.recordSize == 0 {
		v.recordSize = 1024
	}
	return nil
}

// BytesPerCluster exposes the cluster size.
func (v *Volume) BytesPerCluster() uint64 { return v.bytesPerCluster }

// readRecord reads and fixups a single MFT record at the given record number.
func (v *Volume) readRecord(recNo uint64) ([]byte, error) {
	buf := make([]byte, v.recordSize)
	off := int64(v.mftStartOffset + recNo*uint64(v.recordSize))
	if _, err := v.f.ReadAt(buf, off); err != nil {
		return nil, err
	}
	if string(buf[0:4]) != "FILE" {
		return nil, fmt.Errorf("record %d has bad signature %q", recNo, string(buf[0:4]))
	}
	if err := applyFixup(buf, v.bytesPerSector); err != nil {
		return nil, err
	}
	return buf, nil
}

// ExtractMetafile reconstructs the unnamed $DATA stream of the MFT record with
// the given number and writes it to dst. Record numbers: $MFT=0, $LogFile=2.
func (v *Volume) ExtractMetafile(recNo uint64, dst io.Writer) (int64, error) {
	rec, err := v.readRecord(recNo)
	if err != nil {
		return 0, err
	}
	attrOff := binary.LittleEndian.Uint16(rec[0x14:])
	var (
		runs    []dataRun
		realSz  uint64
		nonRes  bool
		resData []byte
	)
	for off := uint32(attrOff); off+8 <= v.recordSize; {
		attrType := binary.LittleEndian.Uint32(rec[off:])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := binary.LittleEndian.Uint32(rec[off+4:])
		if attrLen == 0 || off+attrLen > v.recordSize {
			break
		}
		if attrType == 0x80 { // $DATA, unnamed stream (name length at +9)
			nameLen := rec[off+9]
			if nameLen == 0 {
				if rec[off+8] == 0 { // resident
					contentLen := binary.LittleEndian.Uint32(rec[off+0x10:])
					contentOff := binary.LittleEndian.Uint16(rec[off+0x14:])
					resData = rec[off+uint32(contentOff) : off+uint32(contentOff)+contentLen]
				} else { // non-resident
					nonRes = true
					realSz = binary.LittleEndian.Uint64(rec[off+0x30:])
					runOff := binary.LittleEndian.Uint16(rec[off+0x20:])
					runs = parseDataRuns(rec[off+uint32(runOff) : off+attrLen])
				}
				break
			}
		}
		off += attrLen
	}

	if !nonRes {
		if resData == nil {
			return 0, fmt.Errorf("record %d: no $DATA attribute found", recNo)
		}
		n, err := dst.Write(resData)
		return int64(n), err
	}
	return v.writeRuns(runs, realSz, dst)
}

// writeRuns reads each data run from the volume and writes the reconstructed
// stream, honoring sparse runs (written as zeros) and the real size.
func (v *Volume) writeRuns(runs []dataRun, realSize uint64, dst io.Writer) (int64, error) {
	var written uint64
	clusterBuf := make([]byte, v.bytesPerCluster)
	zero := make([]byte, v.bytesPerCluster)
	for _, r := range runs {
		for i := int64(0); i < r.lengthClusters; i++ {
			if written >= realSize {
				return int64(written), nil
			}
			var chunk []byte
			if r.sparse {
				chunk = zero
			} else {
				off := (r.startCluster + i) * int64(v.bytesPerCluster)
				if _, err := v.f.ReadAt(clusterBuf, off); err != nil {
					return int64(written), err
				}
				chunk = clusterBuf
			}
			toWrite := uint64(len(chunk))
			if written+toWrite > realSize {
				toWrite = realSize - written
			}
			n, err := dst.Write(chunk[:toWrite])
			written += uint64(n)
			if err != nil {
				return int64(written), err
			}
		}
	}
	return int64(written), nil
}

