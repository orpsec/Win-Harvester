package rawio

import "fmt"

// This file holds the pure NTFS structure parsers (no OS dependency) so they can
// be unit-tested on any platform.

// dataRun is one extent of a non-resident attribute.
type dataRun struct {
	lengthClusters int64
	startCluster   int64 // absolute LCN (sparse runs have no start)
	sparse         bool
}

// applyFixup applies the NTFS Update Sequence Array fixup to a record buffer,
// restoring the last two bytes of every sector from the USA.
func applyFixup(rec []byte, bytesPerSector uint32) error {
	if len(rec) < 8 {
		return fmt.Errorf("record too small")
	}
	usaOff := uint16(rec[0x04]) | uint16(rec[0x05])<<8
	usaCount := uint16(rec[0x06]) | uint16(rec[0x07])<<8
	if usaCount == 0 {
		return nil
	}
	if int(usaOff)+2 > len(rec) {
		return fmt.Errorf("bad USA offset")
	}
	usn := rec[usaOff : usaOff+2]
	for i := uint16(1); i < usaCount; i++ {
		sectorEnd := int(i)*int(bytesPerSector) - 2
		if sectorEnd < 0 || sectorEnd+2 > len(rec) {
			break
		}
		fixIdx := int(usaOff) + int(i)*2
		if fixIdx+2 > len(rec) {
			break
		}
		if rec[sectorEnd] != usn[0] || rec[sectorEnd+1] != usn[1] {
			return fmt.Errorf("fixup mismatch at sector %d", i)
		}
		rec[sectorEnd] = rec[fixIdx]
		rec[sectorEnd+1] = rec[fixIdx+1]
	}
	return nil
}

// parseDataRuns decodes the data-run list of a non-resident attribute into a
// sequence of extents, resolving the signed-delta-encoded LCNs.
func parseDataRuns(b []byte) []dataRun {
	var runs []dataRun
	var prevLCN int64
	i := 0
	for i < len(b) {
		header := b[i]
		if header == 0 {
			break
		}
		i++
		lenSize := int(header & 0x0F)
		offSize := int(header >> 4)
		if lenSize == 0 || i+lenSize+offSize > len(b) {
			break
		}
		length := readLE(b[i : i+lenSize])
		i += lenSize

		run := dataRun{lengthClusters: length}
		if offSize == 0 {
			run.sparse = true
		} else {
			delta := readSignedLE(b[i : i+offSize])
			prevLCN += delta
			run.startCluster = prevLCN
		}
		i += offSize
		runs = append(runs, run)
	}
	return runs
}

// readLE reads an unsigned little-endian integer of len(b) bytes.
func readLE(b []byte) int64 {
	var v int64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | int64(b[i])
	}
	return v
}

// readSignedLE reads a sign-extended little-endian integer of len(b) bytes.
func readSignedLE(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | int64(b[i])
	}
	shift := uint(64 - 8*len(b))
	return (v << shift) >> shift
}
