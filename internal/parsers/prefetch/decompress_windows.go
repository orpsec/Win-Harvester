//go:build windows

package prefetch

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll                          = windows.NewLazySystemDLL("ntdll.dll")
	procRtlGetCompressionWorkSpace = ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	procRtlDecompressBufferEx      = ntdll.NewProc("RtlDecompressBufferEx")
)

const compressionFormatXpressHuffman = 4

// decompressMAM decompresses a Win10/11 MAM (Xpress Huffman) prefetch container
// using the native ntdll RtlDecompressBufferEx API.
func decompressMAM(raw []byte) ([]byte, error) {
	if len(raw) < 8 {
		return nil, errors.New("prefetch: MAM header too small")
	}
	uncompressedSize := binary.LittleEndian.Uint32(raw[4:8])
	if uncompressedSize == 0 || uncompressedSize > 64*1024*1024 {
		return nil, errors.New("prefetch: implausible uncompressed size")
	}
	compressed := raw[8:]

	var bufWorkSpace, fragWorkSpace uint32
	r, _, _ := procRtlGetCompressionWorkSpace.Call(
		uintptr(compressionFormatXpressHuffman),
		uintptr(unsafe.Pointer(&bufWorkSpace)),
		uintptr(unsafe.Pointer(&fragWorkSpace)),
	)
	if r != 0 {
		return nil, errors.New("prefetch: RtlGetCompressionWorkSpaceSize failed")
	}
	workspace := make([]byte, bufWorkSpace)
	out := make([]byte, uncompressedSize)
	var finalSize uint32

	r, _, _ = procRtlDecompressBufferEx.Call(
		uintptr(compressionFormatXpressHuffman),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(uncompressedSize),
		uintptr(unsafe.Pointer(&compressed[0])),
		uintptr(len(compressed)),
		uintptr(unsafe.Pointer(&finalSize)),
		uintptr(unsafe.Pointer(&workspace[0])),
	)
	if r != 0 {
		return nil, errors.New("prefetch: RtlDecompressBufferEx failed")
	}
	return out[:finalSize], nil
}
