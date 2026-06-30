//go:build !windows

package prefetch

import "errors"

// decompressMAM is unavailable off-Windows (relies on ntdll Xpress Huffman).
func decompressMAM(_ []byte) ([]byte, error) {
	return nil, errors.New("prefetch: MAM decompression requires Windows (ntdll)")
}
