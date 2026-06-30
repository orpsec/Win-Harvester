package core

import (
	"bytes"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

var unsafeChars = regexp.MustCompile(`[<>:"|?*\x00-\x1f]`)

// sanitizeRel converts an absolute Windows path into a safe relative path that
// preserves the directory structure under the module output folder. e.g.
// `C:\Windows\System32\config\SYSTEM` -> `C/Windows/System32/config/SYSTEM`.
func sanitizeRel(p string) string {
	p = strings.ReplaceAll(p, `\`, `/`)
	// strip leading VSS device prefixes if present, including the
	// HarddiskVolumeShadowCopyN device segment that follows.
	if i := strings.Index(p, "GLOBALROOT/Device/"); i >= 0 {
		p = p[i+len("GLOBALROOT/Device/"):]
		if j := strings.Index(p, "/"); j >= 0 && strings.HasPrefix(p, "HarddiskVolume") {
			p = p[j+1:]
		}
	}
	// drive letter "C:" -> "C"
	p = strings.Replace(p, ":", "", 1)
	parts := strings.Split(p, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = unsafeChars.ReplaceAllString(part, "_")
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." {
			continue
		}
		clean = append(clean, part)
	}
	if len(clean) == 0 {
		return "file"
	}
	return filepath.Join(clean...)
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
