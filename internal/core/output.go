package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// OutputWriter is the single sink through which every collector persists data.
// It enforces the forensic rules: source files are only ever read, copies have
// their timestamps preserved, and per-file metadata (incl. hashes) is recorded.
type OutputWriter struct {
	root   string // Collection/ root
	cfg    *Config
	log    Logger
	osi    *OSInfo
	hasher FileHasher
	plat   PlatformOps

	mu    sync.Mutex
	metas []ArtifactMeta
}

// FileHasher computes the three digests over a reader (injected to avoid an
// import cycle with the hashing package).
type FileHasher func(r io.Reader) (FileHashes, error)

// PlatformOps abstracts OS-specific metadata/timestamp operations so the core
// package stays portable and unit-testable.
type PlatformOps interface {
	// FileTimes returns created/modified/accessed times for a path.
	FileTimes(info os.FileInfo, path string) (created, modified, accessed time.Time)
	// SetTimes applies created/modified/accessed times to a destination file.
	SetTimes(path string, created, modified, accessed time.Time) error
	// OwnerAndACL returns the owner SID/name and an ACL string (best effort).
	OwnerAndACL(path string) (owner, acl string, err error)
}

// NewOutputWriter constructs a writer rooted at <outputDir>/Collection.
func NewOutputWriter(root string, cfg *Config, log Logger, osi *OSInfo, h FileHasher, p PlatformOps) *OutputWriter {
	return &OutputWriter{root: root, cfg: cfg, log: log, osi: osi, hasher: h, plat: p}
}

// Root returns the Collection root directory.
func (w *OutputWriter) Root() string { return w.root }

// Metas returns a snapshot of all recorded metadata.
func (w *OutputWriter) Metas() []ArtifactMeta {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]ArtifactMeta, len(w.metas))
	copy(out, w.metas)
	return out
}

func (w *OutputWriter) record(m ArtifactMeta) {
	w.mu.Lock()
	w.metas = append(w.metas, m)
	w.mu.Unlock()
}

// ModuleDir returns (creating if needed) the output directory for a module,
// nested under its category: Collection/<Category>/<Module>.
func (w *OutputWriter) ModuleDir(category, module string) (string, error) {
	dir := filepath.Join(w.root, category, module)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// CopyFile copies srcPath (read-only) into the module directory, preserving the
// source timestamps on the copy, computing hashes, and recording metadata.
// It NEVER writes to or modifies the source. resolvedSrc is the path actually
// read (may be a VSS path); origPath is recorded as the canonical origin.
func (w *OutputWriter) CopyFile(module, category, origPath, resolvedSrc, source string) (ArtifactMeta, error) {
	dir, err := w.ModuleDir(category, module)
	if err != nil {
		return ArtifactMeta{}, err
	}
	// Preserve relative layout by flattening the source path safely.
	destName := sanitizeRel(origPath)
	dest := filepath.Join(dir, destName)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return ArtifactMeta{}, err
	}

	meta := ArtifactMeta{
		Module:       module,
		OriginalPath: origPath,
		StoredPath:   dest,
		CollectedAt:  time.Now().UTC(),
		Source:       source,
	}

	src, err := os.Open(resolvedSrc)
	if err != nil {
		meta.Success = false
		meta.Error = err.Error()
		w.record(meta)
		return meta, err
	}
	defer src.Close()

	info, err := src.Stat()
	if err == nil {
		meta.Size = info.Size()
		if w.cfg.MaxFileSize > 0 && info.Size() > w.cfg.MaxFileSize {
			meta.Success = false
			meta.Error = fmt.Sprintf("skipped: size %d exceeds max_file_size %d", info.Size(), w.cfg.MaxFileSize)
			w.record(meta)
			return meta, nil
		}
		if w.plat != nil {
			meta.CreatedTime, meta.ModifiedTime, meta.AccessedTime = w.plat.FileTimes(info, resolvedSrc)
		}
	}
	if w.cfg.CollectACL && w.plat != nil {
		if owner, acl, e := w.plat.OwnerAndACL(resolvedSrc); e == nil {
			meta.Owner, meta.ACL = owner, acl
		}
	}

	out, err := os.Create(dest)
	if err != nil {
		meta.Success = false
		meta.Error = err.Error()
		w.record(meta)
		return meta, err
	}

	var reader io.Reader = src
	if w.cfg.ComputeHashes {
		// hash while copying via the injected hasher over a TeeReader-free path:
		// we compute hashes by re-reading is wasteful, so copy+hash in one pass.
		h, copyErr := w.copyAndHash(out, src)
		out.Close()
		if copyErr != nil {
			meta.Success = false
			meta.Error = copyErr.Error()
			w.record(meta)
			return meta, copyErr
		}
		meta.Hashes = h
	} else {
		if _, e := io.Copy(out, reader); e != nil {
			out.Close()
			meta.Success = false
			meta.Error = e.Error()
			w.record(meta)
			return meta, e
		}
		out.Close()
	}

	// Preserve source timestamps on the copy (does not touch the source).
	if w.plat != nil && !meta.ModifiedTime.IsZero() {
		if e := w.plat.SetTimes(dest, meta.CreatedTime, meta.ModifiedTime, meta.AccessedTime); e != nil {
			w.log.Debugf("could not preserve timestamps on %s: %v", dest, e)
		}
	}

	meta.Success = true
	w.record(meta)
	return meta, nil
}

// copyAndHash copies src->dst while hashing the bytes in a single pass.
func (w *OutputWriter) copyAndHash(dst io.Writer, src io.Reader) (FileHashes, error) {
	pr, pw := io.Pipe()
	tee := io.TeeReader(src, pw)
	type res struct {
		h   FileHashes
		err error
	}
	ch := make(chan res, 1)
	go func() {
		h, err := w.hasher(pr)
		ch <- res{h, err}
	}()
	_, copyErr := io.Copy(dst, tee)
	pw.Close()
	r := <-ch
	if copyErr != nil {
		return FileHashes{}, copyErr
	}
	return r.h, r.err
}

// WriteData writes an in-memory buffer (e.g. command output) as a named file in
// the module directory and records metadata + hashes.
func (w *OutputWriter) WriteData(module, category, name string, data []byte) (ArtifactMeta, error) {
	dir, err := w.ModuleDir(category, module)
	if err != nil {
		return ArtifactMeta{}, err
	}
	dest := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return ArtifactMeta{}, err
	}
	meta := ArtifactMeta{
		Module:       module,
		OriginalPath: "(generated) " + name,
		StoredPath:   dest,
		Size:         int64(len(data)),
		CollectedAt:  time.Now().UTC(),
		Source:       "generated",
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		meta.Success = false
		meta.Error = err.Error()
		w.record(meta)
		return meta, err
	}
	if w.cfg.ComputeHashes {
		if h, e := w.hasher(bytesReader(data)); e == nil {
			meta.Hashes = h
		}
	}
	meta.Success = true
	w.record(meta)
	return meta, nil
}
