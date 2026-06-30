// Package hashing computes SHA256, SHA1 and MD5 digests in a single streaming
// pass over an io.Reader, so a file is never read more than once.
package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"

	"github.com/winharvest/winharvest/internal/core"
)

// MultiWriter returns the three hashers and an io.Writer that fans out to all
// of them. Useful when copying a file: hash while you copy.
func MultiWriter() (sha256h, sha1h, md5h hash.Hash, w io.Writer) {
	s256 := sha256.New()
	s1 := sha1.New()
	m5 := md5.New()
	return s256, s1, m5, io.MultiWriter(s256, s1, m5)
}

// Sum finalizes the three hashers into a core.FileHashes value.
func Sum(sha256h, sha1h, md5h hash.Hash) core.FileHashes {
	return core.FileHashes{
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
	}
}

// HashReader streams r through all three algorithms and returns the digests.
func HashReader(r io.Reader) (core.FileHashes, error) {
	s256, s1, m5, w := MultiWriter()
	if _, err := io.Copy(w, r); err != nil {
		return core.FileHashes{}, err
	}
	return Sum(s256, s1, m5), nil
}

// HashFile opens a file read-only and hashes it.
func HashFile(path string) (core.FileHashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return core.FileHashes{}, err
	}
	defer f.Close()
	return HashReader(f)
}

// HashBytes hashes an in-memory buffer.
func HashBytes(b []byte) core.FileHashes {
	return core.FileHashes{
		SHA256: hex.EncodeToString(sha256Sum(b)),
		SHA1:   hex.EncodeToString(sha1Sum(b)),
		MD5:    hex.EncodeToString(md5Sum(b)),
	}
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func sha1Sum(b []byte) []byte   { h := sha1.Sum(b); return h[:] }
func md5Sum(b []byte) []byte    { h := md5.Sum(b); return h[:] }
