package hashing

import (
	"strings"
	"testing"
)

func TestHashReaderKnownVectors(t *testing.T) {
	// Known digests for the empty string and "abc".
	cases := []struct {
		in     string
		sha256 string
		sha1   string
		md5    string
	}{
		{
			in:     "",
			sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			sha1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			md5:    "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			in:     "abc",
			sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			sha1:   "a9993e364706816aba3e25717850c26c9cd0d89d",
			md5:    "900150983cd24fb0d6963f7d28e17f72",
		},
	}
	for _, c := range cases {
		h, err := HashReader(strings.NewReader(c.in))
		if err != nil {
			t.Fatalf("HashReader(%q): %v", c.in, err)
		}
		if h.SHA256 != c.sha256 {
			t.Errorf("%q sha256 = %s, want %s", c.in, h.SHA256, c.sha256)
		}
		if h.SHA1 != c.sha1 {
			t.Errorf("%q sha1 = %s, want %s", c.in, h.SHA1, c.sha1)
		}
		if h.MD5 != c.md5 {
			t.Errorf("%q md5 = %s, want %s", c.in, h.MD5, c.md5)
		}
	}
}

func TestHashBytesMatchesReader(t *testing.T) {
	data := []byte("the quick brown fox")
	a := HashBytes(data)
	b, err := HashReader(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("HashBytes != HashReader: %+v vs %+v", a, b)
	}
}
