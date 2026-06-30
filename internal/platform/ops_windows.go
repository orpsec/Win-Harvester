//go:build windows

package platform

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/winharvest/winharvest/internal/core"
	"golang.org/x/sys/windows"
)

// WindowsOps implements core.PlatformOps using Win32 APIs.
type WindowsOps struct{}

// FileTimes extracts created/modified/accessed times from the Win32 file info.
func (WindowsOps) FileTimes(info os.FileInfo, _ string) (created, modified, accessed time.Time) {
	if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		created = time.Unix(0, d.CreationTime.Nanoseconds())
		accessed = time.Unix(0, d.LastAccessTime.Nanoseconds())
		modified = time.Unix(0, d.LastWriteTime.Nanoseconds())
		return
	}
	modified = info.ModTime()
	return
}

// SetTimes applies timestamps to the destination copy (never the source).
func (WindowsOps) SetTimes(path string, created, modified, accessed time.Time) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p,
		windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	c := windows.NsecToFiletime(created.UnixNano())
	a := windows.NsecToFiletime(accessed.UnixNano())
	m := windows.NsecToFiletime(modified.UnixNano())
	var cp, ap, mp *windows.Filetime
	if !created.IsZero() {
		cp = &c
	}
	if !accessed.IsZero() {
		ap = &a
	}
	if !modified.IsZero() {
		mp = &m
	}
	return windows.SetFileTime(h, cp, ap, mp)
}

// OwnerAndACL returns the owner account and a compact DACL description.
func (WindowsOps) OwnerAndACL(path string) (string, string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", "", err
	}
	owner := ""
	if sid, _, e := sd.Owner(); e == nil && sid != nil {
		if acct, dom, _, e2 := sid.LookupAccount(""); e2 == nil {
			owner = dom + "\\" + acct
		} else {
			owner = sid.String()
		}
	}
	acl := ""
	if s := sd.String(); s != "" {
		// SDDL string is a faithful, parseable ACL representation.
		if i := strings.Index(s, "D:"); i >= 0 {
			acl = s[i:]
		} else {
			acl = s
		}
	}
	return owner, acl, nil
}

var _ core.PlatformOps = WindowsOps{}

// NewOps returns the platform operations implementation for this build.
func NewOps() core.PlatformOps { return WindowsOps{} }

// IsElevated reports whether the current process runs with administrative
// privileges, required to read SAM/SECURITY hives and locked artifacts.
func IsElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

func describeError(e error) string { return fmt.Sprintf("%v", e) }
