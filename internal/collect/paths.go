package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/winharvest/winharvest/internal/core"
)

// UserProfile describes one local user profile directory.
type UserProfile struct {
	Username    string
	ProfilePath string // e.g. C:\Users\alice
	NTUser      string // NTUSER.DAT
	UsrClass    string // AppData\Local\Microsoft\Windows\UsrClass.dat
}

// EnumerateUserProfiles lists user profile directories under <drive>\Users,
// skipping system pseudo-profiles. Works by directory enumeration so it does
// not depend on the registry being parseable.
func EnumerateUserProfiles(osi *core.OSInfo) []UserProfile {
	drive := "C:"
	if osi != nil && osi.SystemDrive != "" {
		drive = osi.SystemDrive
	}
	usersDir := drive + `\Users`
	var out []UserProfile
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return out
	}
	skip := map[string]bool{
		"public": true, "default": true, "default user": true,
		"all users": true, "defaultaccount": true,
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if skip[strings.ToLower(name)] {
			continue
		}
		profile := filepath.Join(usersDir, name)
		out = append(out, UserProfile{
			Username:    name,
			ProfilePath: profile,
			NTUser:      filepath.Join(profile, "NTUSER.DAT"),
			UsrClass:    filepath.Join(profile, `AppData\Local\Microsoft\Windows\UsrClass.dat`),
		})
	}
	return out
}

// SystemRoot returns the Windows directory (C:\Windows).
func SystemRoot(osi *core.OSInfo) string {
	if osi != nil && osi.SystemRoot != "" {
		return osi.SystemRoot
	}
	return `C:\Windows`
}

// SystemDrive returns the system drive (C:).
func SystemDrive(osi *core.OSInfo) string {
	if osi != nil && osi.SystemDrive != "" {
		return osi.SystemDrive
	}
	return "C:"
}

// Win32 returns C:\Windows\System32.
func Win32(osi *core.OSInfo) string { return filepath.Join(SystemRoot(osi), "System32") }

// ConfigDir returns the registry hive directory.
func ConfigDir(osi *core.OSInfo) string { return filepath.Join(Win32(osi), "config") }

// ProgramData returns the ProgramData path.
func ProgramData(osi *core.OSInfo) string { return SystemDrive(osi) + `\ProgramData` }

// Exists reports whether a path exists (best effort, ignores permission errors).
func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Join is a convenience wrapper.
func Join(parts ...string) string { return filepath.Join(parts...) }

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
