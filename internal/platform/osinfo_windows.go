//go:build windows

package platform

import (
	"os"
	"strconv"

	"github.com/winharvest/winharvest/internal/core"
	"golang.org/x/sys/windows/registry"
)

// DetectOS reads the live registry to identify the Windows version and resolve
// the canonical artifact paths. Windows 11 is distinguished from Windows 10 by
// build number (>= 22000), since both report ProductName "Windows 10" in the
// CurrentVersion key.
func DetectOS() (*core.OSInfo, error) {
	osi := &core.OSInfo{
		Architecture: archString(),
		SystemRoot:   envOr("SystemRoot", `C:\Windows`),
		SystemDrive:  envOr("SystemDrive", "C:"),
	}
	osi.Hostname, _ = os.Hostname()

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return osi, err
	}
	defer k.Close()

	osi.ProductName, _, _ = k.GetStringValue("ProductName")
	osi.DisplayVersion, _, _ = k.GetStringValue("DisplayVersion")
	osi.ReleaseID, _, _ = k.GetStringValue("ReleaseId")
	osi.BuildNumber, _, _ = k.GetStringValue("CurrentBuildNumber")
	osi.RegisteredOrg, _, _ = k.GetStringValue("RegisteredOrganization")
	if ubr, _, e := k.GetIntegerValue("UBR"); e == nil {
		osi.UBR = strconv.FormatUint(ubr, 10)
	}
	if id, _, e := k.GetStringValue("InstallDate"); e == nil {
		osi.InstallDate = id
	}

	if b, err := strconv.Atoi(osi.BuildNumber); err == nil && b >= 22000 {
		osi.IsWindows11 = true
		// Normalize the product name which still says "Windows 10" in registry.
		if len(osi.ProductName) >= 10 && osi.ProductName[:10] == "Windows 10" {
			osi.ProductName = "Windows 11" + osi.ProductName[10:]
		}
	}
	return osi, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func archString() string {
	switch v := os.Getenv("PROCESSOR_ARCHITECTURE"); v {
	case "AMD64":
		return "amd64"
	case "ARM64":
		return "arm64"
	case "x86":
		return "386"
	default:
		return v
	}
}
