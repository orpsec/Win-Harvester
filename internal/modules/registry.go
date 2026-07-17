package modules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
	"github.com/winharvest/winharvest/internal/parsers/regf"
)

// registryModule copies the raw registry hives (with their transaction logs and
// RegBack copies) and additionally exports the high-value forensic keys to text
// so analysts get immediate, greppable artifacts.
type registryModule struct{}

func (registryModule) Name() string        { return "registry" }
func (registryModule) Category() string    { return "Registry" }
func (registryModule) Description() string { return "System/user hives, RegBack, transaction logs, key artifacts" }

func (m registryModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	cfgDir := collect.ConfigDir(cc.OS)

	// 1) System hives + their transaction logs.
	hives := []string{"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"}
	for _, hv := range hives {
		base := filepath.Join(cfgDir, hv)
		h.CopyFile(base)
		// Transaction logs and clean-shutdown markers.
		for _, ext := range []string{".LOG", ".LOG1", ".LOG2"} {
			h.CopyFile(base + ext)
		}
	}

	// 2) RegBack copies (often present, sometimes empty on modern Win10/11).
	h.CopyGlob(filepath.Join(cfgDir, "RegBack", "*"))

	// 3) Per-user hives: NTUSER.DAT and UsrClass.dat plus their logs.
	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		for _, p := range []string{u.NTUser, u.UsrClass} {
			h.CopyFile(p)
			for _, ext := range []string{".LOG1", ".LOG2"} {
				h.CopyFile(p + ext)
			}
		}
	}

	// 4) Amcache.hve (program execution evidence) lives under AppCompat.
	amcache := filepath.Join(collect.Win32(cc.OS), "config", "..", "AppCompat", "Programs", "Amcache.hve")
	h.CopyFile(filepath.Clean(amcache))
	for _, ext := range []string{".LOG1", ".LOG2"} {
		h.CopyFile(filepath.Clean(amcache) + ext)
	}

	// 5) Export high-value keys to text for immediate analysis. reg.exe reads
	//    the live registry read-only.
	m.exportKeys(ctx, h)

	// 6) Parse the collected hives natively into readable JSON (parsed/).
	m.parseHives(h)

	return h.Result(), nil
}

// parseHives decodes the raw hive copies into analyst/AI-readable JSON.
func (m registryModule) parseHives(h *collect.Helper) {
	h.WalkCollected(nil, func(path string) {
		name := strings.ToLower(filepath.Base(path))
		switch name {
		case "system":
			m.parseSystemHive(h, path)
		case "ntuser.dat":
			m.parseNTUser(h, path)
		}
	})
}

func (m registryModule) parseSystemHive(h *collect.Helper, path string) {
	root, ok := openHiveRoot(path)
	if !ok {
		return
	}
	if shim := regf.ShimCache(root); len(shim) > 0 {
		h.SaveJSON("shimcache.json", shim)
		for _, e := range shim {
			h.Timeline(core.TimelineEvent{
				Timestamp: e.LastModified, Source: "ShimCache", EventType: "Execution",
				Module: "registry", Description: e.Path,
			})
		}
		h.Note("parsed ShimCache -> %d entries", len(shim))
	}
	if usb := regf.USBStor(root); len(usb) > 0 {
		h.SaveJSON("usbstor.json", usb)
		for _, d := range usb {
			h.Timeline(core.TimelineEvent{
				Timestamp: d.LastWritten, Source: "Registry", EventType: "USBDevice",
				Module: "registry", Description: d.DeviceClass, Details: "serial=" + d.SerialNumber,
			})
		}
		h.Note("parsed USBSTOR -> %d devices", len(usb))
	}
}

func (m registryModule) parseNTUser(h *collect.Helper, path string) {
	root, ok := openHiveRoot(path)
	if !ok {
		return
	}
	// Derive the username from the stored relative path (.../Users/<name>/NTUSER.DAT).
	user := userFromPath(path)
	if ua := regf.UserAssist(root); len(ua) > 0 {
		h.SaveJSON("userassist_"+user+".json", ua)
		for _, e := range ua {
			if e.LastRun.IsZero() {
				continue
			}
			h.Timeline(core.TimelineEvent{
				Timestamp: e.LastRun, Source: "UserAssist", EventType: "Execution",
				Module: "registry", Description: e.Name,
				Details: "user=" + user + " run_count=" + itoa(int(e.RunCount)),
			})
		}
		h.Note("parsed UserAssist for %s -> %d entries", user, len(ua))
	}
}

func openHiveRoot(path string) (*regf.Key, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	hive, err := regf.Open(data)
	if err != nil {
		return nil, false
	}
	root, err := hive.Root()
	if err != nil {
		return nil, false
	}
	return root, true
}

func userFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if strings.EqualFold(p, "Users") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "user"
}

// exportKeys dumps forensically important registry keys with `reg query /s`.
func (m registryModule) exportKeys(ctx context.Context, h *collect.Helper) {
	keys := map[string]string{
		"run.txt":               `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"runonce.txt":           `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		"run_wow64.txt":         `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
		"services.txt":          `HKLM\SYSTEM\CurrentControlSet\Services`,
		"bam.txt":               `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`,
		"dam.txt":               `HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings`,
		"shimcache.txt":         `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
		"usbstor.txt":           `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`,
		"usb.txt":               `HKLM\SYSTEM\CurrentControlSet\Enum\USB`,
		"mounteddevices.txt":    `HKLM\SYSTEM\MountedDevices`,
		"network_profiles.txt":  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`,
		"network_signatures.txt": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures`,
		"installed_software.txt": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		"installed_wow64.txt":   `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		"firewall_rules.txt":    `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`,
		"winlogon.txt":          `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		"lsa.txt":               `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
		"credential_providers.txt": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`,
		"defender.txt":          `HKLM\SOFTWARE\Microsoft\Windows Defender`,
		"timezone.txt":          `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`,
		"appcompatflags.txt":    `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`,
		"ifeo.txt":              `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		"appinit_dlls.txt":      `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		"knowndlls.txt":         `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
		"profilelist.txt":       `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`,
		"computername.txt":      `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`,
	}
	for file, key := range keys {
		h.RunToFile(ctx, "exported/"+file, 45*time.Second, "reg", "query", key, "/s")
	}

	// HKCU per-user artifacts require loading each NTUSER hive; we instead export
	// the live HKCU (current user) and note that per-user hives are collected raw.
	hkcu := map[string]string{
		"hkcu_run.txt":         `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"hkcu_runonce.txt":     `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		"hkcu_userassist.txt":  `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`,
		"hkcu_typedurls.txt":   `HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs`,
		"hkcu_typedpaths.txt":  `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`,
		"hkcu_recentdocs.txt":  `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`,
		"hkcu_opensavemru.txt": `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`,
		"hkcu_lastvisited.txt": `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`,
		"hkcu_mountpoints2.txt": `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`,
		"hkcu_muicache.txt":    `HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`,
		"hkcu_shellbags.txt":   `HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags`,
		"hkcu_shellbagmru.txt": `HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU`,
	}
	for file, key := range hkcu {
		h.RunToFile(ctx, "exported/current_user/"+file, 45*time.Second, "reg", "query", key, "/s")
	}
	h.Note("exported %d HKLM and %d HKCU registry artifact keys", len(keys), len(hkcu))
}

func init() { core.Register(registryModule{}) }
