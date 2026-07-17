package modules

import (
	"context"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// persistenceModule consolidates the common autostart/persistence locations
// into one report, complementing the raw hives & service collection.
type persistenceModule struct{}

func (persistenceModule) Name() string        { return "persistence" }
func (persistenceModule) Category() string    { return "System" }
func (persistenceModule) Description() string { return "ASEPs: Run keys, IFEO, AppInit, COM, Winlogon, BITS, startup folders" }

func (m persistenceModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	t := 60 * time.Second

	keys := map[string]string{
		"run_hklm.txt":            `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"runonce_hklm.txt":        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		"run_policies.txt":        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		"run_hkcu.txt":            `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"runonce_hkcu.txt":        `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		"winlogon.txt":            `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		"userinit_shell.txt":      `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		"ifeo.txt":                `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		"appinit_dlls.txt":        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		"appcertdlls.txt":         `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`,
		"knowndlls.txt":           `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
		"silentprocessexit.txt":   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`,
		"bootexecute.txt":         `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`,
		"lsa_packages.txt":        `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
		"netsh_helpers.txt":       `HKLM\SOFTWARE\Microsoft\Netsh`,
		"com_hijack_hkcu.txt":     `HKCU\SOFTWARE\Classes\CLSID`,
		"shellext_approved.txt":   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`,
		"contextmenu_handlers.txt": `HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers`,
		"explorer_shellfolders.txt": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`,
		"activesetup.txt":         `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`,
		"winsock_lsp.txt":         `HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters`,
		"font_drivers.txt":        `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\FontDrivers`,
		"print_monitors.txt":      `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`,
		"lsa_notification.txt":    `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`,
		"gpoextensions.txt":       `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions`,
	}
	for f, k := range keys {
		h.RunToFile(ctx, "registry_aseps/"+f, t, "reg", "query", k, "/s")
	}

	// Startup folders (machine + per-user).
	progData := collect.ProgramData(cc.OS)
	h.CopyTree(filepath.Join(progData, `Microsoft\Windows\Start Menu\Programs\StartUp`), nil)
	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		h.CopyTree(filepath.Join(u.ProfilePath, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), nil)
	}

	// BITS jobs (download persistence).
	h.RunToFile(ctx, "bits_jobs.txt", t, "powershell.exe", "-NoProfile", "-Command",
		`Get-BitsTransfer -AllUsers 2>$null | Format-List *; bitsadmin /list /allusers /verbose 2>$null`)

	// Office add-ins (per-user, common persistence).
	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		h.CopyTree(filepath.Join(u.ProfilePath, `AppData\Roaming\Microsoft\AddIns`), nil)
		h.CopyTree(filepath.Join(u.ProfilePath, `AppData\Roaming\Microsoft\Word\STARTUP`), nil)
		h.CopyTree(filepath.Join(u.ProfilePath, `AppData\Roaming\Microsoft\Excel\XLSTART`), nil)
	}

	// Autoruns-style consolidated WMI Startup commands.
	h.PowerShellToFile(ctx, "startup_commands.txt", t,
		`Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User | Format-List`)

	h.Note("collected %d ASEP registry locations + startup folders + BITS + Office add-ins", len(keys))
	return h.Result(), nil
}

func init() { core.Register(persistenceModule{}) }
