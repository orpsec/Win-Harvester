package modules

import (
	"context"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// usbModule collects USB device history: USBSTOR/USB enumeration, MountedDevices,
// SetupAPI device install logs and portable-device records.
type usbModule struct{}

func (usbModule) Name() string        { return "usb" }
func (usbModule) Category() string    { return "USB" }
func (usbModule) Description() string { return "USBSTOR, MountedDevices, SetupAPI logs, portable devices" }

func (m usbModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	win := collect.SystemRoot(cc.OS)

	// SetupAPI device install log — first-insert timestamps per device.
	h.CopyFile(filepath.Join(win, "INF", "setupapi.dev.log"))
	h.CopyGlob(filepath.Join(win, "INF", "setupapi.dev.*.log"))
	h.CopyGlob(filepath.Join(win, "INF", "setupapi.setup.log"))

	// Registry-based USB history exports.
	keys := map[string]string{
		"usbstor.txt":          `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`,
		"usb.txt":              `HKLM\SYSTEM\CurrentControlSet\Enum\USB`,
		"scsi.txt":             `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI`,
		"mounteddevices.txt":   `HKLM\SYSTEM\MountedDevices`,
		"portable_devices.txt": `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`,
		"volume_info.txt":      `HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`,
		"diskclasses.txt":      `HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`,
		"emdmgmt.txt":          `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`,
	}
	for f, k := range keys {
		h.RunToFile(ctx, "exported/"+f, 60*time.Second, "reg", "query", k, "/s")
	}

	// Live PnP device inventory (cross-reference for currently attached devices).
	h.PowerShellToFile(ctx, "pnp_devices.txt", 90*time.Second,
		`Get-PnpDevice 2>$null | Where-Object {$_.InstanceId -match 'USB'} | Select Status,Class,FriendlyName,InstanceId | Format-Table -Auto`)

	return h.Result(), nil
}

func init() { core.Register(usbModule{}) }
