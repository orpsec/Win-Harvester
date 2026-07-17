package modules

import (
	"context"
	"encoding/json"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// systemModule collects host identity and hardware/configuration facts.
type systemModule struct{}

func (systemModule) Name() string        { return "system" }
func (systemModule) Category() string    { return "System" }
func (systemModule) Description() string { return "Host identity, hardware, OS, BitLocker, VM detection" }

func (m systemModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())

	// Persist the detected OS info first (always available, even off-box parse).
	if b, err := json.MarshalIndent(cc.OS, "", "  "); err == nil {
		h.SaveText("osinfo.json", string(b))
	}

	// Each command is saved to its own file for analyst convenience. PowerShell
	// CIM classes give structured, parseable output without native API code.
	type q struct {
		file   string
		script string
	}
	queries := []q{
		{"computersystem.txt", `Get-CimInstance Win32_ComputerSystem | Format-List *`},
		{"operatingsystem.txt", `Get-CimInstance Win32_OperatingSystem | Format-List *`},
		{"bios.txt", `Get-CimInstance Win32_BIOS | Format-List *`},
		{"baseboard.txt", `Get-CimInstance Win32_BaseBoard | Format-List *`},
		{"processor.txt", `Get-CimInstance Win32_Processor | Format-List *`},
		{"memory.txt", `Get-CimInstance Win32_PhysicalMemory | Format-List *`},
		{"disks.txt", `Get-CimInstance Win32_DiskDrive | Format-List *`},
		{"partitions.txt", `Get-CimInstance Win32_DiskPartition | Format-List *`},
		{"logicaldisks.txt", `Get-CimInstance Win32_LogicalDisk | Format-List *`},
		{"volumes.txt", `Get-CimInstance Win32_Volume | Format-List *`},
		{"timezone.txt", `Get-TimeZone | Format-List *; Get-CimInstance Win32_TimeZone | Format-List *`},
		{"computerinfo.txt", `Get-ComputerInfo | Format-List *`},
		{"hotfixes.txt", `Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -Auto`},
		{"localusers.txt", `Get-LocalUser | Format-List *`},
		{"localgroups.txt", `Get-LocalGroup | Format-List *; foreach($g in Get-LocalGroup){"=== "+$g.Name+" ===";Get-LocalGroupMember $g.Name 2>$null}`},
		{"bitlocker.txt", `Get-BitLockerVolume 2>$null | Format-List *; manage-bde -status 2>$null`},
		{"secureboot.txt", `Confirm-SecureBootUEFI 2>$null`},
		{"tpm.txt", `Get-Tpm 2>$null | Format-List *`},
		{"hyperv.txt", `Get-CimInstance Win32_ComputerSystem | Select HypervisorPresent; Get-WindowsOptionalFeature -Online -FeatureName *Hyper* 2>$null | Format-Table`},
		{"environment.txt", `Get-ChildItem Env: | Format-Table -Auto`},
		{"systeminfo.txt", `systeminfo`},
		{"whoami.txt", `whoami /all`},
	}
	for _, qq := range queries {
		h.PowerShellToFile(ctx, qq.file, 60*time.Second, qq.script)
	}

	// Machine SID (derived from a local account RID-stripped SID).
	h.PowerShellToFile(ctx, "machine_sid.txt", 30*time.Second,
		`$s=(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Select -First 1).SID; if($s){$s.Substring(0,$s.LastIndexOf('-'))}`)

	// VM detection heuristic from manufacturer/model strings.
	h.PowerShellToFile(ctx, "vm_detection.txt", 30*time.Second, vmDetectScript)

	// Uptime / last boot.
	h.PowerShellToFile(ctx, "uptime.txt", 30*time.Second,
		`$os=Get-CimInstance Win32_OperatingSystem; "LastBootUpTime: "+$os.LastBootUpTime; "Uptime: "+((Get-Date)-$os.LastBootUpTime)`)

	h.Note("collected %d system query files", len(queries)+4)
	return h.Result(), nil
}

const vmDetectScript = `
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$indicators = @()
$hay = "$($cs.Manufacturer) $($cs.Model) $($bios.SerialNumber) $($bios.Manufacturer)".ToLower()
foreach($k in @("vmware","virtualbox","vbox","qemu","kvm","xen","hyper-v","microsoft corporation virtual","parallels","bochs","innotek")){
  if($hay.Contains($k)){ $indicators += $k }
}
"Manufacturer: $($cs.Manufacturer)"
"Model: $($cs.Model)"
"BIOS: $($bios.Manufacturer) $($bios.SerialNumber)"
if($indicators.Count -gt 0){ "VIRTUAL MACHINE LIKELY. Indicators: " + ($indicators -join ", ") } else { "No VM indicators found (likely physical)." }
`

func init() { core.Register(systemModule{}) }
