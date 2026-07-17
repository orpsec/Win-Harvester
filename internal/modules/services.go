package modules

import (
	"context"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// servicesModule enumerates services and drivers with their image paths,
// ServiceDLLs and failure actions — common persistence and tampering vectors.
type servicesModule struct{}

func (servicesModule) Name() string        { return "services" }
func (servicesModule) Category() string    { return "Services" }
func (servicesModule) Description() string { return "Services, drivers, ImagePath, ServiceDLL, FailureActions" }

func (m servicesModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())

	// Full services registry tree (authoritative: ImagePath, Start, Type, DLL).
	h.RunToFile(ctx, "services_registry.txt", 90*time.Second, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services`, "/s")

	// Structured service listing with binary paths and accounts.
	h.PowerShellToFile(ctx, "services.txt", 90*time.Second,
		`Get-CimInstance Win32_Service | Select Name,DisplayName,State,StartMode,StartName,PathName,ServiceType,Description | Format-List`)

	// Drivers (kernel & filesystem) — Win32_SystemDriver.
	h.PowerShellToFile(ctx, "drivers.txt", 90*time.Second,
		`Get-CimInstance Win32_SystemDriver | Select Name,DisplayName,State,StartMode,PathName,ServiceType | Format-List`)

	// driverquery gives signed/unsigned and module load info.
	h.RunToFile(ctx, "driverquery.csv", 90*time.Second, "driverquery", "/v", "/fo", "csv")
	h.RunToFile(ctx, "driverquery_signed.txt", 90*time.Second, "driverquery", "/si")

	// Failure actions and ServiceDLL extraction (recovery abuse / svchost groups).
	h.PowerShellToFile(ctx, "service_dll_and_failure.txt", 120*time.Second, serviceDeepScript)

	// sc.exe full dump as a cross-check.
	h.RunToFile(ctx, "sc_queryex.txt", 90*time.Second, "sc", "queryex", "type=", "service", "state=", "all")

	return h.Result(), nil
}

const serviceDeepScript = `
$base = 'HKLM:\SYSTEM\CurrentControlSet\Services'
Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
  $svc = $_.PSChildName
  $img = (Get-ItemProperty "$base\$svc" -ErrorAction SilentlyContinue).ImagePath
  $dll = (Get-ItemProperty "$base\$svc\Parameters" -ErrorAction SilentlyContinue).ServiceDll
  $fa  = (Get-ItemProperty "$base\$svc" -ErrorAction SilentlyContinue).FailureCommand
  if($img -or $dll -or $fa){
    "Service: $svc"
    if($img){ "  ImagePath: $img" }
    if($dll){ "  ServiceDll: $dll" }
    if($fa){  "  FailureCommand: $fa" }
  }
}
`

func init() { core.Register(servicesModule{}) }
