//go:build windows

package platform

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/winharvest/winharvest/internal/core"
)

// VSS implements core.VSSResolver. It creates a single read-only Volume Shadow
// Copy of the target volume and routes locked-file reads through it. The shadow
// device path looks like:
//
//	\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
//
// Files under it are read-only point-in-time copies, ideal for SYSTEM/SAM hives,
// $MFT, registry, and event logs that are normally locked by the OS.
type VSS struct {
	log        core.Logger
	drive      string // e.g. "C:"
	deviceRoot string // e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
	shadowID   string
	available  bool
}

// NewVSS attempts to create a shadow copy of the given drive (e.g. `C:\`).
// On failure it returns a resolver in "unavailable" mode that simply passes
// live paths through.
func NewVSS(ctx context.Context, log core.Logger, targetVolume string, enabled bool) *VSS {
	v := &VSS{log: log, drive: strings.TrimRight(targetVolume, `\`)}
	if !enabled {
		log.Infof("VSS disabled by configuration")
		return v
	}
	if !IsElevated() {
		log.Warnf("VSS requires administrative privileges; falling back to live reads")
		return v
	}
	log.Infof("creating Volume Shadow Copy of %s (this can take up to a minute)...", v.drive)
	if err := v.create(ctx); err != nil {
		log.Warnf("could not create Volume Shadow Copy: %v (falling back to live reads)", err)
		return v
	}
	v.available = true
	log.Infof("created Volume Shadow Copy %s -> %s", v.shadowID, v.deviceRoot)
	return v
}

func (v *VSS) create(ctx context.Context) error {
	// Create the snapshot with the modern CIM stack. Get-WmiObject is deprecated
	// and can hang indefinitely on Windows 11 (24H2/25H2), so Invoke-CimMethod
	// is used instead. A hard timeout guarantees we never block the whole run.
	script := fmt.Sprintf(
		`$ErrorActionPreference='Stop';`+
			`$cls=Get-CimClass -ClassName Win32_ShadowCopy;`+
			`$r=Invoke-CimMethod -CimClass $cls -MethodName Create -Arguments @{Volume='%s\';Context='ClientAccessible'};`+
			`if($r.ReturnValue -ne 0){Write-Error ("ReturnValue="+$r.ReturnValue);exit 1};`+
			`$sc=Get-CimInstance Win32_ShadowCopy | Where-Object {$_.ID -eq $r.ShadowID};`+
			`Write-Output ($sc.ID + '|' + $sc.DeviceObject)`,
		v.drive)
	res := PowerShell(ctx, 120*time.Second, script)
	if res.Err != nil {
		return fmt.Errorf("%v: %s", res.Err, strings.TrimSpace(res.Stderr))
	}
	out := strings.TrimSpace(res.Stdout)
	parts := strings.SplitN(out, "|", 2)
	if len(parts) != 2 || parts[1] == "" {
		return fmt.Errorf("unexpected shadow create output: %q", out)
	}
	v.shadowID = parts[0]
	// DeviceObject is \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
	v.deviceRoot = strings.TrimRight(parts[1], `\`)
	return nil
}

// Available reports whether shadow fallback is usable.
func (v *VSS) Available() bool { return v.available }

// Resolve returns a readable path for livePath. It first attempts a live
// read-only open; only when that fails (sharing violation / lock) does it map
// the path into the shadow copy.
func (v *VSS) Resolve(livePath string) (string, bool, error) {
	if f, err := os.Open(livePath); err == nil {
		f.Close()
		return livePath, false, nil
	}
	if !v.available {
		// Re-open to surface the real error to the caller.
		_, err := os.Open(livePath)
		return livePath, false, err
	}
	shadow := v.mapToShadow(livePath)
	if f, err := os.Open(shadow); err == nil {
		f.Close()
		return shadow, true, nil
	} else {
		return shadow, true, err
	}
}

// mapToShadow rewrites C:\path\file -> <deviceRoot>\path\file.
func (v *VSS) mapToShadow(livePath string) string {
	rest := livePath
	if len(livePath) >= 2 && livePath[1] == ':' {
		rest = livePath[2:]
	}
	rest = strings.TrimPrefix(rest, `\`)
	return v.deviceRoot + `\` + rest
}

// Cleanup removes the shadow copy created by this resolver.
func (v *VSS) Cleanup(ctx context.Context) {
	if !v.available || v.shadowID == "" {
		return
	}
	script := fmt.Sprintf(
		`Get-CimInstance Win32_ShadowCopy | Where-Object {$_.ID -eq '%s'} | Remove-CimInstance`,
		v.shadowID)
	res := PowerShell(ctx, 30*time.Second, script)
	if res.Err != nil {
		v.log.Warnf("failed to delete shadow copy %s: %v", v.shadowID, res.Err)
		return
	}
	v.log.Infof("deleted Volume Shadow Copy %s", v.shadowID)
}

var _ core.VSSResolver = (*VSS)(nil)
