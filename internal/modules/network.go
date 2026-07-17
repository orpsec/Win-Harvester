package modules

import (
	"context"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// networkModule captures the live network state: connections, ARP/DNS caches,
// routing, configuration, Wi-Fi profiles, hosts file and proxy settings.
type networkModule struct{}

func (networkModule) Name() string        { return "network" }
func (networkModule) Category() string    { return "Network" }
func (networkModule) Description() string { return "Connections, ARP/DNS cache, routes, Wi-Fi/VPN, hosts, proxy" }

func (m networkModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())
	t := 60 * time.Second

	h.RunToFile(ctx, "ipconfig_all.txt", t, "ipconfig", "/all")
	h.RunToFile(ctx, "arp_cache.txt", t, "arp", "-a")
	h.RunToFile(ctx, "dns_cache.txt", t, "ipconfig", "/displaydns")
	h.RunToFile(ctx, "route_table.txt", t, "route", "print")
	h.RunToFile(ctx, "netstat_anob.txt", t, "netstat", "-anob")
	h.RunToFile(ctx, "netstat_routes.txt", t, "netstat", "-rn")
	h.RunToFile(ctx, "tcp_connections.txt", t, "powershell.exe", "-NoProfile", "-Command",
		`Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Sort State | Format-Table -Auto`)
	h.RunToFile(ctx, "udp_endpoints.txt", t, "powershell.exe", "-NoProfile", "-Command",
		`Get-NetUDPEndpoint | Select LocalAddress,LocalPort,OwningProcess,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Format-Table -Auto`)
	h.RunToFile(ctx, "smb_sessions.txt", t, "powershell.exe", "-NoProfile", "-Command",
		`Get-SmbSession 2>$null | Format-List *; Get-SmbConnection 2>$null | Format-List *; Get-SmbOpenFile 2>$null | Format-List *`)
	h.RunToFile(ctx, "netbios_sessions.txt", t, "nbtstat", "-S")

	// Wi-Fi profiles incl. clear-text keys (forensically valuable).
	h.RunToFile(ctx, "wifi_profiles.txt", t, "netsh", "wlan", "show", "profiles")
	h.RunToFile(ctx, "wifi_profiles_keys.txt", t, "netsh", "wlan", "show", "profiles", "key=clear")
	h.RunToFile(ctx, "wifi_interfaces.txt", t, "netsh", "wlan", "show", "interfaces")

	// Proxy / WinHTTP settings.
	h.RunToFile(ctx, "winhttp_proxy.txt", t, "netsh", "winhttp", "show", "proxy")
	h.RunToFile(ctx, "internet_settings.txt", t, "reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/s")

	// Firewall configuration & rules.
	h.RunToFile(ctx, "firewall_profiles.txt", t, "netsh", "advfirewall", "show", "allprofiles")
	h.RunToFile(ctx, "firewall_rules.txt", 120*time.Second, "netsh", "advfirewall", "firewall", "show", "rule", "name=all")

	// VPN / RAS connections.
	h.RunToFile(ctx, "vpn_connections.txt", t, "powershell.exe", "-NoProfile", "-Command",
		`Get-VpnConnection -AllUserConnection 2>$null | Format-List *; rasphone -? 2>$null; Get-VpnConnection 2>$null | Format-List *`)

	// hosts file (static DNS overrides — common malware tampering).
	h.CopyFile(filepath.Join(collect.Win32(cc.OS), "drivers", "etc", "hosts"))
	h.CopyFile(filepath.Join(collect.Win32(cc.OS), "drivers", "etc", "networks"))
	h.CopyFile(filepath.Join(collect.Win32(cc.OS), "drivers", "etc", "lmhosts.sam"))

	// Wi-Fi profile XMLs (BSSID/SSID history).
	h.CopyTree(collect.ProgramData(cc.OS)+`\Microsoft\Wlansvc\Profiles\Interfaces`, func(n string) bool {
		return filepath.Ext(n) == ".xml"
	})

	return h.Result(), nil
}

func init() { core.Register(networkModule{}) }
