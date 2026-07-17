package core

// OSInfo describes the host operating system and the resolved artifact paths.
// It is populated once at startup and shared (read-only) with all collectors.
type OSInfo struct {
	ProductName    string `json:"product_name"`     // e.g. "Windows 10 Pro"
	DisplayVersion string `json:"display_version"`  // e.g. "22H2"
	ReleaseID      string `json:"release_id"`       // e.g. "2009"
	BuildNumber    string `json:"build_number"`     // e.g. "19045"
	UBR            string `json:"ubr"`              // update build revision
	IsWindows11    bool   `json:"is_windows_11"`    // build >= 22000
	Architecture   string `json:"architecture"`     // amd64, arm64...
	SystemRoot     string `json:"system_root"`      // C:\Windows
	SystemDrive    string `json:"system_drive"`     // C:
	Hostname       string `json:"hostname"`
	InstallDate    string `json:"install_date"`
	RegisteredOrg  string `json:"registered_org,omitempty"`
}

// Win11 reports whether the host is Windows 11 based on the build number.
func (o *OSInfo) Win11() bool { return o.IsWindows11 }

// VersionString is a compact human readable version label.
func (o *OSInfo) VersionString() string {
	if o == nil {
		return "unknown"
	}
	s := o.ProductName
	if o.DisplayVersion != "" {
		s += " " + o.DisplayVersion
	}
	if o.BuildNumber != "" {
		s += " (build " + o.BuildNumber
		if o.UBR != "" {
			s += "." + o.UBR
		}
		s += ")"
	}
	return s
}
