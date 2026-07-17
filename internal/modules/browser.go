package modules

import (
	"context"
	"path/filepath"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// browserModule collects artifacts from Chromium-family browsers (Chrome, Edge,
// Brave, Opera) and Firefox for every user profile.
type browserModule struct{}

func (browserModule) Name() string        { return "browser" }
func (browserModule) Category() string    { return "Browser" }
func (browserModule) Description() string { return "Chrome/Edge/Brave/Opera/Firefox history, cookies, logins, etc." }

// chromiumArtifacts are the per-profile SQLite/JSON files of interest.
var chromiumArtifacts = []string{
	"History", "Archived History", "Downloads", "Cookies", "Network/Cookies",
	"Login Data", "Login Data For Account", "Web Data", "Bookmarks",
	"Favicons", "Top Sites", "Shortcuts", "Visited Links",
	"Preferences", "Secure Preferences", "Network Action Predictor",
	"Current Session", "Current Tabs", "Last Session", "Last Tabs",
}

// chromiumBrowsers maps a label to its user-data root relative to a profile.
var chromiumBrowsers = map[string]string{
	"Chrome":        `AppData\Local\Google\Chrome\User Data`,
	"Edge":          `AppData\Local\Microsoft\Edge\User Data`,
	"Brave":         `AppData\Local\BraveSoftware\Brave-Browser\User Data`,
	"Opera":         `AppData\Roaming\Opera Software\Opera Stable`,
	"OperaGX":       `AppData\Roaming\Opera Software\Opera GX Stable`,
	"ChromeBeta":    `AppData\Local\Google\Chrome Beta\User Data`,
	"Vivaldi":       `AppData\Local\Vivaldi\User Data`,
	"Chromium":      `AppData\Local\Chromium\User Data`,
}

func (m browserModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())

	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		for label, rel := range chromiumBrowsers {
			root := filepath.Join(u.ProfilePath, rel)
			if !collect.Exists(root) {
				continue
			}
			m.collectChromium(h, u.Username, label, root)
		}
		m.collectFirefox(h, u)
	}
	return h.Result(), nil
}

func (m browserModule) collectChromium(h *collect.Helper, user, label, root string) {
	// Profile directories: "Default", "Profile 1", ... plus root-level files.
	profiles := []string{"Default"}
	if entries, err := filepathGlobDirs(filepath.Join(root, "Profile *")); err == nil {
		profiles = append(profiles, entries...)
	}
	// Opera stores artifacts at the root with no "Default" subfolder.
	profiles = append(profiles, ".")

	for _, prof := range profiles {
		base := filepath.Join(root, prof)
		if !collect.Exists(base) {
			continue
		}
		for _, art := range chromiumArtifacts {
			h.CopyFile(filepath.Join(base, art))
		}
		// Extensions (manifest + metadata, not full payloads of huge size).
		h.CopyTree(filepath.Join(base, "Extensions"), func(n string) bool {
			return n == "manifest.json" || filepath.Ext(n) == ".json"
		})
		// Local Storage / IndexedDB / Service Workers / Sessions metadata.
		h.CopyTree(filepath.Join(base, "Local Storage"), nil)
		h.CopyTree(filepath.Join(base, "IndexedDB"), nil)
		h.CopyTree(filepath.Join(base, "Service Worker"), func(n string) bool {
			return filepath.Ext(n) == ".ldb" || filepath.Ext(n) == ".log" || n == "current"
		})
		h.CopyTree(filepath.Join(base, "Sessions"), nil)
	}
	h.Note("collected %s artifacts for user %s", label, user)
}

func (m browserModule) collectFirefox(h *collect.Helper, u collect.UserProfile) {
	ffRoot := filepath.Join(u.ProfilePath, `AppData\Roaming\Mozilla\Firefox\Profiles`)
	if !collect.Exists(ffRoot) {
		return
	}
	files := []string{
		"places.sqlite",      // history + bookmarks + downloads
		"cookies.sqlite",
		"formhistory.sqlite",
		"logins.json",        // saved credentials (encrypted)
		"key4.db",            // credential decryption key
		"permissions.sqlite",
		"favicons.sqlite",
		"sessionstore.jsonlz4",
		"prefs.js",
		"extensions.json",
		"addons.json",
		"webappsstore.sqlite",
		"content-prefs.sqlite",
	}
	dirs, _ := filepathGlobDirs(filepath.Join(ffRoot, "*"))
	for _, d := range dirs {
		for _, f := range files {
			h.CopyFile(filepath.Join(d, f))
		}
		h.CopyTree(filepath.Join(d, "sessionstore-backups"), nil)
		h.CopyTree(filepath.Join(d, "storage", "default"), func(n string) bool {
			return filepath.Ext(n) == ".sqlite" || filepath.Ext(n) == ".js"
		})
	}
	h.Note("collected Firefox artifacts for user %s", u.Username)
}

// filepathGlobDirs returns directory matches for a glob pattern.
func filepathGlobDirs(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range matches {
		if collect.Exists(m) {
			out = append(out, m)
		}
	}
	return out, nil
}

func init() { core.Register(browserModule{}) }
