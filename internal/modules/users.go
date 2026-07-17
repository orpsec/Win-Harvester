package modules

import (
	"context"
	"path/filepath"
	"time"

	"github.com/winharvest/winharvest/internal/collect"
	"github.com/winharvest/winharvest/internal/core"
)

// usersModule collects per-user shell artifacts and cloud-storage sync metadata.
type usersModule struct{}

func (usersModule) Name() string        { return "users" }
func (usersModule) Category() string    { return "Users" }
func (usersModule) Description() string { return "Recent, shell folders, clipboard, OneDrive/GDrive/Dropbox metadata" }

func (m usersModule) Collect(ctx context.Context, cc *core.Context) (*core.ModuleResult, error) {
	h := collect.New(cc, m.Name(), m.Category())

	for _, u := range collect.EnumerateUserProfiles(cc.OS) {
		app := filepath.Join(u.ProfilePath, "AppData")

		// Recent items (LNK targets resolve to opened files).
		h.CopyTree(filepath.Join(app, `Roaming\Microsoft\Windows\Recent`), nil)

		// Clipboard history (Win10 1809+, when enabled).
		h.CopyTree(filepath.Join(app, `Local\Microsoft\Windows\Clipboard`), nil)

		// Sticky Notes (often contains credentials/notes).
		h.CopyFile(filepath.Join(app, `Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`))

		// OneDrive sync metadata & logs.
		h.CopyTree(filepath.Join(app, `Local\Microsoft\OneDrive\logs`), func(n string) bool {
			return filepath.Ext(n) == ".log" || filepath.Ext(n) == ".odl" || filepath.Ext(n) == ".odlgz"
		})
		h.CopyTree(filepath.Join(app, `Local\Microsoft\OneDrive\settings`), nil)

		// Google Drive (Drive File Stream / Backup and Sync) metadata.
		h.CopyTree(filepath.Join(app, `Local\Google\DriveFS`), func(n string) bool {
			return filepath.Ext(n) == ".db" || filepath.Ext(n) == ".sqlite" || n == "metadata_sqlite_db"
		})

		// Dropbox metadata.
		h.CopyTree(filepath.Join(u.ProfilePath, ".dropbox"), nil)
		h.CopyTree(filepath.Join(app, `Local\Dropbox`), func(n string) bool {
			return filepath.Ext(n) == ".dbx" || filepath.Ext(n) == ".db"
		})

		// Capture the existence of standard shell folders for the report.
		for _, sf := range []string{"Desktop", "Downloads", "Documents", "Pictures"} {
			p := filepath.Join(u.ProfilePath, sf)
			if collect.Exists(p) {
				h.Note("user %s has %s", u.Username, sf)
			}
		}
	}

	// Live clipboard contents snapshot (text only).
	h.PowerShellToFile(ctx, "clipboard_current.txt", 30*time.Second, `Get-Clipboard 2>$null`)

	return h.Result(), nil
}

func init() { core.Register(usersModule{}) }
