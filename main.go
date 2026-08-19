package main

import (
	"context"
	"embed"
	"log"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/mihanistudio/mihanisecurity/internal/app"
	"github.com/mihanistudio/mihanisecurity/internal/events"
	"github.com/mihanistudio/mihanisecurity/internal/ipc"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	a := app.New()
	err := wails.Run(&options.App{
		Title:			"MihaniSecurity",
		Width:			1100,
		Height:			760,
		MinWidth:		980,
		MinHeight:		640,
		DisableResize:		false,
		Fullscreen:		false,
		Frameless:		true,
		StartHidden:		false,
		HideWindowOnClose:	false,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour:	&options.RGBA{R: 18, G: 4, B: 6, A: 1},
		OnStartup: func(ctx context.Context) {

			a.Init(ctx,
				func(v events.Verdict) { runtime.EventsEmit(ctx, "verdict", v) },
				func(p events.ScanProgress) { runtime.EventsEmit(ctx, "scan_progress", p) },
				func(r *ipc.ScanResult) { runtime.EventsEmit(ctx, "scan_result", r) },
				func(s events.Status) { runtime.EventsEmit(ctx, "status", s) },
			)

			if err := a.Connect(); err != nil {
				log.Println("ipc connect:", err)
			}
		},
		OnShutdown:	func(ctx context.Context) { a.Disconnect() },
		Bind:		[]interface{}{a},
		Windows: &windows.Options{
			WebviewIsTransparent:			false,
			WindowIsTranslucent:			false,
			DisableWindowIcon:			false,
			DisableFramelessWindowDecorations:	false,
			WebviewUserDataPath:			wailsUserData(),
		},
	})
	if err != nil {
		log.Println("wails run:", err)
		os.Exit(1)
	}
}

func wailsUserData() string {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "MihaniSecurity", "WebView2")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}
