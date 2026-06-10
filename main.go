package main

import (
	"embed"
	"log"
	"os" // Обязательно добавляем пакет os для экстренного закрытия программы
	"password-saver/antidebug"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// МГНОВЕННЫЙ АУДИТ СРЕДЫ ЗАПУСКА
	// Проверяем наличие отладчика до того, как загрузится интерфейс
	if antidebug.Check() {
		os.Exit(1) // Убиваем процесс без лишних окон и логов
	}

	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "password-saver",
		Width:  1024,
		Height: 768,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		log.Fatal(err)
	}
}
