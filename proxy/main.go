package main

import (
	"fmt"
	_ "test/docs"

	"github.com/joho/godotenv"
	_ "net/http/pprof"
)

// @title ГеоAPI
// @version 1.0
// @description Поиск информации по адресу или координатам.

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apiKey ApiKeyAuth
// @in header
// @name Authorization

func main() {
	// Загружаем переменные окружения из файла .env
	err := godotenv.Load()
	if err != nil {
		fmt.Println(err)
		return
	}
	NewServer(":8080", "hugo", "1313").Serve()

}
