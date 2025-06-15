/*
'prac' es una base para el desarrollo de prácticas en clase con Go.

se puede compilar con "go build" en el directorio donde resida main.go

versión: 1.0
curso: 			2024-2025
asignatura: 	Seguridad y Confidencialidad
estudiantes: 	Esther Adeyemi y Sebastián Hernández
*/
package main

import (
	"log"
	"os"
	"time"

	"prac/pkg/client"
	"prac/pkg/server"
	"prac/pkg/ui"

	"github.com/joho/godotenv"
)

var jwtSecret []byte //La clave que se usará para firmar los tokens JWT

func main() {

	// Cargar las variables desde el .env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error al cargar .env")
	}

	// Leer la clave
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET no está definida")
	}
	jwtSecret = []byte(secret)
	log.Println("Clave secreta cargada correctamente.")

	// Creamos un logger con prefijo 'main' para identificar
	// los mensajes en la consola.
	log := log.New(os.Stdout, "[main] ", log.LstdFlags)

	// Inicia servidor en goroutine.
	log.Println("Iniciando servidor...")
	started := make(chan struct{})
	go func() {
		if err := server.Run(started); err != nil {
			log.Fatalf("Error del servidor: %v\n", err)
		}
	}()
	<-started //Con esta instrucción esperamos a que el servidor termine de iniciarse anets de iniciar el cliente--> se hace porque al principio el cliente se hace en la terminal
	log.Println("Servidor listo, iniciando cliente...")
	// Esperamos un tiempo prudencial a que arranque el servidor.
	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	// Inicia cliente.
	log.Println("Iniciando cliente...")
	client.Run()
}
