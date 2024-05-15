package main

import (
	"erebor/pkg/config"
	"erebor/pkg/gateway"
	"log"
)

func main() {

	config := config.Load("erebor")

	gateway, err := gateway.New(*config)
	if err != nil {
		log.Fatalf("Failed to create Erebor Gateway: %v", err)
	}

	if err := gateway.Run(); err != nil {
		log.Fatalf("Failed to run Erebor Gateway: %v", err)
	}

	select{}
}
