package main

import (
	"erebor/internal/util"

	"erebor/pkg/gateway"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/pkg/config"
)

func main() {

	logger := slog.Default().With(slog.String(util.ComponentKey, util.ComponentMain))

	config, err := config.Load("erebor")
	if err != nil {
		logger.Error("Failed to load Erebor config: %v", err)
		os.Exit(1)
	}

	gateway, err := gateway.New(*config)
	if err != nil {
		logger.Error("Failed to create Erebor Gateway: %v", err)
		os.Exit(1)
	}

	defer gateway.CloseDb()

	if err := gateway.Run(); err != nil {
		logger.Error("Failed to run Erebor Gateway: %v", err)
		os.Exit(1)
	}

	select {}
}
