package main

import (
	"erebor/internal/util"
	"fmt"

	"erebor/internal/gateway"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/pkg/config"
)

func main() {

	// set logging to json format for application
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(jsonHandler).With(
		slog.String(util.ServiceKey, util.ServiceGateway),
	))

	// set up logger for main
	logger := slog.Default().
		With(slog.String(util.PackageKey, util.PackageMain)).
		With(slog.String(util.ComponentKey, util.ComponentMain))

	// service definition
	def := config.SvcDefinition{
		ServiceName: util.ServiceGateway,
		Tls:         config.StandardTls,
		Requires: config.Requires{
			S2sClient:        true,
			Db:               true,
			IndexSecret:      true,
			AesSecret:        true,
			S2sSigningKey:    false,
			S2sVerifyingKey:  false,
			Identity:         true,
			UserSigningKey:   false,
			UserVerifyingKey: true,
			OauthRedirect:    true,
			Tasks:            true,
			Gallery:          true,
		},
	}

	config, err := config.Load(def)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to load %s config", def.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	gateway, err := gateway.New(config)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create %s gateway", config.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	defer gateway.CloseDb()

	if err := gateway.Run(); err != nil {
		logger.Error(fmt.Sprintf("failed to run %s gateway", config.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	select {}
}
