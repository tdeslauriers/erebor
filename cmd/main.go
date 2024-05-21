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

	// service definition
	def := config.SvcDefinition{
		Name: "erebor",
		Tls:  config.StandardTls,
		Requires: config.Requires{
			Client:           true,
			Db:               true,
			IndexKey:         false,
			AesKey:           true,
			UserAuthUrl:      true,
			S2sSigningKey:    false,
			S2sVerifyingKey:  false,
			UserSigningKey:   false,
			UserVerifyingKey: false,
		},
	}

	config, err := config.Load(def)
	if err != nil {
		logger.Error("failed to load Erebor config", "err", err.Error())
		os.Exit(1)
	}

	gateway, err := gateway.New(*config)
	if err != nil {
		logger.Error("failed to create erebor gateway", "err", err.Error())
		os.Exit(1)
	}

	defer gateway.CloseDb()

	if err := gateway.Run(); err != nil {
		logger.Error("failed to run erebor gateway", "err", err.Error())
		os.Exit(1)
	}

	select {}
}
