package main

import (
	"erebor/internal/util"
	"fmt"

	"erebor/pkg/gateway"
	"log/slog"
	"os"

	"github.com/tdeslauriers/carapace/pkg/config"
)

func main() {

	logger := slog.Default().With(slog.String(util.ComponentKey, util.ComponentMain))

	// service definition
	def := config.SvcDefinition{
		ServiceName: "erebor",
		Tls:         config.StandardTls,
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
			OauthRedirect:    true,
		},
	}

	config, err := config.Load(def)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to load %s config", def.ServiceName), "err", err.Error())
		os.Exit(1)
	}

	gateway, err := gateway.New(*config)
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
