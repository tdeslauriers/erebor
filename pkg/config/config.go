package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Name string
	Certs Certs
	Database Database
	ServiceAuth ServiceAuth
	UserAuth UserAuth
}

type Certs struct {
	ServerCert *string
	ServerKey *string
	ServerCa *string

	ClientCert *string
	ClientKey *string
	ClientCa *string
	
	dbClientCert *string
	dbClientKey *string
	dbCaCert *string
}

type Database struct {
	Url string
	Name string
	Username string
	Password string
	FieldKey string
}

type ServiceAuth struct {
	Url string
	ClientId string
	ClientSecret string
}

type UserAuth struct {
	Url string
}

func Load(name string) *Config {
	config := &Config{Name: name}

	// read in and set certs for all services
	err := config.readCerts()
	if err != nil {
		panic(err)
	}

	// read in and set env vars for database
	err = config.databaseEnvVars()
	if err != nil {
		panic(err)
	}

	// read in and set service auth env vars
	err = config.serviceAuthEnvVars()
	if err != nil {
		panic(err)
	}

	// read in and set service auth env vars
	err = config.userAuthEnvVars()
	if err != nil {
		panic(err)
	}

	return config
}

func (config *Config) readCerts() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))
	}
	
	// read in certificates from environment variables
	envServerCert, ok := os.LookupEnv(fmt.Sprintf("%sSERVER_CERT", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sSERVER_CERT not set", serviceName))
	}
	serverCert := &envServerCert	
	
	envServerKey, ok := os.LookupEnv(fmt.Sprintf("%sSERVER_KEY", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sSERVER_KEY not set", serviceName))
	}
	serverKey := &envServerKey
	
	envClientCert, ok := os.LookupEnv(fmt.Sprintf("%sCLIENT_CERT", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sCLIENT_CERT not set", serviceName))
	}
	clientCert := &envClientCert
	
	
	envClientKey, ok := os.LookupEnv(fmt.Sprintf("%sCLIENT_KEY", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sCLIENT_KEY not set", serviceName))
	}
	clientKey := &envClientKey
	
	envCaCert, ok := os.LookupEnv(fmt.Sprintf("%sCA_CERT", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sCA_CERT not set", serviceName))
	}
	caCert := &envCaCert

	config.Certs.ServerCert = serverCert
	config.Certs.ServerKey = serverKey
	config.Certs.ServerCa = caCert
	config.Certs.ClientCert = clientCert
	config.Certs.ClientKey = clientKey
	config.Certs.ClientCa = caCert

	config.Certs.dbClientCert = clientCert
	config.Certs.dbClientKey = clientKey
	config.Certs.dbCaCert = caCert
	
	return nil
}

func (config *Config) databaseEnvVars() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))
	}
	
	// db env vars
	envDbUrl, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_URL not set", serviceName))
	}
	
	envDbName, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_NAME", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_NAME not set", serviceName))
	}
	
	envDbUsername, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_USERNAME", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_USERNAME not set", serviceName))
	}
	
	envDbPassword, ok := os.LookupEnv(fmt.Sprintf("%sDATABASE_PASSWORD", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sDATABASE_PASSWORD not set", serviceName))
	}
	
	envFieldsKey, ok := os.LookupEnv(fmt.Sprintf("%sFIELD_LEVEL_AES_GCM_KEY", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sFIELD_LEVEL_AES_GCM_KEY not set", serviceName))
	}

	config.Database.FieldKey = envFieldsKey
	config.Database.Url = envDbUrl
	config.Database.Password = envDbPassword
	config.Database.Name = envDbName
	config.Database.Username = envDbUsername
	
	return nil
}

func (config *Config) serviceAuthEnvVars() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))
	}
	
	envRanUrl, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_URL not set", serviceName))
	}
	
	envRanClientId, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_CLIENT_ID", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_CLIENT_ID not set", serviceName))
	}

	envRanClientSecret, ok := os.LookupEnv(fmt.Sprintf("%sS2S_AUTH_CLIENT_SECRET", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sS2S_AUTH_CLIENT_SECRET not set", serviceName))
	}

	config.ServiceAuth.Url = envRanUrl
	config.ServiceAuth.ClientId = envRanClientId
	config.ServiceAuth.ClientSecret = envRanClientSecret
	
	return nil
}

func (config *Config) userAuthEnvVars() error {

	var serviceName string
	if config.Name != "" {
		serviceName = fmt.Sprintf("%s_", strings.ToUpper(config.Name))
		
	}

	envUserAuthUrl, ok := os.LookupEnv(fmt.Sprintf("%sUSER_AUTH_URL", serviceName))
	if !ok {
		return fmt.Errorf(fmt.Sprintf("%sUSER_AUTH_URL not set", serviceName))
	}

	config.UserAuth.Url = envUserAuthUrl
	
	return nil
}