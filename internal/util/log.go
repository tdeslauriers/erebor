package util

const (
	PackageKey = "package"

	PackageMain    string = "main"
	PackageGateway string = "gateway"
	PackageAuth    string = "authentication"
	PackageSession string = "uxsession"
	PackageUser    string = "user"
	PackageScopes  string = "scopes"
	PackageClients string = "clients"

	ComponentKey string = "component"

	ComponentMain          string = "main"
	ComponentCsrf          string = "csrf"
	ComponentLogin         string = "login"
	ComponentLogout        string = "logout"
	ComponentRegister      string = "register"
	ComponentOauth         string = "oauth flow exchange"
	ComponentCallback      string = "oauth flow callback"
	ComponentProfile       string = "profile"
	ComponentReset         string = "password reset"
	ComponentScopes        string = "scopes"
	ComponentClients       string = "s2s service clients"
	ComponentClientsScopes string = "client scopes"
	ComponentUser          string = "user"
	ComponentUserScopes    string = "user scopes"
	ComponentUxSession     string = "ux session"

	SerivceKey = "service"

	// service names in definitions.go
)
