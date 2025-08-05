package util

const (
	PackageKey = "package"

	PackageMain        string = "main"
	PackageGateway     string = "gateway"
	PackageAuth        string = "authentication"
	PackageSession     string = "uxsession"
	PackageUser        string = "user"
	PackageScopes      string = "scopes"
	PackageClients     string = "clients"
	PackageTasks       string = "tasks"
	PackageGallery     string = "gallery"
	PackagePermissions string = "permissions"
	PackageScheduled   string = "scheduled"

	ComponentKey string = "component"

	ComponentMain                 string = "main"
	ComponentGateway              string = "gateway"
	ComponentCsrf                 string = "csrf"
	ComponentLogin                string = "login"
	ComponentLogout               string = "logout"
	ComponentRegister             string = "register"
	ComponentOauth                string = "oauth flow exchange"
	ComponentCallback             string = "oauth flow callback"
	ComponentProfile              string = "profile"
	ComponentReset                string = "password reset"
	ComponentScopes               string = "scopes"
	ComponentClients              string = "s2s service clients"
	ComponentClientsScopes        string = "client scopes"
	ComponentUser                 string = "user"
	ComponentUserScopes           string = "user scopes"
	ComponentUserPermissions      string = "user permissions"
	ComponentUxSession            string = "ux session"
	ComponentTasks                string = "tasks"
	ComponentAllowances           string = "task allowances"
	ComponentTemplate             string = "task templates"
	ComponentAlbums               string = "gallery albums"
	ComponentImages               string = "gallery images"
	ComponentPermissions          string = "permissions"
	ComponentScheduledUserAccount string = "scheduled user account service"

	SerivceKey = "service"

	// service names in definitions.go
)
