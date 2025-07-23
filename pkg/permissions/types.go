package permissions

import (
	"erebor/internal/util"
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// possible service selection for permission routing
var serviceSelection = map[string]struct{}{
	util.ServiceGallery: {},
	util.ServiceTasks:   {},
}

// returns the canonical name of the service
func selectService(service string) (string, error) {
	// check if the service is in the selection map
	key := strings.TrimSpace(strings.ToLower(service))
	if _, ok := serviceSelection[key]; ok {
		return key, nil
	}
	return "", fmt.Errorf("service %s not found in selection", service)
}

// UpdatePermissionsCmd is a model that represents the payload for updating permissions
// that the gateway receives from the client.  Entity will be a resource slug.
type UpdatePermissionsCmd struct {
	Csrf               string              `json:"csrf,omitempty"`
	EntitySlug         string              `json:"entity_slug,omitempty"`
	ServicePermissions []ServicePermission `json:"service_permissions,omitempty"`
}

// ServicePermission is a model that represents a service permission which will be submitted to an
// upstream service to update permissions for a specific entity.
type ServicePermission struct {
	ServiceName    string `json:"service_name"`
	PermissionSlug string `json:"permission_slug"`
}

// Validate checks if the UpdatePermissionsGateway payload is valid
func (p *UpdatePermissionsCmd) Validate() error {
	// check csrf token
	if !validate.IsValidUuid(p.Csrf) {
		return fmt.Errorf("invalid csrf token in update permissions payload")
	}

	// check entity slug
	if !validate.IsValidUuid(p.EntitySlug) {
		return fmt.Errorf("invalid entity slug in update permissions payload")
	}

	// check service permissions
	if len(p.ServicePermissions) == 0 {
		return fmt.Errorf("no service permissions provided in update permissions payload")
	}

	for _, perm := range p.ServicePermissions {

		// check if service name is allowed.
		if _, ok := serviceSelection[strings.TrimSpace(strings.ToLower(perm.ServiceName))]; !ok {
			return fmt.Errorf("invalid service name in update permissions payload: %s", perm.ServiceName)
		}

		// check if permission slug is well formed uuid
		if !validate.IsValidUuid(perm.PermissionSlug) {
			return fmt.Errorf("invalid permission name in update permissions payload: %s", perm)
		}
	}

	return nil
}
