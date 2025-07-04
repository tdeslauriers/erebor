package permissions

import (
	"erebor/internal/util"
	"fmt"
	"strings"
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
