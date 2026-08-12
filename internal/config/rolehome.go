package config

import (
	"fmt"
	"path/filepath"
)

func RoleHome(base string, role Role) string {
	return filepath.Join(base, string(role))
}

func ResolveRoleHome(base string, role Role) (string, bool, error) {
	sub := RoleHome(base, role)
	got, err := PeekRole(sub)
	if err != nil {
		return "", false, err
	}
	switch got {
	case role:
		return sub, true, nil
	case RoleUninitialized:
	default:
		return "", false, fmt.Errorf("kauket: %s declares role %q, expected %q", ConfigPath(sub), got, role)
	}
	got, err = PeekRole(base)
	if err != nil {
		return "", false, err
	}
	if got == role {
		return "", false, fmt.Errorf("kauket: %s uses the legacy root-layout home; run 'kauket migrate' with the kauket v2.0.x release to move it into its role subdirectory", base)
	}
	return sub, false, nil
}

func InstalledRoles(base string) ([]Role, error) {
	var roles []Role
	for _, role := range []Role{RoleAdmin, RoleClient} {
		if _, exists, err := ResolveRoleHome(base, role); err != nil {
			return nil, err
		} else if exists {
			roles = append(roles, role)
		}
	}
	return roles, nil
}
