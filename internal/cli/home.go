package cli

import (
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
)

func resolveBaseHome(a *app.App) (string, error) {
	if a.Home != "" {
		return a.Home, nil
	}
	return config.Home()
}

func resolveRoleHome(a *app.App, role config.Role) (string, bool, error) {
	base, err := resolveBaseHome(a)
	if err != nil {
		return "", false, err
	}
	return config.ResolveRoleHome(base, role)
}

func requireRoleHome(a *app.App, role config.Role, command string) (string, error) {
	base, err := resolveBaseHome(a)
	if err != nil {
		return "", &ExitError{Code: ExitUsage, Err: err}
	}
	home, exists, err := config.ResolveRoleHome(base, role)
	if err != nil {
		return "", &ExitError{Code: ExitUsage, Err: err}
	}
	if exists {
		return home, nil
	}
	installed, err := config.InstalledRoles(base)
	if err != nil {
		return "", &ExitError{Code: ExitUsage, Err: err}
	}
	if len(installed) == 0 {
		return "", &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: no kauket store configured here; run '%s' first", createHint(role))}
	}
	return "", &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: %s requires the %s role, but this kauket home only has the %s role; run '%s' to add it", command, role, otherRole(role), createHint(role))}
}

func createHint(role config.Role) string {
	if role == config.RoleAdmin {
		return "kauket init"
	}
	return "kauket enroll"
}

func otherRole(role config.Role) config.Role {
	if role == config.RoleAdmin {
		return config.RoleClient
	}
	return config.RoleAdmin
}

func parseRoleFlag(s string) (config.Role, error) {
	switch config.Role(s) {
	case config.RoleUninitialized, config.RoleAdmin, config.RoleClient:
		return config.Role(s), nil
	default:
		return config.RoleUninitialized, fmt.Errorf("kauket: invalid --role %q; must be admin or client", s)
	}
}

type roleHome struct {
	role config.Role
	home string
}

func resolveTargetRoles(a *app.App, roleFlag string) ([]roleHome, error) {
	role, err := parseRoleFlag(roleFlag)
	if err != nil {
		return nil, &ExitError{Code: ExitUsage, Err: err}
	}
	base, err := resolveBaseHome(a)
	if err != nil {
		return nil, &ExitError{Code: ExitUsage, Err: err}
	}
	if role != config.RoleUninitialized {
		home, exists, err := config.ResolveRoleHome(base, role)
		if err != nil {
			return nil, &ExitError{Code: ExitUsage, Err: err}
		}
		if !exists {
			return nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: --role %s requested but the %s role is not configured here; run '%s' first", role, role, createHint(role))}
		}
		return []roleHome{{role: role, home: home}}, nil
	}
	installed, err := config.InstalledRoles(base)
	if err != nil {
		return nil, &ExitError{Code: ExitUsage, Err: err}
	}
	targets := make([]roleHome, 0, len(installed))
	for _, r := range installed {
		home, _, err := config.ResolveRoleHome(base, r)
		if err != nil {
			return nil, &ExitError{Code: ExitUsage, Err: err}
		}
		targets = append(targets, roleHome{role: r, home: home})
	}
	return targets, nil
}
