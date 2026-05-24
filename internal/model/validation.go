package model

import (
	"fmt"
	"regexp"
)

var secretIDRegex = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

func ValidateSecretID(id string) error {
	if !secretIDRegex.MatchString(id) {
		return fmt.Errorf("secret id %q is invalid", id)
	}
	return nil
}
