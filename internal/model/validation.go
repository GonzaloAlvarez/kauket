package model

import (
	"fmt"
	"regexp"
)

var secretIDRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$`)

func ValidateSecretID(id string) error {
	if !secretIDRegex.MatchString(id) {
		return fmt.Errorf("secret id %q is invalid", id)
	}
	return nil
}

var identityIDRegex = regexp.MustCompile(`^(h_|i_)[a-z2-7]{16}$`)

func ValidateIdentityID(id string) error {
	if !identityIDRegex.MatchString(id) {
		return fmt.Errorf("identity id %q is invalid", id)
	}
	return nil
}

var requestIDRegex = regexp.MustCompile(`^rq_[a-z2-7]{16}$`)

func ValidateRequestID(id string) error {
	if !requestIDRegex.MatchString(id) {
		return fmt.Errorf("request id %q is invalid", id)
	}
	return nil
}
