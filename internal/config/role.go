package config

import (
	"errors"
	"fmt"
)

type WrongRoleError struct {
	Want Role
	Got  Role
}

func (e *WrongRoleError) Error() string {
	return fmt.Sprintf("kauket: this command requires %s role on this machine; current role is %s", e.Want, e.Got)
}

func RequireRole(home string, want Role) error {
	got, err := PeekRole(home)
	if err != nil {
		if errors.Is(err, ErrNoConfig) {
			return errors.New("kauket: no kauket store configured here; run 'kauket init' or 'kauket enroll' first")
		}
		return err
	}
	if got == RoleUninitialized {
		return errors.New("kauket: no kauket store configured here; run 'kauket init' or 'kauket enroll' first")
	}
	if got != want {
		return &WrongRoleError{Want: want, Got: got}
	}
	return nil
}
