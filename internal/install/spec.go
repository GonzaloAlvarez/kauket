package install

import (
	"fmt"
	"os"
	"strconv"
)

type InstallSpec struct {
	Destination   string
	Mode          os.FileMode
	DirectoryMode os.FileMode
}

func ParseMode(s string) (os.FileMode, error) {
	if s == "" {
		return 0, fmt.Errorf("install: empty mode string")
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("install: parse mode %q: %w", s, err)
	}
	return os.FileMode(n), nil
}

func ValidateSecretMode(mode os.FileMode, allowLoose bool) error {
	if mode != mode.Perm() {
		return fmt.Errorf("%w: mode %o sets non-permission bits (setuid/setgid/sticky)", ErrUnsafeMode, uint32(mode))
	}
	perm := mode.Perm()
	if perm&0o022 != 0 {
		return fmt.Errorf("%w: mode %o is group/other-writable", ErrUnsafeMode, uint32(perm))
	}
	if !allowLoose && perm&0o077 != 0 {
		return fmt.Errorf("%w: mode %o exposes the secret to group/other; set install_allow_modes in client config to override", ErrUnsafeMode, uint32(perm))
	}
	return nil
}

func ValidateDirMode(mode os.FileMode) error {
	if mode != mode.Perm() {
		return fmt.Errorf("%w: directory mode %o sets non-permission bits", ErrUnsafeMode, uint32(mode))
	}
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("%w: directory mode %o is group/other-accessible", ErrUnsafeMode, uint32(mode.Perm()))
	}
	return nil
}
