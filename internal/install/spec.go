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
