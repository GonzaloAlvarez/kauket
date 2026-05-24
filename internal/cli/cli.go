package cli

import (
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/buildflags"
)

func Execute() error {
	fmt.Printf("kauket %s (not yet implemented)\n", buildflags.Version)
	return nil
}
