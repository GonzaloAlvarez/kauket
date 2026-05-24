package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/gonzaloalvarez/kauket/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			fmt.Fprintln(os.Stderr, "error: "+exitErr.Error())
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}
