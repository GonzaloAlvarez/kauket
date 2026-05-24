package cli

const (
	ExitSuccess    = 0
	ExitUsage      = 1
	ExitCrypto     = 2
	ExitSync       = 3
	ExitInstall    = 4
	ExitNotGranted = 5
)

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }

func (e *ExitError) Unwrap() error { return e.Err }
