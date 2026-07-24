package githubauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type SelectorOptions struct {
	Shell           Shell
	ClientID        string
	Account         string
	GHTimeout       time.Duration
	PrintCode       func(verifyURL, userCode string)
	HTTPClient      *http.Client
	Endpoints       *DeviceEndpoints
	AllowDeviceFlow bool
	GHProvider      Provider
	DeviceProvider  Provider
}

func Select(ctx context.Context, scopes []string, opts SelectorOptions) (string, string, error) {
	ghProvider := opts.GHProvider
	if ghProvider == nil {
		ghProvider = &GHCLIProvider{Shell: opts.Shell, Account: opts.Account, Timeout: opts.GHTimeout}
	}

	token, ghErr := ghProvider.Token(ctx, scopes)
	if ghErr == nil {
		return token, "gh", nil
	}

	fallback := errors.Is(ghErr, ErrGHNotInstalled) ||
		errors.Is(ghErr, ErrGHNotAuthenticated) ||
		errors.Is(ghErr, ErrInsufficientScopes) ||
		errors.Is(ghErr, ErrGHTimeout)

	if !fallback {
		return "", "", fmt.Errorf("kauket: GitHub authentication via gh failed: %w", ghErr)
	}

	if !opts.AllowDeviceFlow {
		return "", "", fmt.Errorf("kauket: GitHub authentication required; gh provider unavailable and device flow is disabled; run 'gh auth login' with the required scopes: %w", ghErr)
	}

	deviceProvider := opts.DeviceProvider
	if deviceProvider == nil {
		clientID := opts.ClientID
		if clientID == "" {
			clientID = ClientID
		}
		deviceProvider = &DeviceFlowProvider{
			ClientID:   clientID,
			PrintCode:  opts.PrintCode,
			HTTPClient: opts.HTTPClient,
			Endpoints:  opts.Endpoints,
		}
	}

	token, devErr := deviceProvider.Token(ctx, scopes)
	if devErr == nil {
		return token, "device", nil
	}
	if errors.Is(ghErr, ErrGHTimeout) {
		return "", "", fmt.Errorf("kauket: GitHub authentication failed: gh timed out and the device flow did not complete; ensure your internet connectivity is working; gh error: %v; device flow error: %w", ghErr, devErr)
	}
	return "", "", fmt.Errorf("kauket: GitHub authentication required; run 'gh auth login' (recommended) or complete the device flow when prompted; gh provider error: %v; device flow error: %w", ghErr, devErr)
}
