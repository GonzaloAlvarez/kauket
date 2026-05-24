package githubauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/cli/oauth/device"
)

var stderrWriter io.Writer = os.Stderr

const (
	defaultDeviceCodeURL = "https://github.com/login/device/code"
	defaultTokenURL      = "https://github.com/login/oauth/access_token"
)

type DeviceEndpoints struct {
	DeviceCodeURL string
	TokenURL      string
}

type DeviceFlowProvider struct {
	ClientID   string
	PrintCode  func(verifyURL, userCode string)
	HTTPClient *http.Client
	Endpoints  *DeviceEndpoints
}

func (p *DeviceFlowProvider) Token(ctx context.Context, scopes []string) (string, error) {
	if p.ClientID == "" {
		return "", errors.New("kauket: device flow provider requires a client id")
	}
	httpClient := p.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	deviceCodeURL := defaultDeviceCodeURL
	tokenURL := defaultTokenURL
	if p.Endpoints != nil {
		if p.Endpoints.DeviceCodeURL != "" {
			deviceCodeURL = p.Endpoints.DeviceCodeURL
		}
		if p.Endpoints.TokenURL != "" {
			tokenURL = p.Endpoints.TokenURL
		}
	}

	code, err := device.RequestCode(httpClient, deviceCodeURL, p.ClientID, scopes)
	if err != nil {
		return "", fmt.Errorf("kauket: device flow request failed: %w", err)
	}

	if p.PrintCode != nil {
		p.PrintCode(code.VerificationURI, code.UserCode)
	} else {
		fmt.Fprintf(stderrWriter, "Open %s and enter code: %s\n", code.VerificationURI, code.UserCode)
	}

	token, err := device.Wait(ctx, httpClient, tokenURL, device.WaitOptions{
		ClientID:   p.ClientID,
		DeviceCode: code,
	})
	if err != nil {
		return "", fmt.Errorf("kauket: device flow wait failed: %w", err)
	}
	if token == nil || token.Token == "" {
		return "", errors.New("kauket: device flow returned empty token")
	}
	return token.Token, nil
}
