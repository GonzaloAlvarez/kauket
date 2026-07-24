package githubauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type recordingProvider struct {
	Name        string
	Token       string
	Err         error
	Called      bool
	CalledTimes int
	FailOnCall  bool
	t           *testing.T
}

func (r *recordingProvider) TokenFn(ctx context.Context, scopes []string) (string, error) {
	r.Called = true
	r.CalledTimes++
	if r.FailOnCall {
		r.t.Fatalf("provider %q must not be called", r.Name)
	}
	return r.Token, r.Err
}

type providerFn func(ctx context.Context, scopes []string) (string, error)

func (f providerFn) Token(ctx context.Context, scopes []string) (string, error) {
	return f(ctx, scopes)
}

func TestSelectGHSuccess(t *testing.T) {
	const tok = "FAKE_GH_TOKEN_aaaaaaaaaaaaaaaaaaaaaaaaaaa"
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return tok, nil
	})
	dev := &recordingProvider{Name: "device", FailOnCall: true, t: t}
	out, name, err := Select(context.Background(), []string{"repo"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  providerFn(dev.TokenFn),
		AllowDeviceFlow: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if name != "gh" {
		t.Fatalf("provider name = %q, want gh", name)
	}
	if out != tok {
		t.Fatalf("token mismatch")
	}
	if dev.Called {
		t.Fatalf("device provider should not be called when gh succeeds")
	}
}

func TestSelectFallsThroughOnInsufficientScopes(t *testing.T) {
	const tok = "FAKE_DEVICE_TOKEN_zzzzzzzzzzzzzzzzzzzzzzz"
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", &InsufficientScopesError{Missing: []string{"admin:public_key"}}
	})
	dev := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return tok, nil
	})
	out, name, err := Select(context.Background(), []string{"repo", "admin:public_key"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  dev,
		AllowDeviceFlow: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if name != "device" {
		t.Fatalf("provider name = %q, want device", name)
	}
	if out != tok {
		t.Fatalf("token mismatch")
	}
}

func TestSelectFallsThroughOnNotInstalled(t *testing.T) {
	const tok = "FAKE_DEVICE_TOKEN_2_zzzzzzzzzzzzzzzzzzzzzzz"
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", ErrGHNotInstalled
	})
	dev := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return tok, nil
	})
	out, name, err := Select(context.Background(), []string{"repo"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  dev,
		AllowDeviceFlow: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if name != "device" || out != tok {
		t.Fatalf("unexpected: name=%q tok=%q", name, out)
	}
}

func TestSelectFallsThroughOnNotAuthenticated(t *testing.T) {
	const tok = "FAKE_DEVICE_TOKEN_3_zzzzzzzzzzzzzzzzzzzzzzz"
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", ErrGHNotAuthenticated
	})
	dev := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return tok, nil
	})
	out, name, err := Select(context.Background(), []string{"repo"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  dev,
		AllowDeviceFlow: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if name != "device" || out != tok {
		t.Fatalf("unexpected: name=%q tok=%q", name, out)
	}
}

func TestSelectDoesNotFallThroughOnUnknownError(t *testing.T) {
	custom := errors.New("kauket: some other failure")
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", custom
	})
	dev := &recordingProvider{Name: "device", FailOnCall: true, t: t}
	_, _, err := Select(context.Background(), []string{"repo"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  providerFn(dev.TokenFn),
		AllowDeviceFlow: true,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, custom) {
		t.Fatalf("expected wrapped custom error, got %v", err)
	}
	if dev.Called {
		t.Fatalf("device provider should not be called for unknown gh errors")
	}
}

func TestSelectDeviceFlowDisabledReturnsActionableError(t *testing.T) {
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", &InsufficientScopesError{Missing: []string{"admin:public_key"}}
	})
	dev := &recordingProvider{Name: "device", FailOnCall: true, t: t}
	_, _, err := Select(context.Background(), []string{"repo", "admin:public_key"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  providerFn(dev.TokenFn),
		AllowDeviceFlow: false,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "gh auth login") {
		t.Fatalf("expected 'gh auth login' hint, got: %v", err)
	}
	if !strings.Contains(strings.ToLower(msg), "device flow") {
		t.Fatalf("expected device flow mention in error, got: %v", err)
	}
	if dev.Called {
		t.Fatalf("device provider should not be called when AllowDeviceFlow=false")
	}
}

func TestSelectBothProvidersFailReturnsCombinedError(t *testing.T) {
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", ErrGHNotInstalled
	})
	dev := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", errors.New("kauket: device flow timed out")
	})
	_, _, err := Select(context.Background(), []string{"repo"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  dev,
		AllowDeviceFlow: true,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "gh auth login") {
		t.Fatalf("expected gh auth login hint")
	}
	if !strings.Contains(err.Error(), "device flow") {
		t.Fatalf("expected device flow mention")
	}
}

func TestSelectFallsThroughOnGHTimeout(t *testing.T) {
	const tok = "FAKE_DEVICE_TOKEN_4_zzzzzzzzzzzzzzzzzzzzzzz"
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", fmt.Errorf("%w: gh auth status gave no answer", ErrGHTimeout)
	})
	dev := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return tok, nil
	})
	out, name, err := Select(context.Background(), []string{"repo"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  dev,
		AllowDeviceFlow: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if name != "device" || out != tok {
		t.Fatalf("unexpected: name=%q tok=%q", name, out)
	}
}

func TestSelectGHTimeoutAndDeviceFailureMentionsConnectivity(t *testing.T) {
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", fmt.Errorf("%w: gh auth status gave no answer", ErrGHTimeout)
	})
	dev := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return "", errors.New("kauket: device flow request failed")
	})
	_, _, err := Select(context.Background(), []string{"repo"}, SelectorOptions{
		GHProvider:      gh,
		DeviceProvider:  dev,
		AllowDeviceFlow: true,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "internet connectivity") {
		t.Fatalf("expected connectivity hint, got: %v", err)
	}
}

func TestSelectReturnsTokenWithoutLogging(t *testing.T) {
	const tok = "FAKE_SELECT_TOKEN_qqqqqqqqqqqqqqqqqqqqqqq"
	gh := providerFn(func(ctx context.Context, scopes []string) (string, error) {
		return tok, nil
	})
	out, name, err := Select(context.Background(), []string{"repo"}, SelectorOptions{
		GHProvider:      gh,
		AllowDeviceFlow: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if out != tok {
		t.Fatalf("token mismatch")
	}
	if name != "gh" {
		t.Fatalf("name = %q want gh", name)
	}
}
