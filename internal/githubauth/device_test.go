package githubauth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const fakeDeviceCode = "FAKE_DEVICE_CODE_xxxxxxxxxxxxxxxxxxxxxx"
const fakeUserCode = "WXYZ-ABCD"
const fakeVerificationURI = "https://example.test/login/device"
const fakeAccessToken = "FAKE_ACCESS_TOKEN_yyyyyyyyyyyyyyyyyyyyyy"

type fakeDeviceServer struct {
	server          *httptest.Server
	pollCount       int32
	deniedFirstPoll bool
	requestedScopes string
	mu              sync.Mutex
}

func newFakeDeviceServer(t *testing.T, clientID string) *fakeDeviceServer {
	t.Helper()
	f := &fakeDeviceServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.PostForm.Get("client_id") != clientID {
			http.Error(w, "wrong client_id", 400)
			return
		}
		f.mu.Lock()
		f.requestedScopes = r.PostForm.Get("scope")
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		body := fmt.Sprintf("device_code=%s&user_code=%s&verification_uri=%s&expires_in=600&interval=0",
			fakeDeviceCode, fakeUserCode, fakeVerificationURI)
		fmt.Fprint(w, body)
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.PostForm.Get("client_id") != clientID {
			http.Error(w, "wrong client_id", 400)
			return
		}
		if r.PostForm.Get("device_code") != fakeDeviceCode {
			http.Error(w, "wrong device_code", 400)
			return
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		count := atomic.AddInt32(&f.pollCount, 1)
		if f.deniedFirstPoll && count == 1 {
			fmt.Fprint(w, "error=authorization_pending")
			return
		}
		fmt.Fprintf(w, "access_token=%s&token_type=bearer&scope=repo", fakeAccessToken)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeDeviceServer) endpoints() *DeviceEndpoints {
	return &DeviceEndpoints{
		DeviceCodeURL: f.server.URL + "/login/device/code",
		TokenURL:      f.server.URL + "/login/oauth/access_token",
	}
}

func TestDeviceFlowProviderHappyPath(t *testing.T) {
	const clientID = "test-client-id"
	srv := newFakeDeviceServer(t, clientID)

	var gotVerifyURL, gotUserCode string
	p := &DeviceFlowProvider{
		ClientID: clientID,
		PrintCode: func(verifyURL, userCode string) {
			gotVerifyURL = verifyURL
			gotUserCode = userCode
		},
		HTTPClient: srv.server.Client(),
		Endpoints:  srv.endpoints(),
	}

	token, err := p.Token(context.Background(), []string{"repo"})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token != fakeAccessToken {
		t.Fatalf("token = %q, want %q", token, fakeAccessToken)
	}
	if gotVerifyURL != fakeVerificationURI {
		t.Fatalf("verify URL = %q, want %q", gotVerifyURL, fakeVerificationURI)
	}
	if gotUserCode != fakeUserCode {
		t.Fatalf("user code = %q, want %q", gotUserCode, fakeUserCode)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !strings.Contains(srv.requestedScopes, "repo") {
		t.Fatalf("scopes not forwarded: %q", srv.requestedScopes)
	}
}

func TestDeviceFlowProviderPollsWhenPending(t *testing.T) {
	const clientID = "test-client-id"
	srv := newFakeDeviceServer(t, clientID)
	srv.deniedFirstPoll = true

	p := &DeviceFlowProvider{
		ClientID:   clientID,
		PrintCode:  func(string, string) {},
		HTTPClient: srv.server.Client(),
		Endpoints:  srv.endpoints(),
	}

	token, err := p.Token(context.Background(), []string{"repo"})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token != fakeAccessToken {
		t.Fatalf("token mismatch")
	}
	if atomic.LoadInt32(&srv.pollCount) < 2 {
		t.Fatalf("expected at least 2 polls, got %d", srv.pollCount)
	}
}

func TestDeviceFlowProviderRejectsEmptyClientID(t *testing.T) {
	p := &DeviceFlowProvider{}
	tok, err := p.Token(context.Background(), []string{"repo"})
	if err == nil {
		t.Fatalf("expected error for empty client id")
	}
	if tok != "" {
		t.Fatalf("expected empty token")
	}
	if bytes.Contains([]byte(err.Error()), []byte(fakeAccessToken)) {
		t.Fatalf("error leaked token")
	}
}

func TestDeviceFlowProviderDefaultPrintWritesToStderr(t *testing.T) {
	const clientID = "test-client-id"
	srv := newFakeDeviceServer(t, clientID)

	oldStderr := stderrWriter
	var captured bytes.Buffer
	stderrWriter = &captured
	t.Cleanup(func() { stderrWriter = oldStderr })

	p := &DeviceFlowProvider{
		ClientID:   clientID,
		HTTPClient: srv.server.Client(),
		Endpoints:  srv.endpoints(),
	}
	tok, err := p.Token(context.Background(), []string{"repo"})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != fakeAccessToken {
		t.Fatalf("token mismatch")
	}
	wantLine := fmt.Sprintf("Open %s and enter code: %s\n", fakeVerificationURI, fakeUserCode)
	if got := captured.String(); got != wantLine {
		t.Fatalf("stderr output = %q, want %q", got, wantLine)
	}
}

func TestDeviceFlowProviderTokenNeverInError(t *testing.T) {
	const clientID = "test-client-id"
	mux := http.NewServeMux()
	mux.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprintf(w, "device_code=%s&user_code=%s&verification_uri=%s&expires_in=600&interval=0",
			fakeDeviceCode, fakeUserCode, fakeVerificationURI)
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprint(w, "error=access_denied&error_description=user_cancelled")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p := &DeviceFlowProvider{
		ClientID:   clientID,
		PrintCode:  func(string, string) {},
		HTTPClient: srv.Client(),
		Endpoints: &DeviceEndpoints{
			DeviceCodeURL: srv.URL + "/login/device/code",
			TokenURL:      srv.URL + "/login/oauth/access_token",
		},
	}
	tok, err := p.Token(context.Background(), []string{"repo"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if tok != "" {
		t.Fatalf("expected empty token")
	}
	if bytes.Contains([]byte(err.Error()), []byte(fakeAccessToken)) {
		t.Fatalf("error leaked token: %v", err)
	}
}
