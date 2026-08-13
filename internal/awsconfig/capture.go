package awsconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Capture struct {
	Envelope Envelope
	Captured []string
	Warnings []string
}

func ConfigPath() (string, error) {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("aws config path: %w", err)
	}
	return filepath.Join(home, ".aws", "config"), nil
}

func CredentialsPath() (string, error) {
	if p := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("aws credentials path: %w", err)
	}
	return filepath.Join(home, ".aws", "credentials"), nil
}

func ReadFiles() (configText, credsText []byte, configPath, credsPath string, err error) {
	configPath, err = ConfigPath()
	if err != nil {
		return nil, nil, "", "", err
	}
	credsPath, err = CredentialsPath()
	if err != nil {
		return nil, nil, "", "", err
	}
	configText, err = readOptional(configPath)
	if err != nil {
		return nil, nil, "", "", err
	}
	credsText, err = readOptional(credsPath)
	if err != nil {
		return nil, nil, "", "", err
	}
	return configText, credsText, configPath, credsPath, nil
}

func readOptional(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

func CaptureProfile(profile string, configText, credsText []byte, configPath, credsPath string) (Capture, error) {
	out := Capture{Envelope: Envelope{Schema: EnvelopeSchema, Profile: profile}}
	cfg := Parse(configText, KindConfig)
	creds := Parse(credsText, KindCredentials)

	cfgSection := findSection(cfg, profile)
	credSection := findSection(creds, profile)
	if cfgSection == nil && credSection == nil {
		return Capture{}, fmt.Errorf("aws profile %q not found in %s or %s", profile, configPath, credsPath)
	}

	if cfgSection != nil {
		out.Envelope.Config = NormalizeSection(cfgSection.Raw)
		out.Captured = append(out.Captured, fmt.Sprintf("captured [%s] from %s", cfgSection.Header, configPath))
		if sso := sectionValue(cfgSection.Raw, "sso_session"); sso != "" {
			if ssoSection := findSection(cfg, "sso-session "+sso); ssoSection != nil {
				out.Envelope.Config += "\n" + NormalizeSection(ssoSection.Raw)
				out.Captured = append(out.Captured, fmt.Sprintf("captured [%s] from %s", ssoSection.Header, configPath))
			} else {
				out.Warnings = append(out.Warnings, fmt.Sprintf("profile %s references sso_session %q but [sso-session %s] was not found in %s", profile, sso, sso, configPath))
			}
		}
		if sp := sectionValue(cfgSection.Raw, "source_profile"); sp != "" {
			out.Warnings = append(out.Warnings, fmt.Sprintf("profile %s references source_profile %q; that profile is not captured, add it separately", profile, sp))
		}
	}
	if credSection != nil {
		out.Envelope.Credentials = NormalizeSection(credSection.Raw)
		out.Captured = append(out.Captured, fmt.Sprintf("captured [%s] from %s", credSection.Header, credsPath))
	}
	if err := ValidateEnvelope(out.Envelope, nil); err != nil {
		return Capture{}, err
	}
	return out, nil
}

func findSection(f File, key string) *Section {
	for i := range f.Sections {
		if f.Sections[i].Key == key {
			return &f.Sections[i]
		}
	}
	return nil
}

func sectionValue(raw, key string) string {
	for _, line := range splitLines(raw) {
		if len(line) > 0 && line[0] == '[' {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		k, v, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		if strings.ToLower(strings.TrimSpace(k)) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
