package awsconfig

import (
	"fmt"
	"strings"
)

var defaultDeniedKeys = []string{"credential_process"}

func ValidateEnvelope(env Envelope, deniedKeys []string) error {
	if len(deniedKeys) == 0 {
		deniedKeys = defaultDeniedKeys
	}
	denied := map[string]struct{}{}
	for _, k := range deniedKeys {
		denied[strings.ToLower(strings.TrimSpace(k))] = struct{}{}
	}

	cfg := Parse([]byte(env.Config), KindConfig)
	creds := Parse([]byte(env.Credentials), KindCredentials)

	allowedConfig := map[string]struct{}{env.Profile: {}}
	for i := range cfg.Sections {
		if cfg.Sections[i].Key != env.Profile {
			continue
		}
		if sso := sectionValue(cfg.Sections[i].Raw, "sso_session"); sso != "" {
			allowedConfig["sso-session "+sso] = struct{}{}
		}
	}

	if err := validateSections(cfg, allowedConfig, denied, "config"); err != nil {
		return err
	}
	return validateSections(creds, map[string]struct{}{env.Profile: {}}, denied, "credentials")
}

func validateSections(f File, allowed, denied map[string]struct{}, label string) error {
	for i := range f.Sections {
		s := f.Sections[i]
		if _, ok := allowed[s.Key]; !ok {
			return fmt.Errorf("aws %s: incoming section [%s] does not match the declared profile; refusing", label, s.Header)
		}
		for _, line := range strings.Split(s.Raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq < 0 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(line[:eq]))
			if _, bad := denied[key]; bad {
				return fmt.Errorf("aws %s: section [%s] sets denied directive %q; refusing", label, s.Header, key)
			}
		}
	}
	return nil
}
