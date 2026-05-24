package gitstore

import "strings"

func SelectTransportWithSSH(url, token, deployKeyPath string) (Transport, error) {
	if strings.HasPrefix(url, "file://") {
		return FileURLTransport{}, nil
	}
	if strings.HasPrefix(url, "git@") || strings.HasPrefix(url, "ssh://") {
		return NewSSHDeployKeyTransport(deployKeyPath)
	}
	return HTTPSTokenTransport{Token: token}, nil
}
