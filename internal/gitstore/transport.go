package gitstore

import (
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

type Transport interface {
	Auth() transport.AuthMethod
}

type HTTPSTokenTransport struct {
	Token string
}

func (t HTTPSTokenTransport) Auth() transport.AuthMethod {
	if t.Token == "" {
		return nil
	}
	return &http.BasicAuth{
		Username: "x-access-token",
		Password: t.Token,
	}
}

type FileURLTransport struct{}

func (FileURLTransport) Auth() transport.AuthMethod {
	return nil
}

func SelectTransport(url string, token string) Transport {
	if strings.HasPrefix(url, "file://") {
		return FileURLTransport{}
	}
	return HTTPSTokenTransport{Token: token}
}
