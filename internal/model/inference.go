package model

import (
	"errors"
	"strings"
)

var ErrNoDestRule = errors.New("no destination rule; pass --dest")

func InferInstallSpec(secretID, sourcePath string) (InstallSpec, error) {
	segments := strings.Split(secretID, ".")
	last := segments[len(segments)-1]
	first := segments[0]

	if strings.HasSuffix(secretID, "_private_key") && first == "ssh" {
		return InstallSpec{
			Destination:   "~/.ssh/" + last,
			Mode:          "0600",
			DirectoryMode: "0700",
		}, nil
	}
	if first == "aws" && last == "key_file" && len(segments) >= 3 {
		return InstallSpec{
			Destination:   "~/.aws/credentials",
			Mode:          "0600",
			DirectoryMode: "0700",
		}, nil
	}
	if last == "kubeconfig" {
		return InstallSpec{
			Destination:   "~/.kube/config",
			Mode:          "0600",
			DirectoryMode: "0700",
		}, nil
	}
	return InstallSpec{}, ErrNoDestRule
}

func InferProfile(secretID string) string {
	segments := strings.Split(secretID, ".")
	if len(segments) == 0 {
		return ""
	}
	first := segments[0]
	last := segments[len(segments)-1]
	switch {
	case first == "ssh":
		return "ssh"
	case first == "aws":
		return "aws"
	case last == "kubeconfig":
		return "kube"
	default:
		return ""
	}
}
