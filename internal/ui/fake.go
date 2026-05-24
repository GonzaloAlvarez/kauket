package ui

import "fmt"

type Fake struct {
	Lines        []string
	Errors       []string
	ConfirmReply bool
	PromptReply  string
}

func (f *Fake) Println(s string) {
	f.Lines = append(f.Lines, s)
}

func (f *Fake) Errorf(format string, args ...any) {
	f.Errors = append(f.Errors, fmt.Sprintf(format, args...))
}

func (f *Fake) Confirm(prompt string) (bool, error) {
	return f.ConfirmReply, nil
}

func (f *Fake) Promptf(format string, args ...any) (string, error) {
	return f.PromptReply, nil
}
