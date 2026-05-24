package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type UI interface {
	Println(s string)
	Errorf(format string, args ...any)
	Confirm(prompt string) (bool, error)
	Promptf(format string, args ...any) (string, error)
}

type Terminal struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Stdin   io.Reader
	NoColor bool
}

func NewTerminal() *Terminal {
	return &Terminal{
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Stdin:   os.Stdin,
		NoColor: os.Getenv("KAUKET_NO_COLOR") != "",
	}
}

func (t *Terminal) Println(s string) {
	fmt.Fprint(t.Stdout, s+"\n")
}

func (t *Terminal) Errorf(format string, args ...any) {
	fmt.Fprint(t.Stderr, "error: "+fmt.Sprintf(format, args...)+"\n")
}

func (t *Terminal) Confirm(prompt string) (bool, error) {
	fmt.Fprint(t.Stdout, prompt+" [y/N] ")
	line, err := readLine(t.Stdin)
	if err != nil {
		return false, err
	}
	s := strings.ToLower(strings.TrimSpace(line))
	return s == "y" || s == "yes", nil
}

func (t *Terminal) Promptf(format string, args ...any) (string, error) {
	fmt.Fprint(t.Stdout, fmt.Sprintf(format, args...))
	line, err := readLine(t.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func readLine(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return line, nil
}
