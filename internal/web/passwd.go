package web

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// HashPasswordInteractive asks for a password twice (without echo on a terminal)
// and returns its bcrypt hash for the config file.
func HashPasswordInteractive() (string, error) {
	read := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		if term.IsTerminal(int(os.Stdin.Fd())) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	p1, err := read("Password: ")
	if err != nil {
		return "", err
	}
	if len(p1) < 12 {
		return "", errors.New("use at least 12 characters")
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		p2, err := read("Repeat: ")
		if err != nil {
			return "", err
		}
		if p1 != p2 {
			return "", errors.New("passwords do not match")
		}
	}
	h, err := bcrypt.GenerateFromPassword([]byte(p1), 12)
	return string(h), err
}
