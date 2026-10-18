package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klppl/valv/core"
	"golang.org/x/term"
)

// lineReader reads one secret per line for --passphrase-stdin.
type lineReader struct{ r *bufio.Reader }

func (l *lineReader) next() (string, error) {
	line, err := l.r.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("could not read a line from stdin")
	}
	line = strings.TrimSuffix(line, "\n")
	return strings.TrimSuffix(line, "\r"), nil
}

// readSecret reads a passphrase or recovery key. With --passphrase-stdin it
// takes the next stdin line (only the line ending is removed); otherwise it
// reads from the terminal without echo.
func (a *app) readSecret(prompt string) (string, error) {
	if a.passStdin {
		if a.lines == nil {
			a.lines = &lineReader{bufio.NewReader(a.stdin)}
		}
		return a.lines.next()
	}
	f, ok := a.stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", errors.New("stdin is not a terminal; use --passphrase-stdin")
	}
	fmt.Fprint(a.stderr, prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(a.stderr)
	if err != nil {
		return "", errors.New("could not read from the terminal")
	}
	s := string(b)
	clear(b)
	return s, nil
}

// newPassphrase asks for a new passphrase, twice on a terminal.
func (a *app) newPassphrase() (string, error) {
	p, err := a.readSecret("New passphrase: ")
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("the passphrase must not be empty")
	}
	if !a.passStdin {
		again, err := a.readSecret("Repeat passphrase: ")
		if err != nil {
			return "", err
		}
		if again != p {
			return "", errors.New("the passphrases do not match")
		}
	}
	return p, nil
}

// unlock reads vault.json from dir and unlocks it with a passphrase.
func (a *app) unlock(dir string) (*core.VaultKeys, error) {
	data, err := os.ReadFile(filepath.Join(dir, core.ConfigFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no %s in %s (not a vault?)", core.ConfigFile, dir)
		}
		return nil, err
	}
	c, err := core.ParseConfig(data)
	if err != nil {
		return nil, err
	}
	pass, err := a.readSecret("Passphrase: ")
	if err != nil {
		return nil, err
	}
	return core.Unlock(c, pass)
}
