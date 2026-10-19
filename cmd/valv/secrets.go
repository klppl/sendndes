package main

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/klppl/valv/core"
	"golang.org/x/term"
	"golang.org/x/text/unicode/norm"
)

// minPassphraseLen is the minimum for a new passphrase, in code points after
// NFC (SPEC 3).
const minPassphraseLen = 12

// terminal reads secrets interactively. Tests replace it.
type terminal interface {
	IsTerminal() bool
	ReadPassword(prompt string) (string, error)
}

// osTerminal reads from stdin when it is a terminal, without echo.
type osTerminal struct {
	in     io.Reader
	prompt io.Writer
}

func (t osTerminal) IsTerminal() bool {
	f, ok := t.in.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func (t osTerminal) ReadPassword(prompt string) (string, error) {
	f := t.in.(*os.File)
	fd := int(f.Fd())
	// If a signal arrives while echo is off, the handler restores it.
	if state, err := term.GetState(fd); err == nil {
		defer addCleanupHook(func() { term.Restore(fd, state) })()
	}
	fmt.Fprint(t.prompt, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(t.prompt)
	if err != nil {
		return "", errors.New("could not read from the terminal")
	}
	s := string(b)
	clear(b)
	return s, nil
}

// lineReader reads one secret per line for --passphrase-stdin.
type lineReader struct{ r *bufio.Reader }

// next returns the next line with exactly one trailing "\n" or "\r\n"
// removed, and nothing else.
func (l *lineReader) next() (string, error) {
	line, err := l.r.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("could not read a line from stdin")
	}
	if s, ok := strings.CutSuffix(line, "\r\n"); ok {
		return s, nil
	}
	return strings.TrimSuffix(line, "\n"), nil
}

// interactive reports whether secrets come from a terminal.
func (a *app) interactive() bool { return !a.passStdin }

// readSecret reads a passphrase or recovery key: the next stdin line with
// --passphrase-stdin, otherwise from the terminal without echo.
func (a *app) readSecret(prompt string) (string, error) {
	if a.passStdin {
		if a.lines == nil {
			a.lines = &lineReader{bufio.NewReader(a.stdin)}
		}
		return a.lines.next()
	}
	if !a.term.IsTerminal() {
		return "", errors.New("stdin is not a terminal; use --passphrase-stdin")
	}
	return a.term.ReadPassword(prompt)
}

// newPassphrase asks for a new passphrase, twice on a terminal, and enforces
// the minimum length unless --allow-weak-passphrase was given.
func (a *app) newPassphrase() (string, error) {
	p, err := a.readSecret("New passphrase: ")
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("the passphrase must not be empty")
	}
	if n := utf8.RuneCountInString(norm.NFC.String(p)); n < minPassphraseLen && !a.allowWeak {
		return "", fmt.Errorf("the passphrase must have at least %d characters", minPassphraseLen)
	}
	if a.interactive() {
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

// confirmRecoveryKey makes an interactive user retype the recovery key; it
// must decode to vk.
func (a *app) confirmRecoveryKey(vk *[core.KeySize]byte) error {
	typed, err := a.readSecret("Retype the recovery key to confirm: ")
	if err != nil {
		return err
	}
	got, err := core.DecodeRecoveryKey(typed)
	if err != nil {
		return err
	}
	defer clear(got[:])
	if subtle.ConstantTimeCompare(got[:], vk[:]) != 1 {
		return errors.New("that is not the same recovery key")
	}
	return nil
}

// unlock reads vault.json through the vault handle and unlocks it with a
// passphrase.
func (a *app) unlock(v *dirHandle) (*core.VaultKeys, error) {
	data, err := v.readConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &notVaultError{fmt.Sprintf("no %s in %s (not a vault?)", core.ConfigFile, display(v.path))}
		}
		return nil, fmt.Errorf("%s: %w", core.ConfigFile, err)
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
