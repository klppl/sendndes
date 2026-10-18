// Command valv is the Valv command-line tool (SPEC 11, step 2).
//
// Usage:
//
//	valv init <vault-dir>
//	valv add <file> [--dir <path>] [--name <name>]
//	valv ls [--dir <path>]
//	valv get <id-or-path> [-o <out>] [--force]
//	valv ingest [--inbox <dir>]
//	valv verify
//	valv passwd
//	valv recover <vault-dir> [--force]
//
// Every command except init and recover finds the vault through --vault,
// then $VALV_VAULT, then the current directory. Passphrases are read from the
// terminal without echo, or one per line from stdin with --passphrase-stdin.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const usage = `usage: valv <command> [arguments]

commands:
  init <vault-dir>                       create a new vault
  add <file> [--dir <path>] [--name <n>] encrypt a file into the vault
  ls [--dir <path>]                      list files
  get <id-or-path> [-o <out>] [--force]  decrypt a file (-o - writes to stdout)
  ingest [--inbox <dir>]                 move sealed inbox files into the vault
  verify                                 authenticate every file in the vault
  passwd                                 change the passphrase
  recover <vault-dir> [--force]          rebuild vault.json from the recovery key

common flags:
  --vault <dir>         vault directory (default $VALV_VAULT, then .)
  --passphrase-stdin    read passphrases from stdin, one per line
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// app holds what one invocation needs.
type app struct {
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	vault     string
	passStdin bool
	lines     *lineReader
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 1
	}
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr}
	commands := map[string]func([]string) error{
		"init":    a.cmdInit,
		"add":     a.cmdAdd,
		"ls":      a.cmdLs,
		"get":     a.cmdGet,
		"ingest":  a.cmdIngest,
		"verify":  a.cmdVerify,
		"passwd":  a.cmdPasswd,
		"recover": a.cmdRecover,
	}
	name := args[0]
	if name == "help" || name == "-h" || name == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(stderr, "valv: unknown command %q (see valv help)\n", name)
		return 1
	}
	if err := cmd(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintf(stderr, "valv: %s\n", oneLine(err.Error()))
		return 1
	}
	return 0
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// flags returns a flag set with the common flags. withVault is false for
// commands that take the vault directory as an argument.
func (a *app) flags(name string, withVault bool) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if withVault {
		fs.StringVar(&a.vault, "vault", "", "vault directory")
	}
	fs.BoolVar(&a.passStdin, "passphrase-stdin", false, "read passphrases from stdin")
	return fs
}

// parse parses flags that may come before or after positional arguments
// and checks the number of positionals.
func parse(fs *flag.FlagSet, args []string, minPos, maxPos int) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, fmt.Errorf("%s: %v", fs.Name(), err)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		if args[0] == "--" {
			pos = append(pos, args[1:]...)
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) < minPos || len(pos) > maxPos {
		return nil, fmt.Errorf("%s: wrong number of arguments (see valv help)", fs.Name())
	}
	return pos, nil
}

// vaultDir resolves the vault directory.
func (a *app) vaultDir() string {
	if a.vault != "" {
		return a.vault
	}
	if v := os.Getenv("VALV_VAULT"); v != "" {
		return v
	}
	return "."
}
