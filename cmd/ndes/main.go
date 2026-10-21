// Command ndes is the Ndes command-line tool (SPEC 11, step 2).
//
// Usage:
//
//	ndes init <vault-dir>
//	ndes add <file> [--dir <path>] [--name <name>]
//	ndes ls [--dir <path>]
//	ndes get <id-or-path> [-o <out>] [--force] [--unverified-stream]
//	ndes ingest [--inbox <dir>]
//	ndes pull --server <url> --token-file <file>
//	ndes verify
//	ndes passwd
//	ndes recover <vault-dir> [--force]
//	ndes server-config
//
// Every command except init and recover finds the vault through --vault,
// then $NDES_VAULT, then the current directory. Passphrases are read from the
// terminal without echo, or one per line from stdin with --passphrase-stdin.
//
// Test seams in production code (package-level variables that only tests set; nothing in the
// command line or the environment can reach them):
//
//	initTestHook          commands.go  runs inside init after vault.json is written (failure injection)
//	pullTestTransport     pull.go      replaces the HTTP transport of `ndes pull` with an in-process handler
//	routeInterfaceLookup  route.go     replaces the OS route lookup of the Tailscale check (H1)
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const usage = `usage: ndes <command> [arguments]

commands:
  init <vault-dir>                       create a new vault
  add <file> [--dir <path>] [--name <n>] encrypt a file into the vault
  ls [--dir <path>]                      list files
  get <id-or-path> [-o <out>] [--force]  decrypt a file
  ingest [--inbox <dir>]                 move sealed inbox files into the vault
  pull --server <url> --token-file <f>   pull and ingest sealed files from a ndesd server
  verify                                 authenticate every file in the vault
  passwd                                 change the passphrase
  recover <vault-dir> [--force] [--unverified-key]
                                         rebuild vault.json from the recovery key
  recovery-key                           print the recovery key (needs the passphrase)
  server-config                          print the inbox server's inbox_pub and K_auth

get writes to a temp file and moves it into place only after the whole file
has been authenticated. It never writes inside the vault directory.
  -o -                  write to stdout; needs --unverified-stream, because
                        plaintext is emitted before authentication finishes and
                        a damaged file can produce a valid-looking prefix

common flags:
  --vault <dir>             vault directory (default $NDES_VAULT, then .)
  --passphrase-stdin        read passphrases from stdin, one per line
  --allow-weak-passphrase   accept a new passphrase under 12 characters (tests)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// app holds what one invocation needs.
type app struct {
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	term      terminal
	vault     string
	passStdin bool
	allowWeak bool
	lines     *lineReader
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr, term: osTerminal{in: stdin, prompt: stderr}}
	// Every command: temp files, init's directories and the terminal state
	// are cleaned up on SIGINT, SIGTERM, SIGHUP and SIGQUIT (SPEC 8).
	defer installSignalCleanup(os.Exit)()
	return a.run(args)
}

func (a *app) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, usage)
		return 1
	}
	commands := map[string]func([]string) error{
		"init":          a.cmdInit,
		"add":           a.cmdAdd,
		"ls":            a.cmdLs,
		"get":           a.cmdGet,
		"ingest":        a.cmdIngest,
		"pull":          a.cmdPull,
		"verify":        a.cmdVerify,
		"passwd":        a.cmdPasswd,
		"recover":       a.cmdRecover,
		"recovery-key":  a.cmdRecoveryKey,
		"server-config": a.cmdServerConfig,
	}
	name := args[0]
	if name == "help" || name == "-h" || name == "--help" {
		fmt.Fprint(a.stdout, usage)
		return 0
	}
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(a.stderr, "ndes: unknown command %q (see ndes help)\n", name)
		return 1
	}
	if err := cmd(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(a.stdout, usage)
			return 0
		}
		fmt.Fprintf(a.stderr, "ndes: %s\n", oneLine(err.Error()))
		return 1
	}
	return 0
}

// oneLine makes an error a single line with a single "ndes: " prefix: core
// errors carry their own.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "ndes: ", "")), " ")
}

// flags returns a flag set with the common flags. withVault is false for
// commands that take the vault directory as an argument; newPass adds
// --allow-weak-passphrase.
func (a *app) flags(name string, withVault, newPass bool) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if withVault {
		fs.StringVar(&a.vault, "vault", "", "vault directory")
	}
	fs.BoolVar(&a.passStdin, "passphrase-stdin", false, "read passphrases from stdin")
	if newPass {
		fs.BoolVar(&a.allowWeak, "allow-weak-passphrase", false, "accept a short new passphrase")
	}
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
		return nil, fmt.Errorf("%s: wrong number of arguments (see ndes help)", fs.Name())
	}
	return pos, nil
}

// vaultDir resolves the vault directory.
func (a *app) vaultDir() string {
	if a.vault != "" {
		return a.vault
	}
	if v := os.Getenv("NDES_VAULT"); v != "" {
		return v
	}
	return "."
}
