package core

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestNoDeterministicHookInReleaseBuild checks SPEC 10.9: fixed keys, ids and
// nonces exist only in test code behind the valv_testvectors tag.
func TestNoDeterministicHookInReleaseBuild(t *testing.T) {
	const genFile = "gen_vectors_test.go"
	plain := build.Default
	plain.BuildTags = nil
	tagged := build.Default
	tagged.BuildTags = []string{"valv_testvectors"}

	pkg, err := plain.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(pkg.TestGoFiles, genFile) || !slices.Contains(pkg.IgnoredGoFiles, genFile) {
		t.Errorf("%s is built without the tag", genFile)
	}
	tpkg, err := tagged.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(tpkg.TestGoFiles, genFile) {
		t.Errorf("%s is not a test file under the tag", genFile)
	}

	// No non-test file anywhere in the module mentions the tag.
	err = filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testvectors") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "valv_testvectors") {
			t.Errorf("%s mentions valv_testvectors", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// No exported function in the release package takes a key, id, nonce,
	// salt or random source as a parameter.
	forbidden := []string{"fk", "fileid", "id", "nonce", "wrapnonce", "metanonce", "ephpriv", "salt", "rand", "random", "seed"}
	fset := token.NewFileSet()
	for _, f := range pkg.GoFiles {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					if slices.Contains(forbidden, strings.ToLower(name.Name)) {
						t.Errorf("%s: exported %s takes %s", f, fn.Name.Name, name.Name)
					}
				}
			}
		}
	}
}
