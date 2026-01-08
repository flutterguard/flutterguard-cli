package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	preserveDirectives = flag.Bool("preserve-directives", true, "preserve //go: directives and build tags")
	rootDir            = flag.String("root", ".", "root directory to process")
)

var (
	reGoDirective = regexp.MustCompile(`^//\s*go:`)
	reBuildTag1   = regexp.MustCompile(`^//\s*\+build`)  // legacy
	reBuildTag2   = regexp.MustCompile(`^//\s*go:build`) // new style
)

func main() {
	flag.Parse()

	err := filepath.WalkDir(*rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if shouldSkipDir(name, path) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" {
			if err := processFile(path, *preserveDirectives); err != nil {
				return fmt.Errorf("processing %s: %w", path, err)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func shouldSkipDir(name, fullPath string) bool {
	if strings.HasPrefix(name, ".") && (name == ".git" || name == ".github") {
		return true
	}
	switch name {
	case "vendor", "build", "dist", "node_modules":
		return true
	}

	if strings.Contains(fullPath, string(filepath.Separator)+"apk"+string(filepath.Separator)) && strings.Contains(fullPath, "-decompiled") {
		return true
	}
	return false
}

func processFile(path string, keepDirectives bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return err
	}

	// Filter comments
	var filtered []*ast.CommentGroup
	if keepDirectives {
		for _, cg := range file.Comments {

			keep := false
			for _, c := range cg.List {
				txt := strings.TrimSpace(c.Text)
				if reGoDirective.MatchString(txt) || reBuildTag1.MatchString(txt) || reBuildTag2.MatchString(txt) {
					keep = true
					break
				}
			}
			if keep {
				filtered = append(filtered, cg)
			}
		}
		file.Comments = filtered
	} else {

		file.Comments = nil
	}

	// Print without other comments
	var buf bytes.Buffer
	cfg := &printer.Config{Mode: printer.TabIndent | printer.UseSpaces, Tabwidth: 8}
	if err := cfg.Fprint(&buf, fset, file); err != nil {
		return err
	}

	out := buf.Bytes()
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return os.WriteFile(path, out, 0o644)
}
