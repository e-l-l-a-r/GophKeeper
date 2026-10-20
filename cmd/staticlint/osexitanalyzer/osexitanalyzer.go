// Package osexitanalyzer определяет анализатор, который запрещает прямой вызов os.Exit в функции main пакета main.
package osexitanalyzer

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Analyzer — это анализатор analysis.Analyzer для osexitanalyzer.
var Analyzer = &analysis.Analyzer{
	Name: "osexitanalyzer",
	Doc:  "проверка прямого вызова os.Exit в функции main пакета main",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if pass.Pkg.Name() != "main" {
		return nil, nil
	}

	for _, file := range pass.Files {
		// Игнорируем тесты
		fileName := pass.Fset.Position(file.Pos()).Filename
		if strings.Contains(fileName, "_test.go") {
			continue
		}

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "main" {
				return true
			}

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}

				ident, ok := selector.X.(*ast.Ident)
				if !ok || ident.Name != "os" || selector.Sel.Name != "Exit" {
					return true
				}

				pass.Reportf(call.Pos(), "прямой вызов os.Exit в функции main запрещен")
				return true
			})

			return false
		})
	}

	return nil, nil
}
