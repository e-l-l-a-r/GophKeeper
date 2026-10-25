package osexitanalyzer_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/e-l-l-a-r/gophkeeper/cmd/staticlint/osexitanalyzer"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), osexitanalyzer.Analyzer, "withexit", "lib")
}
