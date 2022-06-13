package printer

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

var (
	output io.Writer = os.Stdout
)

type Statistics struct {
	Passed int
	Failed int
}
type displayResult struct {
	ID          string
	Name        string
	Descrition  string
	Remediation string
	Result      string
	Reason      string
	Url         string
}

// println prints a string to the current configured output
func println(msg string) {
	fmt.Fprintln(output, msg)
}

func PrintOutputToFile(data []checkmodels.CheckRunResult, outputFilePath string) {
	file, _ := json.MarshalIndent(getPrintFormat(data), "", "")
	err := ioutil.WriteFile(outputFilePath, file, 0644)
	if err != nil {
		PrintError("Failed to write to output file, make sure your path is valid")
	}
}

func getPrintFormat(results []checkmodels.CheckRunResult) []displayResult {
	resultsToDisplay := []displayResult{}
	for _, r := range results {
		resultsToDisplay = append(resultsToDisplay, displayResult{
			Name:        r.Metadata.Title,
			ID:          r.ID,
			Descrition:  r.Metadata.Description,
			Remediation: r.Metadata.Remediation,
			Result:      string(r.Result.Status),
			Reason:      r.Result.Details,
			Url:         r.Metadata.Url})
	}

	return resultsToDisplay
}

func initializeStatistics() Statistics {
	return Statistics{Passed: 0, Failed: 0}
}

func addToStatistics(s *Statistics, r checkmodels.ResultStatus) {
	if r == checkmodels.Passed {
		s.Passed++
	} else {
		s.Failed++
	}
}

// PrintErrorf prints a message with error color
func PrintError(msg string) {
	println(fmt.Sprint(ColorRed, msg))
}
