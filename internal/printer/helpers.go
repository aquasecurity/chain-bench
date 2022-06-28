package printer

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

var (
	output io.Writer = os.Stdout
)

type Statistics struct {
	Passed  int
	Failed  int
	Unknown int
	Total   int
}
type reportResult struct {
	ID          string
	Name        string
	Descrition  string
	Remediation string
	Result      string
	Reason      string
	Url         string
}

type reportMetadata struct {
	Date       string
	Statistics Statistics
}

type reportResults struct {
	Metadata reportMetadata
	Results  []reportResult
}

// println prints a string to the current configured output
func println(msg string) {
	fmt.Fprintln(output, msg)
}

func PrintOutputToFile(data []checkmodels.CheckRunResult, outputFilePath string) {
	reportRes, statistics := getPrintFormat(data)

	// Populate the report metadata.
	reportMetadata := reportMetadata{
		Date:       time.Now().Format(time.RFC3339),
		Statistics: statistics,
	}

	// Populate the report.
	report := reportResults{
		reportMetadata,
		reportRes,
	}
	file, _ := json.MarshalIndent(report, "", "")
	err := ioutil.WriteFile(outputFilePath, file, 0644)
	if err != nil {
		PrintError("Failed to write to output file, make sure your path is valid")
	}
}

func getPrintFormat(results []checkmodels.CheckRunResult) ([]reportResult, Statistics) {
	resultsToDisplay := []reportResult{}
	statistics := Statistics{
		Passed:  0,
		Failed:  0,
		Unknown: 0,
		Total:   len(results),
	}

	for _, r := range results {
		resultsToDisplay = append(resultsToDisplay, reportResult{
			Name:        r.Metadata.Title,
			ID:          r.ID,
			Descrition:  r.Metadata.Description,
			Remediation: r.Metadata.Remediation,
			Result:      string(r.Result.Status),
			Reason:      r.Result.Details,
			Url:         r.Metadata.Url})

		switch r.Result.Status {
		case "Passed":
			statistics.Passed += 1
		case "Failed":
			statistics.Failed += 1
		case "Unknown":
			statistics.Unknown += 1
		}
	}

	return resultsToDisplay, statistics
}

func initializeStatistics() Statistics {
	return Statistics{Passed: 0, Failed: 0, Unknown: 0, Total: 0}
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
