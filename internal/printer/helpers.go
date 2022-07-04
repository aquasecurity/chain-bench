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

type reportResult struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Result      string `json:"result,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Url         string `json:"url,omitempty"`
}

type reportMetadata struct {
	Date       string     `json:"date"`
	Statistics Statistics `json:"statistics"`
}

type reportResults struct {
	Metadata reportMetadata `json:"metadata"`
	Results  []reportResult `json:"results"`
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
	file, _ := json.MarshalIndent(report, "", "  ")
	err := ioutil.WriteFile(outputFilePath, file, 0644)
	if err != nil {
		PrintError("Failed to write to output file, make sure your path is valid")
	}
}

func getPrintFormat(results []checkmodels.CheckRunResult) ([]reportResult, Statistics) {
	resultsToDisplay := []reportResult{}
	statistics := NewStatistics()

	for _, r := range results {
		resultsToDisplay = append(resultsToDisplay, reportResult{
			Name:        r.Metadata.Title,
			ID:          r.ID,
			Description: r.Metadata.Description,
			Remediation: r.Metadata.Remediation,
			Result:      string(r.Result.Status),
			Reason:      r.Result.Details,
			Url:         r.Metadata.Url})

		statistics.Add(r.Result.Status)
	}

	return resultsToDisplay, statistics
}

// PrintErrorf prints a message with error color
func PrintError(msg string) {
	println(fmt.Sprint(ColorRed, msg))
}
