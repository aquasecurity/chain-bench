package printer

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/google/uuid"
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
	ScanID     uuid.UUID  `json:"scan_id"`
	Statistics Statistics `json:"statistics"`
	Url        string     `json:"url,omitempty"`
}

type reportResults struct {
	Metadata reportMetadata `json:"metadata"`
	Results  []reportResult `json:"results"`
}

// println prints a string to the current configured output
func println(msg string) {
	fmt.Fprintln(output, msg)
}

func PrintOutputToFile(data []checkmodels.CheckRunResult, outputFilePath string, repositoryUrl string, outputTemplate string) {
	reportRes, statistics := getPrintData(data)

	// Populate the report metadata.
	reportMetadata := reportMetadata{
		Date:       time.Now().Format(time.RFC3339),
		ScanID:     uuid.New(),
		Url:        repositoryUrl,
		Statistics: statistics,
	}

	// Populate the report.
	report := reportResults{
		reportMetadata,
		reportRes,
	}

	if strings.HasPrefix(outputTemplate, "@") {
		buf, err := os.ReadFile(strings.TrimPrefix(outputTemplate, "@"))
		if err != nil {
			logger.Errorf(err, "error retrieving template from path:", outputTemplate)
		}
		outputTemplate = string(buf)
		t, _ := template.New("output template").Parse(outputTemplate)
		outputFile, err := os.OpenFile(outputFilePath, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			PrintError("Failed to create an output file, make sure your path is valid")
		}
		err = t.Execute(outputFile, reportRes)
		if err != nil {
			PrintError("Failed to create the template, check the template is valid")
		}
	} else {
		file, _ := json.MarshalIndent(report, "", "  ")
		err := ioutil.WriteFile(outputFilePath, file, 0644)
		if err != nil {
			PrintError("Failed to write to output file, make sure your path is valid")
		}
	}
}

func getPrintData(results []checkmodels.CheckRunResult) ([]reportResult, Statistics) {
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
