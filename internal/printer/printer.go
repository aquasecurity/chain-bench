package printer

import (
	_ "embed"
	"fmt"
	"sort"

	"github.com/alexeyco/simpletable"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/hashicorp/go-version"
)

type CellData struct {
	text  string
	color string
	align int
	span  int
}

var table *simpletable.Table

func init() {
	table = simpletable.New()
	table.SetStyle(simpletable.StyleCompactLite)
}

func PrintFindings(results []checkmodels.CheckRunResult, outputFilePath string, isQuiet bool, repositoryUrl string, outputTemplateFilePath string) {
	sortResuls(results)
	if outputFilePath != "" {
		PrintOutputToFile(results, outputFilePath, repositoryUrl, outputTemplateFilePath)
	}
	if !isQuiet {
		s := NewStatistics()
		table.Header = CreateHeader([]string{"ID", "Name", "Result", "Reason"})
		for _, row := range results {
			rowData := []CellData{
				{text: row.ID},
				{text: row.Metadata.Title},
				getResultData(row.Result.Status),
				{text: row.Result.Details},
			}
			table.Body.Cells = append(table.Body.Cells, CreateBodyRow(rowData))
			s.Add(row.Result.Status)
		}
		table.Footer = CreateFooter(s, len(table.Header.Cells))
		fmt.Println(table.String())
	}
}

func sortResuls(results []checkmodels.CheckRunResult) {
	sort.SliceStable(results, func(i, j int) bool {
		id1, _ := version.NewVersion(results[i].ID)
		id2, _ := version.NewVersion(results[j].ID)
		return id1.LessThan(id2)
	})
}

func getResultData(status checkmodels.ResultStatus) CellData {
	if status == checkmodels.Passed {
		return CellData{text: string(status), color: ColorGreen}
	} else if status == checkmodels.Unknown {
		return CellData{text: string(status), color: ColorYellow}
	} else {
		return CellData{text: string(status), color: ColorRed}
	}
}

func PrintErrors(errors []error) {
	if len(errors) > 0 {
		PrintError(errorsToString(errors))
	}
}

func errorsToString(errs []error) string {
	errorMessages := ""
	for _, err := range errs {
		errorMessages += fmt.Sprintln(err.Error())
	}
	return errorMessages
}
