package commands

import (
	"time"

	"github.com/aquasecurity/chain-bench/internal/checker"
	"github.com/aquasecurity/chain-bench/internal/checks"
	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/printer"
	"github.com/aquasecurity/chain-bench/internal/scm-clients/clients"
	"github.com/enescakir/emoji"
	"github.com/spf13/cobra"
)

func NewScanCommand() *cobra.Command {
	scanCommand := &cobra.Command{
		Use:   "scan",
		Short: "Run CIS Benchmarks checks against a software supply chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()
			logger.Infof("%v	Fetch Starting", emoji.TriangularFlag)
			assetsData, supportedChecks, err := clients.FetchClientData(accessToken, repositoryUrl, branch)
			if err != nil {
				logger.Error(err, "Failed to fetch client data")
				return err
			} else {
				logger.Infof("%v	Fetch succeeded", emoji.ChequeredFlag)
			}

			checks := checks.GetChecks(assetsData)
			results, errors := checker.RunChecks(assetsData, chainbenchConfig, checks)

			printer.PrintFindings(results, supportedChecks, outputFilePath, isQuiet, repositoryUrl, outputTemplateFilePath)
			printer.PrintErrors(errors)
			elapsed := time.Since(start)
			logger.Infof("Scan completed: %s", elapsed.Round(time.Millisecond))
			return nil
		},
	}

	scanCommand.PersistentFlags().StringVarP(&repositoryUrl,
		repositoryUrlFlagName, repositoryUrlShortFlag, "",
		"the url to the repository")

	scanCommand.PersistentFlags().StringVarP(&accessToken,
		accessTokenFlagName, accessTokenShortFlag, "",
		"the access token to use for the repository")

	scanCommand.PersistentFlags().StringVarP(&branch,
		branchFlagName, branchShortFlag, "",
		"the branch to scan branch protection for")

	return scanCommand
}
