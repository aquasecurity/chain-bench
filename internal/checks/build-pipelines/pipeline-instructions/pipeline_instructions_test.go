package pipelineinstructions

import (
	"testing"

	"github.com/argonsecurity/chain-bench/internal/checks/common"
	"github.com/argonsecurity/chain-bench/internal/checks/consts"
	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
	"github.com/argonsecurity/chain-bench/internal/testutils"
	"github.com/argonsecurity/chain-bench/internal/testutils/builders"
)

const (
	vulnerabilityScanningTask = "argonsecurity/scanner-action"
)

func TestBuildChecker(t *testing.T) {
	tests := []testutils.CheckTest{
		{
			Name: "Multiple pipelines, one with a vulnerability and secrets scanning task",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithPipeline(builders.
						NewPipelineBuilder().
						WithJob(builders.
							NewJobBuilder().
							SetAsBuildJob().
							WithTask("NORMAL_TASK_NAME", "commit").
							Build(),
						).
						Build(),
					).WithPipeline(builders.
					NewPipelineBuilder().
					WithJob(builders.
						NewJobBuilder().
						WithTask("NORMAL_TASK_NAME", "commit").
						WithTask(vulnerabilityScanningTask, "tag").
						Build()).
					Build(),
				).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Normal job",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithPipeline(
					builders.NewPipelineBuilder().
						WithJob(builders.
							NewJobBuilder().
							WithTask("NORMAL_TASK_NAME", "commit").
							Build()).
						Build(),
				).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_noBuildJob}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_pipelinesNotScannedForVulnerabilities}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_repositoryNotScannedForSecrets}),
			},
		},
		{
			Name: "Job with a pipeline with a vulnerability and secrets scanning scan task",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithPipeline(builders.
						NewPipelineBuilder().
						WithJob(builders.
							NewJobBuilder().
							WithTask(vulnerabilityScanningTask, "commit").
							Build()).
						Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_noBuildJob}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Failed to fetch pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "No pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithZeroPipelines().
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
			},
		},
		{
			Name: "Permissive default repository roles",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.
						NewOrganizationBuilder().
						WithReposDefaultPermissions("write").
						Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_organization_premissiveDefaultRepositoryPermissions}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "Non permissive default repository roles",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.
						NewOrganizationBuilder().
						WithReposDefaultPermissions("read").
						Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "Organization default repository permissions not fetched",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.
						NewOrganizationBuilder().
						Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_missingMinimalPermissions}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "A pipeline with a secret scan command",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithPipeline(builders.
						NewPipelineBuilder().
						WithJob(builders.
							NewJobBuilder().
							WithShellCommand("secret scan", "spectral scan").
							Build()).
						Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_noBuildJob}),
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_pipelinesNotScannedForVulnerabilities}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests)
}
