package validatepackages

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
			Name: "Failed to fetch pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("3.2.2", checksMetadata.Checks["3.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("3.2.3", checksMetadata.Checks["3.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
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
				checkmodels.ToCheckRunResult("3.2.2", checksMetadata.Checks["3.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
				checkmodels.ToCheckRunResult("3.2.3", checksMetadata.Checks["3.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
			},
		},
		{
			Name: "Multiple pipelines, one with a vulnerability scanner task",
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
				checkmodels.ToCheckRunResult("3.2.2", checksMetadata.Checks["3.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("3.2.3", checksMetadata.Checks["3.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Normal job without vulnerability scanner task",
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
				checkmodels.ToCheckRunResult("3.2.2", checksMetadata.Checks["3.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_dependencies_pipelinesNotScannedForVulnerabilities}),
				checkmodels.ToCheckRunResult("3.2.3", checksMetadata.Checks["3.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_dependencies_pipelinesNotScannedForLicenses}),
			},
		},
		{
			Name: "Job with a pipeline with a vulnerability scanner task",
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
				checkmodels.ToCheckRunResult("3.2.2", checksMetadata.Checks["3.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("3.2.3", checksMetadata.Checks["3.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests)
}
