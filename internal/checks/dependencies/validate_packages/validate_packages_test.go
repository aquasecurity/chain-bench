package validatepackages

import (
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/checks/consts"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
)

func TestBuildChecker(t *testing.T) {
	tests := []testutils.CheckTest{
		{
			Name: "Failed to fetch pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoPipelinesData().Build(),
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
			Name: "Pipeline with one job without vulnerability scanner task",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithZeroPipelines().WithPipeline(
					builders.NewPipelineBuilder().WithNoJobs().
						WithJob(builders.
							NewJobBuilder().WithNoTasks().
							WithTask("NORMAL_TASK_NAME", "commit").WithNoVulnerabilityScannerTask().
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
			Name: "valid input - Job with a pipeline with a vulnerability scanner task",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("3.2.2", checksMetadata.Checks["3.2.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("3.2.3", checksMetadata.Checks["3.2.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
