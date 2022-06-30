package pipelineintegrity

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
			Name: "Should fail and return number of piplines contain build job without SBOM task",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithPipeline(builders.
						NewPipelineBuilder().WithNoJobs().
						WithJob(builders.
							NewJobBuilder().WithNoTasks().
							WithTask("NORMAL_TASK_NAME", "commit").
							Build(),
						).
						Build(),
					).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.4.6", checksMetadata.Checks["2.4.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 pipeline(s) contain a build job without SBOM generation"}),
			},
		},
		{
			Name: "Multiple pipelines one with unpinned task should fail snd return number of tasks",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithPipeline(builders.
						NewPipelineBuilder().WithNoJobs().WithJob(builders.NewJobBuilder().WithTask("NORMAL_TASK_NAME", "tag").Build()).
						Build(),
					).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.4.2", checksMetadata.Checks["2.4.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 task(s) are not pinned"}),
			},
		},
		{
			Name: "valid input - all rules should pass",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{},
		},
		{
			Name: "Should return unkown when failed to fetch pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoPipelinesData().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.4.2", checksMetadata.Checks["2.4.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_are_missing}),
				checkmodels.ToCheckRunResult("2.4.6", checksMetadata.Checks["2.4.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_are_missing}),
			},
		},
		{
			Name: "Should return unkown when there are no pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithZeroPipelines().
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.4.2", checksMetadata.Checks["2.4.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
				checkmodels.ToCheckRunResult("2.4.6", checksMetadata.Checks["2.4.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
