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
			Name: "Build job without SBOM task",
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
			Name: "Multiple pipelines one with unpinned task",
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
			Name: "valid input - include normal task",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{},
		},
		{
			Name: "Failed to fetch pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoPipelinesData().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.4.2", checksMetadata.Checks["2.4.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("2.4.6", checksMetadata.Checks["2.4.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
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
				checkmodels.ToCheckRunResult("2.4.2", checksMetadata.Checks["2.4.2"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
				checkmodels.ToCheckRunResult("2.4.6", checksMetadata.Checks["2.4.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
