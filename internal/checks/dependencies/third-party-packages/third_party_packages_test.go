package thirdpartypackages

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
			Name: "Should return unknown when failed to fetch pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoPipelinesData().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("3.1.7", checksMetadata.Checks["3.1.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "Should return unknown with explanation when there are no pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithZeroPipelines().
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("3.1.7", checksMetadata.Checks["3.1.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
			},
		},
		{
			Name: "valid input - all rules should pass",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("3.1.7", checksMetadata.Checks["3.1.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Should fail and return number of dependencies when there is pipeline with unpinned job",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithZeroPipelines().WithPipeline(
					builders.NewPipelineBuilder().WithNoJobs().WithJob(builders.
						NewJobBuilder().
						WithTask("NORMAL_TASK_NAME", "tag").
						Build()).
						Build(),
				).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("3.1.7", checksMetadata.Checks["3.1.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 dependencies are not pinned"}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
