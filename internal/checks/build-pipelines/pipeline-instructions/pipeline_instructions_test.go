package pipelineinstructions

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
			Name: "should return unknown with explanation when organization wasnt fetched",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoOrganization().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_notFetched}),
			},
		},
		{
			Name: "should return unknown with explanation when organization permissions missing",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("").Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_organization_missingMinimalPermissions}),
			},
		},
		{
			Name: "Valid input - all rules should pass",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{},
		},
		{
			Name: "should return unknown when pipelines fetching was failed",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoPipelinesData().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_are_missing}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_are_missing}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_are_missing}),
			},
		},
		{
			Name: "should return unknown with explanation when there are no pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithZeroPipelines().
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_pipeline_noPipelinesFound}),
			},
		},
		{
			Name: "Should fail when build job not found in pipelines",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithZeroPipelines().WithPipeline(builders.NewPipelineBuilder().WithNoJobs().WithJob(builders.NewJobBuilder().SetAsBuildJob(false).Build()).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.1", checksMetadata.Checks["2.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_noBuildJob}),
			},
		},
		{
			Name: "Should fail when the organization is with strict repo permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("write").Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.5", checksMetadata.Checks["2.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_organization_premissiveDefaultRepositoryPermissions}),
			},
		},
		{
			Name: "Should fail with explanation when repository have no scanning tasks",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithZeroPipelines().WithPipeline(builders.NewPipelineBuilder().WithNoJobs().WithJob(builders.NewJobBuilder().WithNoTasks().WithTask("aquasecurity/trivy-action", "tag").Build()).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.8", checksMetadata.Checks["2.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_repositoryNotScannedForSecrets}),
			},
		},
		{
			Name: "Should fail with explanation when pipelines scanning tasks are missing",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithZeroPipelines().WithPipeline(builders.NewPipelineBuilder().WithNoJobs().WithJob(builders.NewJobBuilder().WithNoTasks().WithTask("zricethezav/gitleaks-action", "tag").Build()).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("2.3.7", checksMetadata.Checks["2.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_pipeline_pipelinesNotScannedForVulnerabilities}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
