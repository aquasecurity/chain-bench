package codechanges

import (
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/checks/consts"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
)

func TestCodeChangesChecker(t *testing.T) {
	tests := []testutils.CheckTest{
		{
			Name: "Organization with no branch protection fails all tests related to branch protection",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(nil).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with no repo settings permission - all tests related to branch protection return unknown",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithRepository(builders.NewRepositoryBuilder().WithNoRepoPemissions().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.13", checksMetadata.Checks["1.1.13"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_repository_missing_minimal_permissions}),
			},
		},
		{
			Name: "Couldnt get repostiroty data because of missing permissions or wrong url",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithNoRepositoryData().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.13", checksMetadata.Checks["1.1.13"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "Should return unknown for repository with no collaborators",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithRepository(builders.NewRepositoryBuilder().WithNoCollborator().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "Should return unknown when authourized user is not admin",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithRepository(builders.NewRepositoryBuilder().WithAdminCollborator(true, 0).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "Should fail when branch protection not requires dismissial restrictions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithDismissalRestrictions(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection not requires 2 minimum reviewers before merge",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithMinimumReviwersBeforeMerge(1).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection not requires dismiss stale reviews",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithDismissStaleReviews(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection not requires code owner review",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithCodeOwnersReview(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when repository with inactive branches",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithRepository(builders.NewRepositoryBuilder().WithBranch(builders.NewBranchBuilder().WithOldCommit().Build()).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
			},
		},
		{
			Name: "Should fail when branch protection not requires status checks before merge",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithStatusCheckEnabled(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection not requires branch to be up to date before merge",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithStrictMode(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection not requires conversation resolution",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithResolveConversations(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection not requires signed commits",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithRequiredSignedCommits(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when repositoty allows merge commit",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithRepository(builders.NewRepositoryBuilder().WithAllowMergeCommit(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.13", checksMetadata.Checks["1.1.13"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_linearHistory_mergeCommitEnabled}),
			},
		},
		{
			Name: "Should fail when repository with all merge options prevented",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithRepository(builders.NewRepositoryBuilder().WithAllowMergeCommit(false).WithAllowRebaseMerge(false).WithAllowSquashMerge(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.13", checksMetadata.Checks["1.1.13"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_linearHistory_requireRebaseOrSquashCommitEnabled}),
			},
		},
		{
			Name: "Should fail when branch protection not enforced on admins",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithEnforceAdmin(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection doesnt include restriction for pushing",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithPushRestrictions(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection doesnt include restriction for force push",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithForcePush(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Should fail when branch protection doesnt include restriction for deleting branch",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithBranchProtections(builders.NewBranchProtectionBuilder().WithDeleteBranch(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Valid input - all rules should pass",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().Build(),
			},
			Expected: []*checkmodels.CheckRunResult{},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests, checksMetadata)
}
