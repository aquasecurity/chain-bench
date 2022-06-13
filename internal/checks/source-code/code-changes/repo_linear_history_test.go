package codechanges

import (
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/consts"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
)

func TestRepoLinearHistoryCheck(t *testing.T) {
	repoLinearHistoryMetadata := checksMetadata.Checks[repoLinearHistoryId]
	tests := []testutils.CheckTest{
		{
			Name: "Repository with rebase enabled commit and prevent merge commit",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(
						builders.NewRepositoryBuilder().
							WithAllowRebaseMerge(true).
							WithAllowMergeCommit(false).
							Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult(repoLinearHistoryId, repoLinearHistoryMetadata, checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Repository with squash enabled commit and prevent merge commit",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(
						builders.NewRepositoryBuilder().
							WithAllowSquashMerge(true).
							WithAllowMergeCommit(false).
							Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult(repoLinearHistoryId, repoLinearHistoryMetadata, checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Repository with merge enabled commit",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(
						builders.NewRepositoryBuilder().
							WithAllowMergeCommit(true).
							Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult(repoLinearHistoryId, repoLinearHistoryMetadata, checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_linearHistory_mergeCommitEnabled}),
			},
		},
		{
			Name: "Repository with all merge options prevented",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(
						builders.NewRepositoryBuilder().
							WithAllowMergeCommit(false).
							WithAllowRebaseMerge(false).
							WithAllowSquashMerge(false).
							Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult(repoLinearHistoryId, repoLinearHistoryMetadata, checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: consts.Details_linearHistory_requireRebaseOrSquashCommitEnabled}),
			},
		},
		{
			Name: "No repository",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithRepository(nil).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult(repoLinearHistoryId, repoLinearHistoryMetadata, checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
	}

	testutils.RunCheckTests(t, repoLinearHistoryCheck, tests)
}
