package codechanges

import (
	"testing"
	"time"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

func TestCodeChangesChecker(t *testing.T) {
	tests := []testutils.CheckTest{
		{
			Name: "Organization with no branch protection",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
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
			Name: "Organization with no repo settings permission",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
			},
		},
		{
			Name: "Organization with branch protection with enforce approval of two strongly authenticated users",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithMinimumReviwersBeforeMerge(2).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
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
			Name: "Organization with branch protection with dissmiss stale approvals",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithDismissStaleReviews(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
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
			Name: "Organization with branch protection with restriction on who can dismiss",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAdminCollborator(true, 1).WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithDismissalRestrictions(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
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
			Name: "Organization with branch protection with restriction on who can dismiss and authorized user with no admin permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).WithAdminCollborator(false, 1).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithDismissalRestrictions(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
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
			Name: "Organization with branch protection with code owners enforcement",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithCodeOwnersReview(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
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
			Name: "Organization that enforce inactive branches",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now()}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithDismissStaleReviews(false).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
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
			Name: "Organization with branch protection with enforce that checks have passed before merge and no enforce that branch is up to date berfore merge",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithStatusCheckEnabled().WithRequireBranchToBeUpToDate(false).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
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
			Name: "Organization with branch protection with enforce that checks have passed before merge and with enforce that branch is up to date berfore merge",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithStatusCheckEnabled().WithRequireBranchToBeUpToDate(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with branch protection with enforce of resolve converstation before merge",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithResolveConversations(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with branch protection rules enforce on admins",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithEnforceAdmin(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with branch protection that restrict who can push",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithPushRestrictions(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with branch protection that restrict who can push",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithForcePush(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with branch protection that restrict who can push",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithDeleteBranch(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Organization with branch protection that require signed commits",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(-1, 0, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithRequiredSignedCommits(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive branches"}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "All Checks Passed",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithAuthorizedUser().WithOrganization(builders.NewOrganizationBuilder().Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAdminCollborator(true, 1).WithAllowRebaseMerge(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now()}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().WithMinimumReviwersBeforeMerge(2).WithDismissStaleReviews(true).WithDismissalRestrictions(true).
						WithCodeOwnersReview(true).WithRequiredSignedCommits(true).WithStatusCheckEnabled().WithRequireBranchToBeUpToDate(true).WithResolveConversations(true).WithEnforceAdmin(true).WithPushRestrictions(true).WithDeleteBranch(true).
						WithForcePush(true).
						Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.1.3", checksMetadata.Checks["1.1.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.4", checksMetadata.Checks["1.1.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.5", checksMetadata.Checks["1.1.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.6", checksMetadata.Checks["1.1.6"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.8", checksMetadata.Checks["1.1.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.9", checksMetadata.Checks["1.1.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.10", checksMetadata.Checks["1.1.10"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.11", checksMetadata.Checks["1.1.11"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.12", checksMetadata.Checks["1.1.12"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.14", checksMetadata.Checks["1.1.14"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.15", checksMetadata.Checks["1.1.15"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.16", checksMetadata.Checks["1.1.16"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.1.17", checksMetadata.Checks["1.1.17"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests)
}
