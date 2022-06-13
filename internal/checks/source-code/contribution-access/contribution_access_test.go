package contributionaccess

import (
	_ "embed"
	"testing"
	"time"

	"github.com/argonsecurity/chain-bench/internal/checks/common"
	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
	"github.com/argonsecurity/chain-bench/internal/testutils"
	"github.com/argonsecurity/chain-bench/internal/testutils/builders"
	"github.com/argonsecurity/chain-bench/internal/utils"
)

func TestOrganizationChecker(t *testing.T) {
	tests := []testutils.CheckTest{
		{
			Name: "Organization with unverified status, and missing permission to fetch org and repo settings",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithVerifiedBadge(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with verified status, and missing permission to fetch org and repo settings",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().
					WithVerifiedBadge(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Organization with unverified status, strict default permission , 2mfa enabled, and missing permission repo settings",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().
					WithVerifiedBadge(false).WithReposDefaultPermissions("read").WithMFAEnabled(true).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with unverified status, permissive default permission , 2mfa disabled, and missing permission repo settings",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().
					WithVerifiedBadge(false).WithReposDefaultPermissions("write").WithMFAEnabled(false).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with unverified status, permissive default permission , 2mfa disabled, and branch protection status check is not validate",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().
						WithVerifiedBadge(false).WithReposDefaultPermissions("write").WithMFAEnabled(false).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowMergeCommit(true).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with unverified status, permissive default permission , 2mfa disabled, and branch protecton status check is not validate, and active commit",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().
						WithVerifiedBadge(false).WithReposDefaultPermissions("write").WithMFAEnabled(false).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowMergeCommit(true).Build()).
					WithBranch(builders.NewBranchBuilder().WithCommit("GD2", utils.Timestamp{Time: time.Now()}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with unverified status, permissive default permission , 2mfa disabled, and branch protection status check is not validate",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().
						WithVerifiedBadge(false).WithReposDefaultPermissions("write").WithMFAEnabled(false).Build()).
					WithRepository(builders.NewRepositoryBuilder().WithAllowMergeCommit(true).Build()).
					WithBranch(builders.NewBranchBuilder().
						WithCommit("GD2", utils.Timestamp{Time: time.Now().AddDate(0, -4, 0)}).Build()).
					WithBranch(builders.NewBranchBuilder().
						WithCommit("gfd3sasss", utils.Timestamp{Time: time.Now().AddDate(0, -1, 0)}).Build()).
					WithBranchProtections(builders.NewBranchProtectionBuilder().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with unverified status, permissive default permission , 2mfa disabled, with org admin permiossion, org has 1 admin",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithVerifiedBadge(false).WithMembers("admin", 1).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Organization with unverified status, permissive default permission , 2mfa disabled, with org admin permiossion, org has 2 admin",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithVerifiedBadge(false).WithMembers("admin", 2).Build()).WithRepository(builders.NewRepositoryBuilder().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "2 inactive users"}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Repository with an less then 2 admins",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithVerifiedBadge(false).WithReposDefaultPermissions("write").WithMFAEnabled(false).Build()).WithRepository(builders.NewRepositoryBuilder().WithAdminCollborator(true, 1).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Repository with 2 admins and repo permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithVerifiedBadge(false).WithReposDefaultPermissions("write").WithMFAEnabled(false).Build()).WithRepository(builders.NewRepositoryBuilder().WithAdminCollborator(true, 2).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Repository with 2 admins and no repo permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithVerifiedBadge(false).WithMFAEnabled(false).Build()).WithRepository(builders.NewRepositoryBuilder().WithAdminCollborator(true, 2).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
			},
		},
		{
			Name: "Repository with 2 members and no repo permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithMembers("member", 2).Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Repository with 2 members no recent commits",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithMembers("member", 2).Build()).WithRepository(builders.NewRepositoryBuilder().Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "2 inactive users"}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Repository with 2 members one stale",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithMembers("member", 2).Build()).WithRepository(builders.NewRepositoryBuilder().WithCommit("user0").Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 inactive users"}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
		{
			Name: "Repository with 2 members and no stale",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().WithOrganization(builders.NewOrganizationBuilder().WithMembers("member", 2).Build()).WithRepository(builders.NewRepositoryBuilder().WithCommit("user0").WithCommit("user1").Build()).Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("1.3.1", checksMetadata.Checks["1.3.1"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
				checkmodels.ToCheckRunResult("1.3.3", checksMetadata.Checks["1.3.3"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed}),
				checkmodels.ToCheckRunResult("1.3.5", checksMetadata.Checks["1.3.5"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.7", checksMetadata.Checks["1.3.7"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.8", checksMetadata.Checks["1.3.8"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown}),
				checkmodels.ToCheckRunResult("1.3.9", checksMetadata.Checks["1.3.9"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests)
}
