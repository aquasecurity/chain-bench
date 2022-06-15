package packageregistries

import (
	"testing"

	"github.com/aquasecurity/chain-bench/internal/checks/common"
	"github.com/aquasecurity/chain-bench/internal/checks/consts"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/testutils/builders"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

const (
	vulnerabilityScanningTask = "argonsecurity/scanner-action"
)

func TestPackageRegistryChecker(t *testing.T) {
	tests := []testutils.CheckTest{

		{
			Name: "no hooks permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("write").Build()).
					WithRepository(builders.NewRepositoryBuilder().Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_hooks_missingMinimalPermissions}),
			},
		},
		{
			Name: "repo permissions only, no org permissions",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("read").Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPackageWebHooks("https://endpoint.com", "0", nil).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown, Details: consts.Details_hooks_missingMinimalPermissions}),
			},
		},
		{
			Name: "ssl: 1 unsecured(ssl) org webhook and 1 unsecured(ssl) repo webhook",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("read").WithPackageWebHooks("https://endpoint.com", "1", utils.GetPtr("**")).
						Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPackageWebHooks("https://endpoint.com", "1", utils.GetPtr("**")).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "2 unsecured webhooks"}),
			},
		},
		{
			Name: "missing secret: 1 unsecured org webhook and 1 unsecured repo webhook",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("read").WithPackageWebHooks("https://endpoint.com", "0", nil).
						Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPackageWebHooks("https://endpoint.com", "0", nil).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "2 unsecured webhooks"}),
			},
		},
		{
			Name: "missing https: 1 unsecured org webhook and 1 unsecured repo webhook",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("read").WithPackageWebHooks("http://endpoint.com", "0", utils.GetPtr("**")).
						Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPackageWebHooks("http://endpoint.com", "0", utils.GetPtr("**")).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "2 unsecured webhooks"}),
			},
		},
		{
			Name: "1 unsecured org webhook",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("read").WithPackageWebHooks("http://endpoint.com", "0", utils.GetPtr("**")).
						Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPackageWebHooks("https://endpoint.com", "0", utils.GetPtr("**")).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 unsecured webhooks"}),
			},
		},
		{
			Name: "1 unsecured repo webhook",
			Data: &checkmodels.CheckData{
				AssetsMetadata: builders.NewAssetsDataBuilder().
					WithOrganization(builders.NewOrganizationBuilder().WithReposDefaultPermissions("read").WithPackageWebHooks("https://endpoint.com", "0", utils.GetPtr("**")).
						Build()).
					WithRepository(builders.NewRepositoryBuilder().WithPackageWebHooks("http://endpoint.com", "0", utils.GetPtr("**")).Build()).
					Build(),
			},
			Expected: []*checkmodels.CheckRunResult{
				checkmodels.ToCheckRunResult("4.3.4", checksMetadata.Checks["4.3.4"], checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Failed, Details: "1 unsecured webhooks"}),
			},
		},
	}
	testutils.RunCheckTests(t, common.GetRegoRunAction(regoQuery, checksMetadata), tests)
}
