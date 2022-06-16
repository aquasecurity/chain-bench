package artifacts

import (
	accesstoartifacts "github.com/aquasecurity/chain-bench/internal/checks/artifacts/access-to-artifacts"
	packageregistries "github.com/aquasecurity/chain-bench/internal/checks/artifacts/package-registries"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

func GetChecks() []*checkmodels.Check {
	checks := []*checkmodels.Check{}
	checks = append(checks, accesstoartifacts.GetChecks()...)
	checks = append(checks, packageregistries.GetChecks()...)
	return checks
}
