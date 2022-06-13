package artifacts

import (
	packageregistries "github.com/aquasecurity/chain-bench/internal/checks/artifacts/package-registries"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

func GetChecks() []*checkmodels.Check {
	checks := []*checkmodels.Check{}
	checks = append(checks, packageregistries.GetChecks()...)
	return checks
}
