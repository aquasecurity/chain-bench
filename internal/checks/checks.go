package checks

import (
	"github.com/aquasecurity/chain-bench/internal/checks/artifacts"
	buildpipelines "github.com/aquasecurity/chain-bench/internal/checks/build-pipelines"
	"github.com/aquasecurity/chain-bench/internal/checks/dependencies"
	sourcecode "github.com/aquasecurity/chain-bench/internal/checks/source-code"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

func GetChecks(ad *checkmodels.AssetsData) []*checkmodels.Check {
	checks := make([]*checkmodels.Check, 0)
	checks = append(checks, sourcecode.GetChecks()...)
	checks = append(checks, buildpipelines.GetChecks()...)
	checks = append(checks, dependencies.GetChecks()...)
	checks = append(checks, artifacts.GetChecks()...)
	return checks
}
