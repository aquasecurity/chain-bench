package buildpipelines

import (
	pipelineinstructions "github.com/aquasecurity/chain-bench/internal/checks/build-pipelines/pipeline-instructions"
	pipelineintegrity "github.com/aquasecurity/chain-bench/internal/checks/build-pipelines/pipeline-integrity"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

func GetChecks() []*checkmodels.Check {
	checks := []*checkmodels.Check{}
	checks = append(checks, pipelineinstructions.GetChecks()...)
	checks = append(checks, pipelineintegrity.GetChecks()...)
	return checks
}
