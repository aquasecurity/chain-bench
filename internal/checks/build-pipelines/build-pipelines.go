package buildpipelines

import (
	pipelineinstructions "github.com/argonsecurity/chain-bench/internal/checks/build-pipelines/pipeline-instructions"
	pipelineintegrity "github.com/argonsecurity/chain-bench/internal/checks/build-pipelines/pipeline-integrity"
	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
)

func GetChecks() []*checkmodels.Check {
	checks := []*checkmodels.Check{}
	checks = append(checks, pipelineinstructions.GetChecks()...)
	checks = append(checks, pipelineintegrity.GetChecks()...)
	return checks
}
