package builders

import (
	"github.com/aquasecurity/chain-bench/internal/utils"
	"github.com/argonsecurity/pipeline-parser/pkg/models"
)

type PipelineBuilder struct {
	pipeline *models.Pipeline
}

func NewPipelineBuilder() *PipelineBuilder {
	return &PipelineBuilder{pipeline: &models.Pipeline{
		Jobs: []*models.Job{utils.GetPtr(NewJobBuilder().Build())},
	}}
}

func (p *PipelineBuilder) WithNoJobs() *PipelineBuilder {
	p.pipeline.Jobs = make([]*models.Job, 0)
	return p
}

func (p *PipelineBuilder) WithJob(job models.Job) *PipelineBuilder {
	if p.pipeline.Jobs == nil {
		p.pipeline.Jobs = make([]*models.Job, 0)
	}
	p.pipeline.Jobs = append(p.pipeline.Jobs, &job)
	return p
}

func (p *PipelineBuilder) Build() *models.Pipeline {
	return p.pipeline
}
