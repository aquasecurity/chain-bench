package builders

import (
	"github.com/argonsecurity/chain-bench/internal/utils"
	"github.com/argonsecurity/pipeline-parser/pkg/models"
)

type JobBuilder struct {
	job models.Job
}

func NewJobBuilder() *JobBuilder {
	return &JobBuilder{job: models.Job{}}
}

func (j *JobBuilder) WithTask(name, versionType string) *JobBuilder {
	j.appendStep(models.Step{
		Name: utils.GetPtr(name),
		Type: "task",
		Task: &models.Task{
			Name:        utils.GetPtr(name),
			VersionType: models.VersionType(versionType),
		},
	})
	return j
}

func (j *JobBuilder) WithShellCommand(name string, command string) *JobBuilder {
	j.appendStep(models.Step{
		Name: utils.GetPtr(name),
		Type: "shell",
		Shell: &models.Shell{
			Script: utils.GetPtr(command),
		},
	})
	return j
}

func (j *JobBuilder) SetAsBuildJob() *JobBuilder {
	j.job.Metadata.Build = true
	return j
}

func (j *JobBuilder) appendStep(step models.Step) *JobBuilder {
	steps := j.job.Steps
	if steps == nil {
		steps = make([]*models.Step, 0)
	}
	j.job.Steps = append(steps, &step)
	return j
}

func (p *JobBuilder) Build() models.Job {
	return p.job
}
