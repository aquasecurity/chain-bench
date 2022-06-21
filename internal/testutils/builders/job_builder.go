package builders

import (
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/utils"
	"github.com/argonsecurity/pipeline-parser/pkg/models"
)

type JobBuilder struct {
	job models.Job
}

func NewJobBuilder() *JobBuilder {
	return &JobBuilder{job: models.Job{
		Steps: []*models.Step{{
			Name: utils.GetPtr(testutils.ArgonScannerAction),
			Type: "task",
			Task: &models.Task{
				Name:        utils.GetPtr(testutils.ArgonScannerAction),
				VersionType: models.VersionType("commit"),
			},
		}, {
			Name: utils.GetPtr(testutils.SbomTask),
			Type: "task",
			Task: &models.Task{
				Name:        utils.GetPtr(testutils.SbomTask),
				VersionType: models.VersionType("commit"),
			},
		}},
		Metadata: models.Metadata{Build: true},
	},
	}
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

func (j *JobBuilder) WithNoVulnerabilityScannerTask() *JobBuilder {
	var newStepsList = []*models.Step{}

	for _, s := range j.job.Steps {
		if utils.GetValue(s.Name) != testutils.ArgonScannerAction &&
			utils.GetValue(s.Name) != testutils.TrivyScannerAction {
			newStepsList = append(newStepsList, s)
		}
	}

	j.job.Steps = newStepsList
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

func (j *JobBuilder) SetAsBuildJob(buildJob bool) *JobBuilder {
	j.job.Metadata.Build = buildJob
	return j
}

func (j *JobBuilder) WithNoTasks() *JobBuilder {
	j.job.Steps = []*models.Step{}
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
