package checkmodels

import (
	"strings"

	"github.com/aquasecurity/chain-bench/internal/config"
	"github.com/aquasecurity/chain-bench/internal/models"
	pipelineModels "github.com/argonsecurity/pipeline-parser/pkg/models"
)

type ScannerType string

const (
	Rego   ScannerType = "Rego"
	Custom ScannerType = "Custom"
)

type CheckType string

const (
	SCM CheckType = "SCM"
)

type EntityType string

const (
	Organization EntityType = "Organization"
	Repository   EntityType = "Repository"
)

type CheckData struct {
	Configuration  *config.Configuration
	AssetsMetadata *AssetsData
}

type AssetsData struct {
	AuthorizedUser    *models.User
	Organization      *models.Organization
	Repository        *models.Repository
	BranchProtections *models.Protection
	Users             []*models.User
	Pipelines         []*pipelineModels.Pipeline
	Registry          *models.PackageRegistry
}

type ResultStatus string

const (
	Passed  ResultStatus = "Passed"
	Failed  ResultStatus = "Failed"
	Unknown ResultStatus = "Unknown"
)

type CheckMetadataMap struct {
	ID     string
	Name   string
	Url    string
	Checks map[string]CheckMetadata
}

type CheckMetadata struct {
	Title       string
	Type        CheckType
	Entity      EntityType
	Description string
	Remediation string
	Url         string
	ScannerType
}

type CheckResult struct {
	Status  ResultStatus `json:"status,omitempty"`
	Details string       `json:"details,omitempty"`
}

type CheckIdToCheckResultMap map[string]CheckResult

type CheckAction func(*CheckData) ([]*CheckRunResult, error)

type Check struct {
	CheckMetadataMap
	Action CheckAction
	ScannerType
}

type CheckRunResult struct {
	ID       string
	Metadata CheckMetadata
	Result   *CheckResult
}

type RegoCustomModule struct {
	Name    string
	Content string
}

func ToCheckRunResult(id string, metadata CheckMetadata, sectionUrl string, result *CheckResult) *CheckRunResult {
	return &CheckRunResult{
		ID: id,
		Metadata: CheckMetadata{
			Title:       metadata.Title,
			Type:        metadata.Type,
			Entity:      metadata.Entity,
			Description: metadata.Description,
			Remediation: metadata.Remediation,
			Url:         getPermalink(sectionUrl, id, metadata.Title),
			ScannerType: metadata.ScannerType,
		},
		Result: result}
}

func getPermalink(sectionUrl, id, name string) string {
	parsedId := fmt.Sprintf("#%s", strings.ToLower(strings.ReplaceAll(id, ".", "")))
	parsedName := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", "-"), "'", ""))
	return fmt.Sprintf("%s/%s-%s", sectionUrl, parsedId, parsedName)
}
