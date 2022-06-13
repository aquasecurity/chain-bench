package common

import (
	_ "embed"

	"github.com/aquasecurity/chain-bench/internal/checks/common/opa"
	"github.com/aquasecurity/chain-bench/internal/consts"
	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

//go:embed assets/utils.rego
var utilsModule string

//go:embed assets/permissions.rego
var permissionsModule string

//go:embed assets/consts.rego
var constsModule string

func getRegoLibs(regoQuery string) []checkmodels.RegoCustomModule {
	return []checkmodels.RegoCustomModule{
		{
			Name:    "security.rego",
			Content: regoQuery,
		},
		{
			Name:    "Generic",
			Content: utilsModule,
		},
		{
			Name:    "Consts",
			Content: constsModule,
		},
		{
			Name:    "Permissions",
			Content: permissionsModule,
		},
	}
}

func GetRegoRunAction(regoQuery string, metadata checkmodels.CheckMetadataMap) checkmodels.CheckAction {
	regoLibs := getRegoLibs(regoQuery)

	return func(data *checkmodels.CheckData) ([]*checkmodels.CheckRunResult, error) {
		results, err := opa.RunRego(data.AssetsMetadata, regoLibs, &metadata)
		if err != nil {
			return nil, err
		}
		return results, nil
	}
}

func ValidateCheck(id string, cm checkmodels.CheckMetadata, action checkmodels.CheckAction, url string) error {

	if id == "" {
		return consts.ErrorNoCheckID
	}
	if cm.Title == "" {
		return consts.ErrorNoName
	}

	if cm.Description == "" {
		return consts.ErrorNoDescription
	}

	if cm.Remediation == "" {
		return consts.ErrorNoRemediation
	}

	if url == "" {
		return consts.ErrorNoUrl
	}

	if cm.Type == "" {
		return consts.ErrorNoType
	}

	if cm.Entity == "" {
		return consts.ErrorNoEntity
	}

	if action == nil {
		return consts.ErrorNoCheckAction
	}

	return nil
}

func ValidateChecks(check checkmodels.Check) error {
	for id, metadata := range check.CheckMetadataMap.Checks {
		if err := ValidateCheck(id, metadata, check.Action, check.Url); err != nil {
			logger.Errorf(err, "error in register check Id: %s", id)
			return err
		}
	}
	return nil
}

func AppendCheck(checks *[]*checkmodels.Check, action checkmodels.Check) error {
	err := ValidateChecks(action)
	if err == nil {
		*checks = append(*checks, &action)
	}

	return err
}
