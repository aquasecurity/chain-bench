package common

import (
	"testing"

	"github.com/argonsecurity/chain-bench/internal/consts"
	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
	"github.com/stretchr/testify/assert"
)

func createDummyAction() checkmodels.CheckAction {
	return func(data *checkmodels.CheckData) ([]*checkmodels.CheckRunResult, error) {
		return []*checkmodels.CheckRunResult{}, nil
	}
}

func TestValidateCheck(t *testing.T) {
	tests := []struct {
		Name          string
		Expected      error
		CheckMetadata checkmodels.CheckMetadata
		CheckId       string
		Action        checkmodels.CheckAction
	}{
		{
			Name:     "A check with all required fields",
			Expected: nil,
			CheckMetadata: checkmodels.CheckMetadata{
				Title:       "SOME NAME",
				Type:        checkmodels.SCM,
				Entity:      checkmodels.Organization,
				Description: "SOME DESCRIPTION",
				Remediation: "SOME REMEDIATION",
				Url:         "SOME URL",
			},
			CheckId: "1.1.9",
			Action:  createDummyAction(),
		},
		{
			Name:     "A check with no ID",
			Expected: consts.ErrorNoCheckID,
			CheckMetadata: checkmodels.CheckMetadata{
				Title:       "SOME NAME",
				Type:        checkmodels.SCM,
				Entity:      checkmodels.Organization,
				Description: "SOME DESCRIPTION",
				Remediation: "SOME REMEDIATION",
				Url:         "SOME URL",
			},
			CheckId: "",
			Action:  createDummyAction(),
		},
		{
			Name:     "A check with no name",
			Expected: consts.ErrorNoName,
			CheckMetadata: checkmodels.CheckMetadata{
				Type:        checkmodels.SCM,
				Entity:      checkmodels.Organization,
				Description: "SOME DESCRIPTION",
				Remediation: "SOME REMEDIATION",
				Url:         "SOME URL",
			},
			CheckId: "1.1.9",
			Action:  createDummyAction(),
		},
		{
			Name:     "A check with no description",
			Expected: consts.ErrorNoDescription,
			CheckMetadata: checkmodels.CheckMetadata{
				Type:   checkmodels.SCM,
				Entity: checkmodels.Organization,
				Title:  "SOME NAME",
				Url:    "SOME URL",
			},
			CheckId: "1.1.9",
			Action:  createDummyAction(),
		},
		{
			Name:     "A check with no remediation",
			Expected: consts.ErrorNoRemediation,
			CheckMetadata: checkmodels.CheckMetadata{
				Type:        checkmodels.SCM,
				Entity:      checkmodels.Organization,
				Title:       "SOME NAME",
				Description: "SOME DESCRIPTION",
				Url:         "SOME URL",
			},
			CheckId: "1.1.9",
			Action:  createDummyAction(),
		},
		{
			Name:     "A check with no url",
			Expected: consts.ErrorNoUrl,
			CheckMetadata: checkmodels.CheckMetadata{
				Type:        checkmodels.SCM,
				Entity:      checkmodels.Organization,
				Title:       "SOME NAME",
				Description: "SOME DESCRIPTION",
				Remediation: "SOME REMEDIATION",
			},
			CheckId: "1.1.9",
			Action:  createDummyAction(),
		},
		{
			Name:     "A check with no type",
			Expected: consts.ErrorNoType,
			CheckMetadata: checkmodels.CheckMetadata{
				Entity:      checkmodels.Organization,
				Title:       "SOME NAME",
				Description: "SOME DESCRIPTION",
				Remediation: "SOME REMEDIATION",
				Url:         "SOME URL",
			},
			CheckId: "1.1.9",
			Action:  createDummyAction(),
		},
		{
			Name:     "A check with no entity",
			Expected: consts.ErrorNoEntity,
			CheckMetadata: checkmodels.CheckMetadata{
				Type:        checkmodels.SCM,
				Title:       "SOME NAME",
				Description: "SOME DESCRIPTION",
				Remediation: "SOME REMEDIATION",
				Url:         "SOME URL",
			},
			CheckId: "1.1.9",
			Action:  createDummyAction(),
		},
		{
			Name:     "A check with no action",
			Expected: consts.ErrorNoCheckAction,
			CheckMetadata: checkmodels.CheckMetadata{
				Type:        checkmodels.SCM,
				Entity:      checkmodels.Organization,
				Title:       "SOME NAME",
				Description: "SOME DESCRIPTION",
				Remediation: "SOME REMEDIATION",
				Url:         "SOME URL",
			},
			CheckId: "1.1.9",
			Action:  nil,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			actualError := ValidateCheck(test.CheckId, test.CheckMetadata, test.Action, test.CheckMetadata.Url)

			if test.Expected == nil {
				assert.NoError(t, actualError)
			} else {
				assert.EqualError(t, actualError, test.Expected.Error())
			}
		})
	}
}
