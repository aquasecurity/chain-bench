package opa

import (
	"testing"

	"github.com/aquasecurity/chain-bench/internal/consts"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/stretchr/testify/assert"
)

type RegoResultTest []struct {
	Name     string
	Findings []*RegoResult
	Metadata checkmodels.CheckMetadataMap
	Expected []*checkmodels.CheckRunResult
}

type RegoRuleResultTest []struct {
	Name      string
	Findings  *RegoResult
	Expected  *RegoResult
	ExpectedE error
}

func TestParseRegoResult(t *testing.T) {
	metadata := checkmodels.CheckMetadata{
		Title:       "Ensure any change to code receives approval of two strongly authenticated users",
		Type:        "SCM",
		Entity:      "Organization",
		Description: "SOME DESCRIPTION",
		ScannerType: checkmodels.Rego,
		Url:         "https://avd.aquasec.com/compliance/softwaresupplychain/cis-1.0/cis-1.0-sourcecode/1.1/#1113-ensure-any-change-to-code-receives-approval-of-two-strongly-authenticated-users",
	}
	metadataMap := checkmodels.CheckMetadataMap{
		Checks: map[string]checkmodels.CheckMetadata{"1.1.13": metadata},
		Url:    "https://avd.aquasec.com/compliance/softwaresupplychain/cis-1.0/cis-1.0-sourcecode/1.1",
	}
	res := []*RegoResult{{IDs: []string{"1.1.13"}, Status: checkmodels.Passed, Details: "Details"}}

	tests := RegoResultTest{
		{
			Name:     "Some Name",
			Findings: res,
			Metadata: metadataMap,
			Expected: []*checkmodels.CheckRunResult{
				{
					ID:       "1.1.13",
					Metadata: metadata,
					Result: &checkmodels.CheckResult{
						Status:  checkmodels.Passed,
						Details: "Details"},
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			actual := parseRegoResult(test.Findings, &test.Metadata)
			assert.Equal(t, test.Expected, actual)
		})
	}
}

func TestParseRegoRule(t *testing.T) {
	tests := RegoRuleResultTest{
		{
			Name:      "rego result with all fields",
			Findings:  &RegoResult{IDs: []string{"1.1.9"}, Status: checkmodels.Passed, Details: "Details"},
			Expected:  &RegoResult{IDs: []string{"1.1.9"}, Status: checkmodels.Passed, Details: "Details"},
			ExpectedE: nil,
		},
		{
			Name:      "rego result missing status",
			Findings:  &RegoResult{IDs: []string{"1.1.9"}, Details: "Details"},
			ExpectedE: errorNoResultStatus,
		},
		{
			Name:      "rego result missing ids",
			Findings:  &RegoResult{Status: checkmodels.Passed, Details: "Details"},
			ExpectedE: consts.ErrorNoCheckID,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			actual, actualE := parseRegoRule(test.Findings)

			if test.ExpectedE == nil {
				assert.NoError(t, actualE)
			} else {
				assert.EqualError(t, actualE, test.ExpectedE.Error())
			}

			if test.Expected == nil {
				assert.Nil(t, actual)
			} else {
				assert.Equal(t, test.Expected, actual)
			}
		})
	}
}
