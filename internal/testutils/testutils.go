package testutils

import (
	"testing"

	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/stretchr/testify/assert"
	funk "github.com/thoas/go-funk"
)

type CheckTest struct {
	Name                    string
	Data                    *checkmodels.CheckData
	Expected                []*checkmodels.CheckRunResult
	ExpectedResultsForRules []*checkmodels.CheckRunResult
	ExpectedE               error
}

var (
	AuthorizedUserMockId = int64(1234)
	SbomTask             = "CycloneDX/gh-dotnet-generate-sbom"
	ArgonScannerAction   = "argonsecurity/scanner-action"
	TrivyScannerAction   = "aquasecurity/trivy-action"
)

func RunCheckTests(t *testing.T, testedAction checkmodels.CheckAction, tests []CheckTest, checksMetadata checkmodels.CheckMetadataMap) {
	for _, test := range tests {
		test := test
		test.ExpectedResultsForRules = generateChecksByMetadata(checksMetadata, test.Expected)
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			actual, actualE := testedAction(test.Data)

			if test.ExpectedE == nil {
				assert.NoError(t, actualE)
			} else {
				assert.EqualError(t, actualE, test.ExpectedE.Error())
			}

			if test.ExpectedResultsForRules == nil {
				assert.Nil(t, actual)
			} else {
				assert.ElementsMatch(t, test.ExpectedResultsForRules, actual)
			}
		})
	}
}

func generateChecksByMetadata(checksMetadata checkmodels.CheckMetadataMap, expectedResults []*checkmodels.CheckRunResult) []*checkmodels.CheckRunResult {
	checksArr := []*checkmodels.CheckRunResult{}
	for id, check := range checksMetadata.Checks {
		if !isCheckAlreadyExist(expectedResults, id) {
			checksArr = append(checksArr, checkmodels.ToCheckRunResult(id, check, checksMetadata.Url, &checkmodels.CheckResult{Status: checkmodels.Passed}))
		}
	}

	if expectedResults != nil {
		checksArr = append(checksArr, expectedResults...)
	}

	return checksArr
}

func isCheckAlreadyExist(expectedResults []*checkmodels.CheckRunResult, checkId string) bool {
	return funk.Contains(expectedResults, func(c *checkmodels.CheckRunResult) bool {
		return c.ID == checkId
	})
}
