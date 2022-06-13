package checks

import (
	"testing"

	"github.com/argonsecurity/chain-bench/internal/models"
	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
	"github.com/argonsecurity/chain-bench/internal/utils"
	"github.com/stretchr/testify/assert"
)

var (
	codeRules = []string{
		"1.1.3",
		"1.1.4",
		"1.1.5",
		"1.1.6",
		"1.1.8",
		"1.1.9",
		"1.1.10",
		"1.1.11",
		"1.1.12",
		"1.1.13",
		"1.1.14",
		"1.1.15",
		"1.1.16",
		"1.1.17",
		"1.2.1",
		"1.2.2",
		"1.2.3",
		"1.2.4",
		"1.3.1",
		"1.3.3",
		"1.3.5",
		"1.3.7",
		"1.3.8",
		"1.3.9",
	}

	buildRules = []string{
		"2.3.1",
		"2.3.5",
		"2.3.7",
		"2.3.8",
		"2.4.2",
		"2.4.6",
	}

	dependenciesRules = []string{
		"3.1.7",
		"3.2.2",
		"3.2.3",
	}

	artifactRules = []string{
		"4.2.3",
		"4.2.5",
		"4.3.4",
	}
)

func TestGetChecks(t *testing.T) {
	tests := []struct {
		Name        string
		ExpectedIds []string
		AssetsData  checkmodels.AssetsData
	}{
		{
			Name: "All checks loaded",
			ExpectedIds: append(append(append(
				codeRules,
				buildRules...),
				dependenciesRules...),
				artifactRules...,
			),
			AssetsData: checkmodels.AssetsData{Organization: &models.Organization{}, Repository: &models.Repository{}},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			checks := GetChecks(&test.AssetsData)
			actualIds := getIds(checks)
			assert.ElementsMatch(t, test.ExpectedIds, actualIds)
		})
	}
}

func getIds(checks []*checkmodels.Check) []string {
	ids := []string{}
	for _, cm := range checks {
		for m := range cm.CheckMetadataMap.Checks {
			if !utils.Contains(ids, m) {
				ids = append(ids, m)
			}
		}
	}
	return ids
}
