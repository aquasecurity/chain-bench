package testutils

import (
	"testing"

	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
	"github.com/stretchr/testify/assert"
)

type CheckTest struct {
	Name      string
	Data      *checkmodels.CheckData
	Expected  []*checkmodels.CheckRunResult
	ExpectedE error
}

var AuthorizedUserMockId = int64(1234)

func RunCheckTests(t *testing.T, testedAction checkmodels.CheckAction, tests []CheckTest) {
	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			actual, actualE := testedAction(test.Data)

			if test.ExpectedE == nil {
				assert.NoError(t, actualE)
			} else {
				assert.EqualError(t, actualE, test.ExpectedE.Error())
			}

			if test.Expected == nil {
				assert.Nil(t, actual)
			} else {
				assert.ElementsMatch(t, test.Expected, actual)
			}
		})
	}
}
