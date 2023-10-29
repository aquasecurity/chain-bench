package clients

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type RepoInfo struct {
	BaseUrl   string
	Namespace string
	Project   string
}

func TestGetRepoInfo(t *testing.T) {

	tests := []struct {
		Name        string
		RepoUrl     string
		ExpectedErr error
		Expected    RepoInfo
	}{{
		Name:        "missing url schema",
		RepoUrl:     "gitlab.com/rootgroup/subgroup/secondsubgroup/test",
		ExpectedErr: fmt.Errorf("error in parsing the host"),
		Expected:    RepoInfo{BaseUrl: "", Namespace: "", Project: ""},
	}, {
		Name:        "invalid url",
		RepoUrl:     "https://gitlab?com/rootgroup/subgroup/secondsubgroup/test",
		ExpectedErr: fmt.Errorf("missing org/repo in the repository url: %s", "https://gitlab?com/rootgroup/subgroup/secondsubgroup/test"),
		Expected:    RepoInfo{BaseUrl: "", Namespace: "", Project: ""},
	}, {
		Name:        "github repo",
		RepoUrl:     "https://github.com/aquasecurity/chain-bench",
		ExpectedErr: nil,
		Expected:    RepoInfo{BaseUrl: "github.com", Namespace: "aquasecurity", Project: "chain-bench"},
	}, {
		Name:        "gitlab project under root group",
		RepoUrl:     "https://gitlab.com/rootgroup/test",
		ExpectedErr: nil,
		Expected:    RepoInfo{BaseUrl: "gitlab.com", Namespace: "rootgroup", Project: "test"},
	}, {
		Name:        "gitlab project under sub group",
		RepoUrl:     "https://gitlab.com/rootgroup/subgroup/secondsubgroup/test",
		ExpectedErr: nil,
		Expected:    RepoInfo{BaseUrl: "gitlab.com", Namespace: "rootgroup/subgroup/secondsubgroup", Project: "test"},
	}, {
		Name:        "gitlab project under sub group with same name as repo",
		RepoUrl:     "https://gitlab.com/rootgroup/subgroup/secondsubgroup/secondsubgroup",
		ExpectedErr: nil,
		Expected:    RepoInfo{BaseUrl: "gitlab.com", Namespace: "rootgroup/subgroup/secondsubgroup", Project: "secondsubgroup"},
	}, {
		Name:        "github project under sub org with same name as repo",
		RepoUrl:     "https://github.com/codekuu/suborg/secondsuborg/secondsuborg",
		ExpectedErr: nil,
		Expected:    RepoInfo{BaseUrl: "github.com", Namespace: "codekuu/suborg/secondsuborg", Project: "secondsuborg"},
	}}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			baseUrl, namespace, project, err := getRepoInfo(test.RepoUrl)

			if test.ExpectedErr == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.ExpectedErr.Error())
			}
			assert.Equal(t, test.Expected.BaseUrl, baseUrl)
			assert.Equal(t, test.Expected.Namespace, namespace)
			assert.Equal(t, test.Expected.Project, project)
		})
	}

}
