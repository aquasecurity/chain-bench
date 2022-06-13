package github

import (
	"context"
	"testing"

	"github.com/aquasecurity/chain-bench/internal/utils"
	"github.com/google/go-github/v41/github"
	"github.com/stretchr/testify/assert"
)

type fields struct {
	githubClient GithubClient
}

type args struct {
	ctx    context.Context
	owner  string
	repo   string
	branch string
	file   string
}
type testsMetadata struct {
	name      string
	args      args
	expected  interface{}
	assertion assert.ErrorAssertionFunc
}

func TestGetRepository(t *testing.T) {
	expected := github.Repository{
		Name:  github.String("repo1"),
		Owner: &github.User{Login: github.String("gkek")}}

	client := MockGetRepo(&expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:   context.TODO(),
				owner: *expected.Owner.Login,
				repo:  *expected.Name,
			},
			expected:  &expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).GetRepository(test.args.owner, test.args.repo)

			test.assertion(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestGetBranchProtection(t *testing.T) {
	expected := github.Protection{
		RequiredStatusChecks: &github.RequiredStatusChecks{Strict: *github.Bool(true)},
		AllowDeletions:       &github.AllowDeletions{Enabled: true},
	}

	client := MockGetBranchProtections(&expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:    context.TODO(),
				owner:  "gkek",
				repo:   "repo1",
				branch: "main",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).GetBranchProtection(test.args.owner, test.args.repo, test.args.branch)

			test.assertion(t, err)
			assert.Equal(t, test.expected, *got)
		})
	}
}

func TestGetSignaturesOfProtectedBranch(t *testing.T) {
	expected := github.SignaturesProtectedBranch{
		Enabled: utils.GetPtr(true),
	}

	client := MockGetSignaturesOfProtectedBranch(&expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:    context.TODO(),
				owner:  "gkek",
				repo:   "repo1",
				branch: "main",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).GetSignaturesOfProtectedBranch(test.args.owner, test.args.repo, test.args.branch)

			test.assertion(t, err)
			assert.Equal(t, test.expected, *got)
		})
	}
}
func TestGetOrganization(t *testing.T) {
	expected := github.Organization{
		Login: github.String("org1"),
	}

	client := MockGetOrganization(&expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:   context.TODO(),
				owner: *expected.Login,
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).GetOrganization(test.args.owner)
			test.assertion(t, err)
			assert.Equal(t, test.expected, *got)
		})
	}
}

func TestGetOrganizationMembers(t *testing.T) {
	expected := []*github.User{
		{Login: github.String("user1")},
		{Login: github.String("user2")},
	}
	client := MockGetOrganizationMembers(expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:   context.TODO(),
				owner: "org1",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).ListOrganizationMembers(test.args.owner, &github.ListMembersOptions{})
			test.assertion(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestListCommits(t *testing.T) {
	expected := []*github.RepositoryCommit{
		{
			SHA: github.String("sha1"),
		},
	}
	client := MockListCommits(expected)
	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:   context.TODO(),
				owner: "org1",
				repo:  "repo1",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).ListCommits(test.args.owner, test.args.repo, &github.CommitsListOptions{})
			test.assertion(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestGetWorkflows(t *testing.T) {
	expected := &github.Workflows{
		Workflows: []*github.Workflow{
			{Name: utils.GetPtr("workflow1")},
			{Name: utils.GetPtr("workflow2")},
		},
		TotalCount: utils.GetPtr(2),
	}
	client := MockGetWorkflows(expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:   context.TODO(),
				owner: "org1",
				repo:  "repo1",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).GetWorkflows(test.args.owner, test.args.repo)
			test.assertion(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestGetContent(t *testing.T) {
	expected := &github.RepositoryContent{
		Content: utils.GetPtr("test"),
	}
	client := MockGetContent(expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:    context.TODO(),
				owner:  "org1",
				repo:   "repo1",
				branch: "main",
				file:   "file1",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, _, err := (*client).GetContent(test.args.owner, test.args.repo, test.args.file, test.args.branch)
			test.assertion(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestGetOrganizationHooks(t *testing.T) {
	expected := []*github.Hook{
		{Name: utils.GetPtr("hook1"), ID: utils.GetPtr(int64(3)), Config: map[string]interface{}{"secret": "test", "insecure_ssl": "1", "url": "http://localhost:8080/hook"}}}

	client := MockGetOrganizationWebhooks(expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:   context.TODO(),
				owner: "org1",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).ListOrganizationHooks(test.args.owner)
			test.assertion(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestGetRepositoryHooks(t *testing.T) {
	expected := []*github.Hook{
		{Name: utils.GetPtr("hook1"), ID: utils.GetPtr(int64(3)), Config: map[string]interface{}{"secret": "test", "insecure_ssl": "1", "url": "http://localhost:8080/hook"}}}

	client := MockGetRepositoryWebhooks(expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:   context.TODO(),
				owner: "org1",
				repo:  "repo1",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).ListRepositoryHooks(test.args.owner, test.args.repo)
			test.assertion(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestListOrganizationPackages(t *testing.T) {
	expected := []*github.Package{{Name: utils.GetPtr("package1"),
		Visibility: utils.GetPtr("public"), PackageType: utils.GetPtr("npm"),
		Repository: &github.Repository{
			Name: utils.GetPtr("repo1"), Private: utils.GetPtr(true)}}}

	client := MockListOrganizationPackages(expected)

	tests := []testsMetadata{
		{
			name: "Success",
			args: args{
				ctx:   context.TODO(),
				owner: "org1",
			},
			expected:  expected,
			assertion: assert.NoError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _, err := (*client).ListOrganizationPackages(test.args.owner, "npm")
			test.assertion(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}
