package builders

import (
	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/testutils"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

type RepositoryBuilder struct {
	repository *models.Repository
}

func NewRepositoryBuilder() *RepositoryBuilder {
	return &RepositoryBuilder{repository: &models.Repository{
		AllowRebaseMerge: utils.GetPtr(true),
		AllowSquashMerge: utils.GetPtr(true),
		AllowMergeCommit: utils.GetPtr(false),
		Collaborators: []*models.User{{
			ID: utils.GetPtr(testutils.AuthorizedUserMockId),
			Permissions: utils.GetPtr(map[string]bool{
				"admin": true,
			}),
		}, {
			ID: utils.GetPtr(int64(1)),
			Permissions: utils.GetPtr(map[string]bool{
				"admin": true,
			}),
		}},
		IsPrivate:            utils.GetPtr(true),
		IsContainsSecurityMd: true,
		Hooks: []*models.Hook{{
			URL: utils.GetPtr("https://endpoint.com"),
			Config: &models.HookConfig{
				URL:          utils.GetPtr("https://endpoint.com"),
				Insecure_SSL: utils.GetPtr("0"),
				Secret:       utils.GetPtr("**"),
			},
			Events: []string{"package"},
		}},
		Commits: []*models.RepositoryCommit{{
			Author: &models.CommitAuthor{
				Login: utils.GetPtr("user0"),
			},
		}, {
			Author: &models.CommitAuthor{
				Login: utils.GetPtr("user1"),
			},
		}, {
			Author: &models.CommitAuthor{
				Login: utils.GetPtr("user2"),
			},
		}, {
			Author: &models.CommitAuthor{
				Login: utils.GetPtr("user3"),
			},
		}},
	}}
}

func (b *RepositoryBuilder) WithAllowRebaseMerge(enable bool) *RepositoryBuilder {
	b.repository.AllowRebaseMerge = utils.GetPtr(enable)
	return b
}

func (b *RepositoryBuilder) WithAdminCollborator(admin bool, count int) *RepositoryBuilder {
	b.repository.Collaborators = []*models.User{}
	authorizedUserId := testutils.AuthorizedUserMockId

	for i := 0; i < count; i++ {
		b.repository.Collaborators = append(b.repository.Collaborators, &models.User{ID: utils.GetPtr(authorizedUserId + int64(i)), Permissions: utils.GetPtr(map[string]bool{
			"admin": admin,
		})})
	}

	return b
}

func (b *RepositoryBuilder) WithAllowSquashMerge(enable bool) *RepositoryBuilder {
	b.repository.AllowSquashMerge = utils.GetPtr(enable)
	return b
}
func (b *RepositoryBuilder) WithAllowMergeCommit(enable bool) *RepositoryBuilder {
	b.repository.AllowMergeCommit = utils.GetPtr(enable)
	return b
}
func (b *RepositoryBuilder) WithPrivate(isPrivate bool) *RepositoryBuilder {
	b.repository.IsPrivate = utils.GetPtr(isPrivate)
	return b
}
func (b *RepositoryBuilder) WithSecurityMdFile(containsSecurityMd bool) *RepositoryBuilder {
	b.repository.IsContainsSecurityMd = containsSecurityMd
	return b
}
func (b *RepositoryBuilder) WithCommit(login string) *RepositoryBuilder {
	b.repository.Commits = append(b.repository.Commits, &models.RepositoryCommit{
		Author: &models.CommitAuthor{
			Login: &login,
		},
	})
	return b
}

func (b *RepositoryBuilder) WithPackageWebHooks(url string, is_ssl string, secret *string) *RepositoryBuilder {
	b.repository.Hooks = []*models.Hook{{
		URL: &url,
		Config: &models.HookConfig{
			URL:          utils.GetPtr(url),
			Insecure_SSL: utils.GetPtr(is_ssl),
			Secret:       secret,
		},
		Events: []string{"package"},
	}}
	return b
}

func (b *RepositoryBuilder) Build() *models.Repository {
	return b.repository
}
