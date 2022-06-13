package builders

import (
	"fmt"

	"github.com/argonsecurity/chain-bench/internal/models"
	"github.com/argonsecurity/chain-bench/internal/utils"
)

type OrganizationBuilder struct {
	org *models.Organization
}

func NewOrganizationBuilder() *OrganizationBuilder {
	return &OrganizationBuilder{org: &models.Organization{}}
}

func (b *OrganizationBuilder) WithMFAEnabled(enable bool) *OrganizationBuilder {
	b.org.TwoFactorRequirementEnabled = utils.GetPtr(enable)
	return b
}

func (b *OrganizationBuilder) WithVerifiedBadge(enable bool) *OrganizationBuilder {
	b.org.IsVerified = utils.GetPtr(enable)
	return b
}

func (b *OrganizationBuilder) WithReposDefaultPermissions(defaultPermissions string) *OrganizationBuilder {
	b.org.DefaultRepoPermission = utils.GetPtr(defaultPermissions)
	return b
}

func (b *OrganizationBuilder) WithMembersCanCreateRepos(membersCanCreateRepos bool) *OrganizationBuilder {
	b.org.MembersCanCreateRepos = utils.GetPtr(membersCanCreateRepos)
	return b
}

func (b *OrganizationBuilder) WithReposDeletionLimitation(repoDeletionLimitation bool) *OrganizationBuilder {
	b.org.IsRepositoryDeletionLimited = utils.GetPtr(repoDeletionLimitation)
	return b
}

func (b *OrganizationBuilder) WithIssuesDeletionLimitation(issueDeletionLimitation bool) *OrganizationBuilder {
	b.org.IsIssueDeletionLimited = utils.GetPtr(issueDeletionLimitation)
	return b
}

func (b *OrganizationBuilder) WithMembers(role string, num int) *OrganizationBuilder {
	var newMembers []*models.User
	for i := 0; i < num; i++ {
		login := fmt.Sprintf("user%d", i)
		newMembers = append(newMembers, &models.User{Role: role, Login: &login})
	}
	b.org.Members = append(b.org.Members, newMembers...)
	return b
}

func (b *OrganizationBuilder) WithPackageWebHooks(url string, is_ssl string, secret *string) *OrganizationBuilder {
	b.org.Hooks = []*models.Hook{{
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

func (b *OrganizationBuilder) Build() *models.Organization {
	return b.org
}
