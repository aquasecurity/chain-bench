package builders

import (
	"fmt"

	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

type OrganizationBuilder struct {
	org *models.Organization
}

func NewOrganizationBuilder() *OrganizationBuilder {
	return &OrganizationBuilder{org: &models.Organization{
		TwoFactorRequirementEnabled: utils.GetPtr(true),
		IsVerified:                  utils.GetPtr(true),
		DefaultRepoPermission:       utils.GetPtr("read"),
		MembersCanCreateRepos:       utils.GetPtr(false),
		IsRepositoryDeletionLimited: utils.GetPtr(true),
		IsIssueDeletionLimited:      utils.GetPtr(true),
		Hooks: []*models.Hook{{
			URL: utils.GetPtr("https://endpoint.com"),
			Config: &models.HookConfig{
				URL:          utils.GetPtr("https://endpoint.com"),
				Insecure_SSL: utils.GetPtr("0"),
				Secret:       utils.GetPtr("**"),
			},
			Events: []string{"package"},
		}},
		Members: []*models.User{{Role: "admin", Login: utils.GetPtr("user0")},
			{Role: "admin", Login: utils.GetPtr("user1")},
			{Role: "member", Login: utils.GetPtr("user2")},
			{Role: "member", Login: utils.GetPtr("user3")}}},
	}
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
	if defaultPermissions == "" {
		b.org.DefaultRepoPermission = nil
	} else {
		b.org.DefaultRepoPermission = utils.GetPtr(defaultPermissions)
	}
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
	b.org.Members = newMembers
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

func (b *OrganizationBuilder) WithNoPackageWebHooks() *OrganizationBuilder {
	b.org.Hooks = nil
	return b
}

func (b *OrganizationBuilder) Build() *models.Organization {
	return b.org
}
