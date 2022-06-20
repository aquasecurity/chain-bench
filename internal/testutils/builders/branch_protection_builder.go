package builders

import (
	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

type BranchProtectionBuilder struct {
	br_protection *models.Protection
}

func NewBranchProtectionBuilder() *BranchProtectionBuilder {
	return &BranchProtectionBuilder{br_protection: &models.Protection{
		EnforceAdmins: &models.AdminEnforcement{
			Enabled: true,
		},
		RequiredStatusChecks: &models.RequiredStatusChecks{Strict: true},
		RequiredPullRequestReviews: &models.PullRequestReviewsEnforcement{
			RequiredApprovingReviewCount: 2,
			RequireCodeOwnerReviews:      true,
			DismissStaleReviews:          true,
			DismissalRestrictions:        &models.DismissalRestrictions{Users: []*models.User{}},
		},
		Restrictions:                   &models.BranchRestrictions{Users: []*models.User{{Name: utils.GetPtr("default")}}, Teams: []*models.Team{}, Apps: []*models.App{}},
		RequiredSignedCommit:           true,
		RequiredConversationResolution: true,
		AllowForcePushes:               true,
		AllowDeletions:                 true,
	}}
}

func (b *BranchProtectionBuilder) WithStatusCheckEnabled(enabled bool) *BranchProtectionBuilder {
	if !enabled {
		b.br_protection.RequiredStatusChecks = nil
	}
	return b
}

func (b *BranchProtectionBuilder) WithStrictMode(enabled bool) *BranchProtectionBuilder {
	if b.br_protection.RequiredStatusChecks != nil {
		b.br_protection.RequiredStatusChecks.Strict = enabled
	}
	return b
}

func (b *BranchProtectionBuilder) WithMinimumReviwersBeforeMerge(num int) *BranchProtectionBuilder {
	b.br_protection.RequiredPullRequestReviews.RequiredApprovingReviewCount = num
	return b
}

func (b *BranchProtectionBuilder) WithCodeOwnersReview(requireCodeOwnerReviews bool) *BranchProtectionBuilder {
	b.br_protection.RequiredPullRequestReviews.RequireCodeOwnerReviews = requireCodeOwnerReviews
	return b
}

func (b *BranchProtectionBuilder) WithDismissStaleReviews(dismissStaleReviews bool) *BranchProtectionBuilder {
	b.br_protection.RequiredPullRequestReviews.DismissStaleReviews = dismissStaleReviews
	return b
}

func (b *BranchProtectionBuilder) WithDismissalRestrictions(dismissalRestrictions bool) *BranchProtectionBuilder {
	if !dismissalRestrictions {
		b.br_protection.RequiredPullRequestReviews.DismissalRestrictions = nil
	}
	return b
}

func (b *BranchProtectionBuilder) WithRequiredSignedCommits(enable bool) *BranchProtectionBuilder {
	b.br_protection.RequiredSignedCommit = enable
	return b
}

func (b *BranchProtectionBuilder) WithResolveConversations(resolveConversion bool) *BranchProtectionBuilder {
	b.br_protection.RequiredConversationResolution = resolveConversion
	return b
}

func (b *BranchProtectionBuilder) WithEnforceAdmin(enforceAdmin bool) *BranchProtectionBuilder {
	b.br_protection.EnforceAdmins = &models.AdminEnforcement{Enabled: enforceAdmin}
	return b
}

func (b *BranchProtectionBuilder) WithPushRestrictions(pushRestriction bool) *BranchProtectionBuilder {
	if !pushRestriction {
		b.br_protection.Restrictions = nil
	}
	return b
}

func (b *BranchProtectionBuilder) WithDeleteBranch(deleteBranch bool) *BranchProtectionBuilder {
	b.br_protection.AllowDeletions = deleteBranch
	return b
}

func (b *BranchProtectionBuilder) WithForcePush(forcePush bool) *BranchProtectionBuilder {
	b.br_protection.AllowForcePushes = forcePush
	return b
}

func (b *BranchProtectionBuilder) Build() *models.Protection {
	return b.br_protection
}
