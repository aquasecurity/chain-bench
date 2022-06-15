package builders

import (
	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

type BranchProtectionBuilder struct {
	br_protection *models.Protection
}

func NewBranchProtectionBuilder() *BranchProtectionBuilder {
	return &BranchProtectionBuilder{br_protection: &models.Protection{EnforceAdmins: &models.AdminEnforcement{}, RequiredPullRequestReviews: &models.PullRequestReviewsEnforcement{}}}
}

func (b *BranchProtectionBuilder) WithStatusCheckEnabled() *BranchProtectionBuilder {
	b.br_protection.RequiredStatusChecks = &models.RequiredStatusChecks{}
	return b
}

func (b *BranchProtectionBuilder) WithRequireBranchToBeUpToDate(required bool) *BranchProtectionBuilder {
	b.br_protection.RequiredStatusChecks.Strict = required
	return b
}

func (b *BranchProtectionBuilder) WithMinimumReviwersBeforeMerge(num int) *BranchProtectionBuilder {
	if b.br_protection.RequiredPullRequestReviews != nil {
		b.br_protection.RequiredPullRequestReviews.RequiredApprovingReviewCount = num
	} else {
		b.br_protection.RequiredPullRequestReviews = &models.PullRequestReviewsEnforcement{RequiredApprovingReviewCount: num}
	}
	return b
}

func (b *BranchProtectionBuilder) WithCodeOwnersReview(requireCodeOwnerReviews bool) *BranchProtectionBuilder {
	if b.br_protection.RequiredPullRequestReviews != nil {
		b.br_protection.RequiredPullRequestReviews.RequireCodeOwnerReviews = requireCodeOwnerReviews
	} else {
		b.br_protection.RequiredPullRequestReviews = &models.PullRequestReviewsEnforcement{RequireCodeOwnerReviews: requireCodeOwnerReviews}
	}
	return b
}

func (b *BranchProtectionBuilder) WithDismissStaleReviews(dismissStaleReviews bool) *BranchProtectionBuilder {
	if b.br_protection.RequiredPullRequestReviews != nil {
		b.br_protection.RequiredPullRequestReviews.DismissStaleReviews = dismissStaleReviews
	} else {
		b.br_protection.RequiredPullRequestReviews = &models.PullRequestReviewsEnforcement{DismissStaleReviews: dismissStaleReviews}
	}
	return b
}

func (b *BranchProtectionBuilder) WithDismissalRestrictions(dismissalRestrictions bool) *BranchProtectionBuilder {
	if b.br_protection.RequiredPullRequestReviews == nil {
		b.br_protection.RequiredPullRequestReviews = &models.PullRequestReviewsEnforcement{}
	}
	if dismissalRestrictions {
		b.br_protection.RequiredPullRequestReviews.DismissalRestrictions = &models.DismissalRestrictions{Users: []*models.User{}}
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
	if pushRestriction {
		b.br_protection.Restrictions = &models.BranchRestrictions{Users: []*models.User{{Name: utils.GetPtr("default")}}, Teams: []*models.Team{}, Apps: []*models.App{}}
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
