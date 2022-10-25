package models

import (
	"time"
)

type Protection struct {
	RequiredStatusChecks           *RequiredStatusChecks
	RequiredPullRequestReviews     *PullRequestReviewsEnforcement
	EnforceAdmins                  *AdminEnforcement
	Restrictions                   *BranchRestrictions
	RequireLinearHistory           bool
	AllowForcePushes               bool
	AllowDeletions                 bool
	RequiredConversationResolution bool
	RequiredSignedCommit           bool
	//PreventSecrets                 bool
}

// PullRequestReviewsEnforcement represents the pull request reviews enforcement of a protected branch.
type PullRequestReviewsEnforcement struct {
	// Specifies which users and teams can dismiss pull request reviews.
	DismissalRestrictions *DismissalRestrictions
	// Specifies if approved reviews are dismissed automatically, when a new commit is pushed.
	DismissStaleReviews bool
	// RequireCodeOwnerReviews specifies if an approved review is required in pull requests including files with a designated code owner.
	RequireCodeOwnerReviews bool
	// RequiredApprovingReviewCount specifies the number of approvals required before the pull request can be merged.
	// Valid values are 1-6.
	RequiredApprovingReviewCount int
}

type RequiredStatusChecks struct {
	Strict bool
}

// AdminEnforcement represents the configuration to enforce required status checks for repository administrators.
type AdminEnforcement struct {
	URL     *string
	Enabled bool
}

// BranchRestrictions represents the restriction that only certain users or
// teams may push to a branch.
type BranchRestrictions struct {
	// The list of user logins with push access.
	Users []*User
	// The list of team slugs with push access.
	Teams []*Team
	// The list of app slugs with push access.
	Apps []*App
}

// DismissalRestrictions specifies which users and teams can dismiss pull request reviews.
type DismissalRestrictions struct {
	// The list of users who can dimiss pull request reviews.
	Users []*User `json:"users"`
}

// Branch represents a repository branch
type Branch struct {
	Name      *string `json:"name,omitempty"`
	Commit    *RepositoryCommit
	Protected *bool `json:"protected,omitempty"`
}

type RepositoryCommit struct {
	NodeID       *string `json:"node_id,omitempty"`
	SHA          *string `json:"sha,omitempty"`
	Author       *CommitAuthor
	Committer    *CommitAuthor
	URL          *string                `json:"url,omitempty"`
	Verification *SignatureVerification `json:"verification,omitempty"`
}

type CommitAuthor struct {
	Date  *time.Time
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`

	// The following fields are only populated by Webhook events.
	Login *string `json:"username,omitempty"` // Renamed for go-github consistency.
}

// SignatureVerification represents GPG signature verification.
type SignatureVerification struct {
	Verified  *bool   `json:"verified,omitempty"`
	Reason    *string `json:"reason,omitempty"`
	Signature *string `json:"signature,omitempty"`
	Payload   *string `json:"payload,omitempty"`
}
