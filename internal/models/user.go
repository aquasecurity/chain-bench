package models

import "github.com/argonsecurity/chain-bench/internal/utils"

type User struct {
	Login             *string          `json:"login,omitempty"`
	ID                *int64           `json:"id,omitempty"`
	NodeID            *string          `json:"node_id,omitempty"`
	AvatarURL         *string          `json:"avatar_url,omitempty"`
	HTMLURL           *string          `json:"html_url,omitempty"`
	GravatarID        *string          `json:"gravatar_id,omitempty"`
	Name              *string          `json:"name,omitempty"`
	Company           *string          `json:"company,omitempty"`
	Blog              *string          `json:"blog,omitempty"`
	Location          *string          `json:"location,omitempty"`
	Email             *string          `json:"email,omitempty"`
	Hireable          *bool            `json:"hireable,omitempty"`
	Bio               *string          `json:"bio,omitempty"`
	PublicRepos       *int             `json:"public_repos,omitempty"`
	PublicGists       *int             `json:"public_gists,omitempty"`
	Followers         *int             `json:"followers,omitempty"`
	Following         *int             `json:"following,omitempty"`
	CreatedAt         *utils.Timestamp `json:"created_at,omitempty"`
	UpdatedAt         *utils.Timestamp `json:"updated_at,omitempty"`
	SuspendedAt       *utils.Timestamp `json:"suspended_at,omitempty"`
	Type              *string          `json:"type,omitempty"`
	SiteAdmin         *bool            `json:"site_admin,omitempty"`
	TotalPrivateRepos *int             `json:"total_private_repos,omitempty"`
	OwnedPrivateRepos *int             `json:"owned_private_repos,omitempty"`
	PrivateGists      *int             `json:"private_gists,omitempty"`
	DiskUsage         *int             `json:"disk_usage,omitempty"`
	Collaborators     *int             `json:"collaborators,omitempty"`
	Plan              *Plan            `json:"plan,omitempty"`
	Role              string

	// API URLs
	URL               *string `json:"url,omitempty"`
	EventsURL         *string `json:"events_url,omitempty"`
	FollowingURL      *string `json:"following_url,omitempty"`
	FollowersURL      *string `json:"followers_url,omitempty"`
	GistsURL          *string `json:"gists_url,omitempty"`
	OrganizationsURL  *string `json:"organizations_url,omitempty"`
	ReceivedEventsURL *string `json:"received_events_url,omitempty"`
	ReposURL          *string `json:"repos_url,omitempty"`
	StarredURL        *string `json:"starred_url,omitempty"`
	SubscriptionsURL  *string `json:"subscriptions_url,omitempty"`

	// Permissions identifies the permissions that a user has on a given
	// repository. This is only populated when calling Repositories.ListCollaborators.
	Permissions *map[string]bool `json:"permissions,omitempty"`
}
