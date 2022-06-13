package models

import "github.com/argonsecurity/chain-bench/internal/utils"

type Repository struct {
	ID               *int64           `json:"id,omitempty"`
	NodeID           *string          `json:"node_id,omitempty"`
	Owner            *User            `json:"owner,omitempty"`
	Name             *string          `json:"name,omitempty"`
	Description      *string          `json:"description,omitempty"`
	DefaultBranch    *string          `json:"default_branch,omitempty"`
	MasterBranch     *string          `json:"master_branch,omitempty"`
	CreatedAt        *utils.Timestamp `json:"created_at,omitempty"`
	PushedAt         *utils.Timestamp `json:"pushed_at,omitempty"`
	UpdatedAt        *utils.Timestamp `json:"updated_at,omitempty"`
	Language         *string          `json:"language,omitempty"`
	Fork             *bool            `json:"fork,omitempty"`
	ForksCount       *int             `json:"forks_count,omitempty"`
	NetworkCount     *int             `json:"network_count,omitempty"`
	OpenIssuesCount  *int             `json:"open_issues_count,omitempty"`
	StargazersCount  *int             `json:"stargazers_count,omitempty"`
	SubscribersCount *int             `json:"subscribers_count,omitempty"`
	WatchersCount    *int             `json:"watchers_count,omitempty"`
	Size             *int             `json:"size,omitempty"`
	AutoInit         *bool            `json:"auto_init,omitempty"`
	Parent           *Repository      `json:"parent,omitempty"`
	Source           *Repository      `json:"source,omitempty"`
	Organization     *Organization    `json:"organization,omitempty"`
	AllowRebaseMerge *bool
	AllowSquashMerge *bool
	AllowMergeCommit *bool
	Topics           []string `json:"topics,omitempty"`

	// Only provided when using RepositoriesService.Get while in preview
	License *License `json:"license,omitempty"`

	// Additional mutable fields when creating and editing a repository
	IsPrivate         *bool
	HasIssues         *bool   `json:"has_issues,omitempty"`
	LicenseTemplate   *string `json:"license_template,omitempty"`
	GitignoreTemplate *string `json:"gitignore_template,omitempty"`
	Archived          *bool   `json:"archived,omitempty"`

	// Creating an organization repository. Required for non-owners.
	TeamID *int64 `json:"team_id,omitempty"`

	// API URLs
	URL *string `json:"url,omitempty"`

	Branches             []*Branch
	Collaborators        []*User
	IsContainsSecurityMd bool
	Commits              []*RepositoryCommit
	Hooks                []*Hook
}

type License struct {
	Key            *string   `json:"key,omitempty"`
	Name           *string   `json:"name,omitempty"`
	URL            *string   `json:"url,omitempty"`
	SPDXID         *string   `json:"spdx_id,omitempty"`
	HTMLURL        *string   `json:"html_url,omitempty"`
	Featured       *bool     `json:"featured,omitempty"`
	Description    *string   `json:"description,omitempty"`
	Implementation *string   `json:"implementation,omitempty"`
	Conditions     *[]string `json:"conditions,omitempty"`
	Permissions    *[]string `json:"permissions,omitempty"`
	Limitations    *[]string `json:"limitations,omitempty"`
	Body           *string   `json:"body,omitempty"`
}
