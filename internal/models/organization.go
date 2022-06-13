package models

import "time"

type Organization struct {
	Login                         *string
	ID                            *int64
	NodeID                        *string
	Name                          *string
	Company                       *string
	Location                      *string
	Email                         *string
	Description                   *string
	PublicRepos                   *int
	CreatedAt                     *time.Time
	UpdatedAt                     *time.Time
	TotalPrivateRepos             *int
	OwnedPrivateRepos             *int
	Collaborators                 *int
	Type                          *string
	Plan                          *Plan
	DefaultRepoPermission         *string
	DefaultRepoSettings           *string
	MembersCanCreateRepos         *bool
	MembersCanCreatePublicRepos   *bool
	MembersCanCreatePrivateRepos  *bool
	MembersCanCreateInternalRepos *bool
	TwoFactorRequirementEnabled   *bool
	IsVerified                    *bool
	Members                       []*User
	IsRepositoryDeletionLimited   *bool
	IsIssueDeletionLimited        *bool
	Hooks                         []*Hook
}

type Plan struct {
	Name          *string
	Space         *int
	Collaborators *int
	PrivateRepos  *int
}
