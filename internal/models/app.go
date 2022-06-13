package models

import "github.com/aquasecurity/chain-bench/internal/utils"

// App represents a GitHub App.
type App struct {
	ID          *int64
	Slug        *string
	NodeID      *string
	Owner       *User
	Name        *string
	Description *string
	ExternalURL *string
	HTMLURL     *string
	CreatedAt   *utils.Timestamp
	UpdatedAt   *utils.Timestamp
	Permissions *InstallationPermissions
	Events      []string
}

// InstallationPermissions lists the repository and organization permissions for an installation.
type InstallationPermissions struct {
	Actions                       *string
	Administration                *string
	Blocking                      *string
	Checks                        *string
	Contents                      *string
	ContentReferences             *string
	Deployments                   *string
	Emails                        *string
	Environments                  *string
	Followers                     *string
	Issues                        *string
	Metadata                      *string
	Members                       *string
	OrganizationAdministration    *string
	OrganizationHooks             *string
	OrganizationPlan              *string
	OrganizationPreReceiveHooks   *string
	OrganizationProjects          *string
	OrganizationSecrets           *string
	OrganizationSelfHostedRunners *string
	OrganizationUserBlocking      *string
	Packages                      *string
	Pages                         *string
	PullRequests                  *string
	RepositoryHooks               *string
	RepositoryProjects            *string
	RepositoryPreReceiveHooks     *string
	Secrets                       *string
	SecretScanningAlerts          *string
	SecurityEvents                *string
	SingleFile                    *string
	Statuses                      *string
	TeamDiscussions               *string
	VulnerabilityAlerts           *string
	Workflows                     *string
}
