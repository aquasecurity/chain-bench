package models

import (
	"github.com/aquasecurity/chain-bench/internal/utils"
)

type PackageRegistry struct {
	TwoFactorRequirementEnabled *bool
	Packages                    []*Package
}

type Package struct {
	ID           *int64
	Name         *string
	PackageType  *string
	HTMLURL      *string
	CreatedAt    *utils.Timestamp
	UpdatedAt    *utils.Timestamp
	Owner        *User
	Version      *string
	URL          *string
	VersionCount *int64
	Visibility   *string
	Repository   *Repository
}
