package consts

import (
	"errors"
)

var (
	// checks execution errors
	ErrorNoRepository       = errors.New("Repository cannot be nil")
	ErrorNoOrganization     = errors.New("Organization cannot be nil")
	ErrorNoBranchProtection = errors.New("Branch Protection cannot be nil")
)
