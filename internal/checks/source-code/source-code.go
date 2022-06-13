package sourcecode

import (
	codechanges "github.com/aquasecurity/chain-bench/internal/checks/source-code/code-changes"
	contributionaccess "github.com/aquasecurity/chain-bench/internal/checks/source-code/contribution-access"
	repositorymanagement "github.com/aquasecurity/chain-bench/internal/checks/source-code/repository-management"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

func GetChecks() []*checkmodels.Check {
	checks := []*checkmodels.Check{}
	checks = append(checks, codechanges.GetChecks()...)
	checks = append(checks, contributionaccess.GetChecks()...)
	checks = append(checks, repositorymanagement.GetChecks()...)
	return checks
}
