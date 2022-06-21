package builders

import (
	"time"

	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

type BranchBuilder struct {
	branch *models.Branch
}

func NewBranchBuilder() *BranchBuilder {
	return &BranchBuilder{branch: &models.Branch{
		Commit: &models.RepositoryCommit{
			SHA:          utils.GetPtr("GD2"),
			Author:       &models.CommitAuthor{},
			Committer:    &models.CommitAuthor{Date: utils.GetPtr(time.Now())},
			Verification: &models.SignatureVerification{},
		},
	},
	}
}

func (b *BranchBuilder) WithOldCommit() *BranchBuilder {
	b.branch.Commit.Committer.Date = utils.GetPtr(time.Now().AddDate(0, -3, 0))
	return b
}

func (b *BranchBuilder) Build() *models.Branch {
	return b.branch
}
