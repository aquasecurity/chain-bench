package builders

import (
	"github.com/argonsecurity/chain-bench/internal/models"
	"github.com/argonsecurity/chain-bench/internal/utils"
)

type BranchBuilder struct {
	branch *models.Branch
}

func NewBranchBuilder() *BranchBuilder {
	return &BranchBuilder{branch: &models.Branch{}}
}

func (b *BranchBuilder) WithCommit(sha string, commitDate utils.Timestamp) *BranchBuilder {
	b.branch.Commit = &models.RepositoryCommit{
		SHA:          utils.GetPtr(sha),
		Author:       &models.CommitAuthor{},
		Committer:    &models.CommitAuthor{Date: &commitDate.Time},
		Verification: &models.SignatureVerification{},
	}
	return b
}

func (b *BranchBuilder) Build() *models.Branch {
	return b.branch
}
