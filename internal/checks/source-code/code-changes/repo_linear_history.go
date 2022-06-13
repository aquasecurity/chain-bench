package codechanges

import (
	"encoding/json"

	"github.com/argonsecurity/chain-bench/internal/checks/common"
	"github.com/argonsecurity/chain-bench/internal/checks/consts"
	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
	"github.com/argonsecurity/chain-bench/internal/utils"
)

var (
	repoLinearHistoryId = "1.1.13"
)

func init() {
	if err := json.Unmarshal(metadataString, &checksMetadata); err != nil {
		panic(err)
	}

	if err := common.AppendCheck(&checks,
		checkmodels.Check{
			Action:           repoLinearHistoryCheck,
			CheckMetadataMap: checksMetadata,
		},
	); err != nil {
		panic(err)
	}
}

func repoLinearHistoryCheck(data *checkmodels.CheckData) ([]*checkmodels.CheckRunResult, error) {
	var (
		status  checkmodels.ResultStatus
		details string
	)
	metadataMap := checksMetadata
	repo := data.AssetsMetadata.Repository
	if repo == nil || repo.AllowMergeCommit == nil {
		return []*checkmodels.CheckRunResult{checkmodels.ToCheckRunResult(repoLinearHistoryId, metadataMap.Checks[repoLinearHistoryId], metadataMap.Url, &checkmodels.CheckResult{Status: checkmodels.Unknown})}, nil
	}

	allowMergeCommit := utils.GetValue(repo.AllowMergeCommit)
	allowRebaseMerge := utils.GetValue(repo.AllowRebaseMerge)
	allowSquashMerge := utils.GetValue(repo.AllowSquashMerge)

	if !allowMergeCommit && (allowRebaseMerge || allowSquashMerge) {
		status = checkmodels.Passed
	} else {
		status = checkmodels.Failed
	}

	if status != checkmodels.Passed {
		details = generateDetails(allowMergeCommit, allowRebaseMerge, allowSquashMerge)
	}
	results := []*checkmodels.CheckRunResult{checkmodels.ToCheckRunResult(repoLinearHistoryId, metadataMap.Checks[repoLinearHistoryId], metadataMap.Url, &checkmodels.CheckResult{Status: status, Details: details})}

	return results, nil
}

func generateDetails(allowMergeCommit, allowRebaseMerge, allowSquashMerge bool) string {
	if allowMergeCommit {
		return consts.Details_linearHistory_mergeCommitEnabled
	}

	return consts.Details_linearHistory_requireRebaseOrSquashCommitEnabled
}
