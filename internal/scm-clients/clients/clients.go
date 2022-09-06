package clients

import (
	"errors"
	"fmt"
	"strings"

	"net/url"

	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/scm-clients/adapter"
	"github.com/aquasecurity/chain-bench/internal/scm-clients/github"
	"github.com/aquasecurity/chain-bench/internal/scm-clients/gitlab"
	"github.com/aquasecurity/chain-bench/internal/utils"
	"github.com/enescakir/emoji"
)

const (
	GithubEndpoint = "github.com"
	GitlabEndpoint = "gitlab.com"
)

func FetchClientData(accessToken string, repoUrl string, branch string) (*checkmodels.AssetsData, error) {
	scmName, orgName, repoName, err := getRepoInfo(repoUrl)
	if err != nil {
		return nil, err
	}

	adapter, err := getClientAdapter(scmName, accessToken)
	if err != nil {
		return nil, err
	}
	authorizedUser, _ := adapter.GetAuthorizedUser()

	repo, _ := adapter.GetRepository(orgName, repoName, branch)
	logger.FetchingFinished("Repository Settings", emoji.OilDrum)

	branchName := utils.GetBranchName(utils.GetValue(repo.DefaultBranch), branch)

	logger.FetchingFinished("Branch Protection Settings", emoji.Seedling)
	protection, _ := adapter.GetBranchProtection(orgName, repo, branchName)

	// pipelines, _ := adapter.GetPipelines(orgName, repoName, branchName)
	// logger.FetchingFinished("Pipelines", emoji.Wrench)

	var org *models.Organization
	//var registry *models.PackageRegistry

	if *repo.Owner.Type == "Organization" {
		org, _ = adapter.GetOrganization(orgName)
		logger.FetchingFinished("Organization Settings", emoji.OfficeBuilding)

		//	registry, _ = adapter.GetRegistry(org)

		//	orgMembers, err := adapter.ListOrganizationMembers(orgName)
		// if err == nil {
		// 	org.Members = orgMembers
		// 	logger.FetchingFinished("Members", emoji.Emoji(emoji.WomanAndManHoldingHands.Tone()))
		// }
	}

	return &checkmodels.AssetsData{
		AuthorizedUser:    authorizedUser,
		Organization:      org,
		Repository:        repo,
		BranchProtections: protection,
		// Pipelines:         pipelines,
		// Registry:          registry,
	}, nil
}

func getRepoInfo(repoUrl string) (scm string, org string, repo string, err error) {
	u, err := url.Parse(repoUrl)
	if err != nil || u.Scheme == "" {
		logger.Errorf(err, "error in parsing repoUrl %s", repoUrl)
		if err == nil {
			err = errors.New("error in parsing the host")
		}
		return "", "", "", err
	}

	path := strings.Split(u.EscapedPath(), "/")
	if len(path) < 3 {
		return "", "", "", fmt.Errorf("missing org/repo in the repository url: %s", repoUrl)
	}
	return u.Host, path[1], path[2], nil
}

func getClientAdapter(scmName string, accessToken string) (adapter.ClientAdapter, error) {
	var err error
	var adapter adapter.ClientAdapter
	httpClient := utils.GetHttpClient(accessToken)

	switch scmName {
	case GithubEndpoint:
		err = github.Adapter.Init(httpClient, accessToken)
		adapter = &github.Adapter
	case GitlabEndpoint:
		err = gitlab.Adapter.Init(httpClient, accessToken)
		adapter = &gitlab.Adapter
	default:
		adapter = nil
	}

	if err != nil {
		logger.Error(err, "error with github init client")
		return &github.ClientAdapterImpl{}, nil
	}
	return adapter, err
}
