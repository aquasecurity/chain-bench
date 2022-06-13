package clients

import (
	"fmt"
	"strings"

	"net/url"

	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/scm-clients/adapter"
	"github.com/aquasecurity/chain-bench/internal/scm-clients/github"
	"github.com/aquasecurity/chain-bench/internal/utils"
	"github.com/enescakir/emoji"
)

const (
	GithubEndpoint = "github.com"
)

func FetchClientData(accessToken string, repoUrl string) (*checkmodels.AssetsData, error) {
	scmName, orgName, repoName, err := getRepoInfo(repoUrl)
	if err != nil {
		return nil, err
	}

	adapter, err := getClientAdapter(scmName, accessToken)
	if err != nil {
		return nil, err
	}
	authorizedUser, _ := adapter.GetAuthorizedUser()
	org, _ := adapter.GetOrganization(orgName)
	logger.FetchingFinished("Organization Settings", emoji.OfficeBuilding)
	registry, _ := adapter.GetRegistry(org)

	repo, _ := adapter.GetRepository(orgName, repoName)
	logger.FetchingFinished("Repository Settings", emoji.OilDrum)

	defaultBranch := utils.GetValue(utils.GetValue(repo).DefaultBranch)
	protection, _ := adapter.GetBranchProtection(orgName, repoName, defaultBranch)
	logger.FetchingFinished("Branch Protection Settings", emoji.Seedling)

	orgMembers, err := adapter.ListOrganizationMembers(orgName)
	if err != nil {
		return nil, err
	}
	org.Members = orgMembers
	logger.FetchingFinished("Members", emoji.Emoji(emoji.WomanAndManHoldingHands.Tone()))

	pipelines, _ := adapter.GetPipelines(orgName, repoName, defaultBranch)
	logger.FetchingFinished("Pipelines", emoji.Wrench)

	return &checkmodels.AssetsData{
		AuthorizedUser:    authorizedUser,
		Organization:      org,
		Repository:        repo,
		BranchProtections: protection,
		Pipelines:         pipelines,
		Registry:          registry,
	}, nil
}

func getRepoInfo(repoUrl string) (scm string, org string, repo string, err error) {
	u, err := url.Parse(repoUrl)
	if err != nil {
		logger.Errorf(err, "error in parsing repoUrl %s", repoUrl)
		return "", "", "", err
	}

	path := strings.Split(u.EscapedPath(), "/")
	if len(path) < 3 {
		return "", "", "", fmt.Errorf("missing org and repo in the repository url: %s", repoUrl)
	}
	return u.Host, path[1], path[2], nil
}

func getClientAdapter(scmName string, accessToken string) (adapter.ClientAdapter, error) {
	var err error
	var adapter adapter.ClientAdapter
	httpClient := utils.GetHttpClient(accessToken)

	switch scmName {
	case GithubEndpoint:
		err = github.Adapter.Init(httpClient)
		adapter = &github.Adapter
	default:
		adapter = nil
	}

	if err != nil {
		logger.Error(err, "error with github init client")
		return &github.ClientAdapterImpl{}, nil
	}
	return adapter, err
}
