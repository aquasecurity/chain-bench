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
	GithubEndpoint = "github"
	GitlabEndpoint = "gitlab"
)

func FetchClientData(accessToken string, repoUrl string, scm string, branch string) (*checkmodels.AssetsData, []string, error) {
	host, orgName, repoName, err := getRepoInfo(repoUrl)
	if err != nil {
		return nil, nil, err
	}

	adapter, err := getClientAdapter(scm, accessToken, host)
	if err != nil {
		return nil, nil, err
	}
	authorizedUser, _ := adapter.GetAuthorizedUser()

	repo, _ := adapter.GetRepository(orgName, repoName, branch)
	logger.FetchingFinished("Repository Settings", emoji.OilDrum)

	branchName := utils.GetBranchName(utils.GetValue(repo.DefaultBranch), branch)

	logger.FetchingFinished("Branch Protection Settings", emoji.Seedling)
	protection, _ := adapter.GetBranchProtection(orgName, repo, branchName)

	pipelines, _ := adapter.GetPipelines(orgName, repoName, branchName)
	logger.FetchingFinished("Pipelines", emoji.Wrench)

	var org *models.Organization
	var registry *models.PackageRegistry

	if *repo.Owner.Type == "Organization" {
		org, _ = adapter.GetOrganization(orgName)
		logger.FetchingFinished("Organization Settings", emoji.OfficeBuilding)

		registry, _ = adapter.GetRegistry(org)

		orgMembers, err := adapter.ListOrganizationMembers(orgName)
		if err == nil {
			org.Members = orgMembers
			logger.FetchingFinished("Members", emoji.Emoji(emoji.WomanAndManHoldingHands.Tone()))
		}
	}

	checksIds, err := adapter.ListSupportedChecksIDs()

	return &checkmodels.AssetsData{
		AuthorizedUser:    authorizedUser,
		Organization:      org,
		Repository:        repo,
		BranchProtections: protection,
		Pipelines:         pipelines,
		Registry:          registry,
	}, checksIds, nil
}

func getRepoInfo(repoFullUrl string) (string, string, string, error) {
	u, err := url.Parse(repoFullUrl)
	if err != nil || u.Scheme == "" {
		logger.Errorf(err, "error in parsing repoUrl %s", repoFullUrl)
		if err == nil {
			err = errors.New("error in parsing the host")
		}
		return "", "", "", err
	}

	path := strings.Split(u.EscapedPath(), "/")
	if len(path) < 3 {
		return "", "", "", fmt.Errorf("missing org/repo in the repository url: %s", repoFullUrl)
	}
	repo := path[len(path)-1]
	namespace := strings.Split(u.Path, repo)[0]
	trimedNamespace := namespace[1:(len(namespace) - 1)]

	return u.Host, trimedNamespace, repo, nil
}

func getClientAdapter(scmName string, accessToken string, host string) (adapter.ClientAdapter, error) {
	var err error
	var adapter adapter.ClientAdapter
	httpClient := utils.GetHttpClient(accessToken)

	switch scmName {
	case GithubEndpoint:
		err = github.Adapter.Init(httpClient, accessToken, host)
		adapter = &github.Adapter
	case GitlabEndpoint:
		err = gitlab.Adapter.Init(httpClient, accessToken, host)
		adapter = &gitlab.Adapter
	default:
		adapter = nil
	}

	if err != nil {
		logger.Error(err, "error with SCM init client")
		return &github.ClientAdapterImpl{}, nil
	}
	return adapter, err
}
