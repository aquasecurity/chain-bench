package gitlab

import (
	"net/http"
	"strconv"

	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/xanzy/go-gitlab"
)

var (
	Adapter ClientAdapterImpl
)

type ClientAdapterImpl struct {
	client GitlabClient
}

func (*ClientAdapterImpl) Init(client *http.Client, token string) error {
	glClient, err := InitClient(client, token)
	Adapter = ClientAdapterImpl{client: glClient}
	return err
}

func (ca *ClientAdapterImpl) GetAuthorizedUser() (*models.User, error) {
	res, _, err := ca.client.GetAuthorizedUser()
	if err != nil {
		logger.Error(err, "error in authenticated user data")
		return nil, err
	}

	return toUser(res), nil
}

// GetRepository implements clients.ClientAdapter
func (ca *ClientAdapterImpl) GetRepository(owner string, repo string, branch string) (*models.Repository, error) {
	rep, _, err := ca.client.GetRepository(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching repository data")
		return nil, err
	}

	// commits, _, err := ca.client.ListCommits(owner, repo, &github.CommitsListOptions{Since: time.Now().AddDate(0, -3, 0)})
	// if err != nil {
	// 	logger.WarnE(err, "failed to fetch commits data")
	// }

	branches, err := ca.ListRepositoryBranches(owner, strconv.Itoa(rep.ID))
	if err != nil {
		logger.WarnE(err, "failed to fetch branches data")
	}

	// isRepoContainsSecurityMD := ca.isRepositoryContainsSecurityMdFile(owner, repo, utils.GetBranchName(utils.GetValue(rep.DefaultBranch), branch))

	// collaborators, _, err := ca.client.ListRepositoryCollaborators(owner, repo)
	// if err != nil {
	// 	logger.WarnE(err, "failed to fetch collaborators data")
	// }

	// hooks, _, err := ca.client.ListRepositoryHooks(owner, repo)
	// if err != nil {
	// 	logger.WarnE(err, "failed to fetch hooks data")
	// }
	return toRepository(rep, branches, nil, nil, nil, false), nil
	//return toRepository(rep, branches, nil, nil, nil, false), nil
}

//listRepositoryBranches implements clients.ClientAdapter
func (ca *ClientAdapterImpl) ListRepositoryBranches(owner string, repo string) ([]*models.Branch, error) {
	branches, _, err := ca.client.ListRepositoryBranches(owner, repo)
	if err != nil {
		logger.Error(err, "error in fetching branches")
		return nil, err
	}
	enhancedBranches := []*gitlab.Branch{}

	for _, b := range branches {
		//commit, _, err := ca.client.GetCommit(owner, repo, utils.GetValue(b.Commit.SHA))
		if err != nil {
			logger.WarnE(err, "failed to fetch branches commit")
		} else {
			branch := &gitlab.Branch{
				Name:      b.Name,
				Commit:    b.Commit,
				Protected: b.Protected,
			}
			enhancedBranches = append(enhancedBranches, branch)
		}
	}
	return toBranches(enhancedBranches), nil
	//return branches, nil
}

func (ca *ClientAdapterImpl) GetOrganization(owner string) (*models.Organization, error) {
	org, _, err := ca.client.GetOrganization(owner)
	if err != nil {
		logger.Error(err, "error in fetching organization")
		return nil, err
	}
	// hooks, _, err := ca.client.ListOrganizationHooks(owner)
	// if err != nil {
	// 	logger.WarnE(err, "failed to fetch organization hooks")
	// }
	return toOrganization(org, nil), nil
}

// // isRepositoryContainsSecurityMdFile implements clients.ClientAdapter
// func (ca *ClientAdapterImpl) isRepositoryContainsSecurityMdFile(owner, repo, branch string) bool {
// 	// optionalSecurityMDNames := []string{"SECURITY.md", "security.md", "Security.md"}

// 	// for _, optionalName := range optionalSecurityMDNames {
// 	// 	securityMdFile, _, _, _ := ca.client.GetContent(owner, repo, optionalName, branch)
// 	// 	if securityMdFile != nil {
// 	// 		return true
// 	// 	}
// 	// }

// 	return false
// }

// // GetCommit implements clients.ClientAdapter
// func (ca *ClientAdapterImpl) GetCommit(owner string, repo string, sha string) (*models.RepositoryCommit, error) {
// 	// commit, _, err := ca.client.GetCommit(owner, repo, sha)
// 	// if err != nil {
// 	// 	logger.Error(err, "error in fetching commit")
// 	// 	return nil, err
// 	// }
// 	// return toCommit(commit), nil
// 	return nil, nil
// }

//GetBranchProtection implements clients.ClientAdapter
func (ca *ClientAdapterImpl) GetBranchProtection(owner string, repo *models.Repository, branch string) (*models.Protection, error) {
	projectId := strconv.Itoa(int(*repo.ID))
	prot, _, err := ca.client.GetBranchProtection(owner, projectId, branch)
	if err != nil {
		logger.Error(err, "error in fetching branch protection")
		return nil, err
	}

	appConf, _, err := ca.client.GetApprovalConfiguration(projectId)
	if err != nil {
		logger.WarnE(err, "failed to fetch approval configuration")
	}

	pushRules, _, err := ca.client.GetProjectPushRules(projectId)
	if err != nil {
		logger.WarnE(err, "failed to fetch approval configuration")
	}

	appRules, _, err := ca.client.GetProjectApprovalRules(projectId)
	if err != nil {
		logger.WarnE(err, "failed to fetch approval rules")
	}

	proj, _, err := ca.client.GetRepository(owner, *repo.Name)
	if err != nil {
		logger.WarnE(err, "failed to fetch project")
	}
	return toBranchProtection(proj, prot, appConf, appRules, pushRules), nil
}

// func (ca *ClientAdapterImpl) ListOrganizationMembers(organization string) ([]*models.User, error) {
// 	// allMembers, _, err := ca.client.ListOrganizationMembers(organization, nil)
// 	// if err != nil {
// 	// 	logger.Error(err, "error in fetching members")
// 	// 	return nil, err
// 	// }
// 	// admins, _, err := ca.client.ListOrganizationMembers(organization, &github.ListMembersOptions{Role: "admin"})
// 	// if err != nil {
// 	// 	logger.Error(err, "error in fetching admins")
// 	// 	return nil, err
// 	// }
// 	// return patchAdminRoles(toUsers(allMembers), toUsers(admins)), nil
// 	return nil, nil
// }

// func (ca *ClientAdapterImpl) GetRegistry(organization *models.Organization) (*models.PackageRegistry, error) {
// 	// if organization == nil {
// 	// 	return nil, errors.New("organization is nil")
// 	// }
// 	// packagesTypes := []string{"npm", "maven", "rubygems", "nuget", "docker", "container"}
// 	// packages := []*github.Package{}

// 	// for _, packageType := range packagesTypes {
// 	// 	pkgs, _, err := ca.client.ListOrganizationPackages(*organization.Login, packageType)
// 	// 	if err != nil {
// 	// 		logger.WarnE(err, "failed to fetch org packages")
// 	// 		packages = nil
// 	// 		break
// 	// 	}
// 	// 	packages = append(packages, pkgs...)
// 	// }

// 	// return toRegistry(packages, organization.TwoFactorRequirementEnabled), nil
// 	return nil, nil
// }

// func patchAdminRoles(allMembers []*models.User, admins []*models.User) []*models.User {
// 	// for _, admin := range admins {
// 	// 	for _, member := range allMembers {
// 	// 		if *member.Login == *admin.Login {
// 	// 			member.Role = "admin"
// 	// 		}
// 	// 	}
// 	// }
// 	// return allMembers
// 	return nil
// }

// func (ca *ClientAdapterImpl) GetPipelines(owner string, repo string, branch string) ([]*pipelineModels.Pipeline, error) {
// 	// workflows, _, err := ca.client.GetWorkflows(owner, repo)
// 	// if err != nil {
// 	// 	logger.Error(err, "error in fetching workflows")
// 	// 	return nil, err
// 	// }

// 	// pipelines := make([]*pipelineModels.Pipeline, 0)
// 	// for _, workflow := range workflows.Workflows {
// 	// 	if *workflow.Path == "" {
// 	// 		continue
// 	// 	}
// 	// 	buf, err := ca.GetFileContent(owner, repo, *workflow.Path, branch)
// 	// 	if err != nil {
// 	// 		return nil, err
// 	// 	}

// 	// 	if buf == nil {
// 	// 		continue
// 	// 	}

// 	// 	pipeline, err := toPipeline(buf)
// 	// 	if err != nil {
// 	// 		return nil, err
// 	// 	}
// 	// 	pipelines = append(pipelines, pipeline)
// 	// }
// 	// return pipelines, nil
// 	return nil, nil
// }

// func (ca *ClientAdapterImpl) GetFileContent(owner string, repo string, filepath string, ref string) ([]byte, error) {
// 	// file, _, res, err := ca.client.GetContent(owner, repo, filepath, ref)
// 	// if res.StatusCode == 404 { // the workflow object exists, but the file is deleted
// 	// 	logger.Warnf("file %s not found", filepath)
// 	// 	return nil, nil
// 	// }

// 	// if err != nil {
// 	// 	logger.Error(err, "error in fetching file content")
// 	// 	return nil, err
// 	// }

// 	// decodedText, err := base64.StdEncoding.DecodeString(*file.Content)
// 	// if err != nil {
// 	// 	logger.Error(err, "error in decoding file content")
// 	// 	return nil, err
// 	// }
// 	// return decodedText, nil
// 	return nil, nil
// }

//var _ adapter.ClientAdapter = (*ClientAdapterImpl)(nil) // Verify that *ClientAdapterImpl implements ClientAdapter.
