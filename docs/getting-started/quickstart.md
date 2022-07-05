# Quick start
The primary way to run chain-bench is as a standalone cli. It requires an access token for your account and the repository url in order to access your SCM.

## Requirements
You must provide an access token with permission to these scopes: `repo`(all), `read:repo_hook`, `admin:org_hook`, `read:org`

## Supported Providers
 We currently support Github as the first SCM, with PAT authentication.

## For example

```shell
$ chain-bench scan --repository-url <REPOSITORY_URL> --access-token <TOKEN> -o <OUTPUT_PATH>

2022-06-13 15:22:18 INF 🚩	Fetch Starting
2022-06-13 15:22:19 INF 🏢	Fetching Organization Settings Finished
2022-06-13 15:22:29 INF 🛢️	Fetching Repository Settings Finished
2022-06-13 15:22:29 INF 🌱	Fetching Branch Protection Settings Finished
2022-06-13 15:22:29 INF 👫	Fetching Members Finished
2022-06-13 15:22:31 INF 🔧	Fetching Pipelines Finished
2022-06-13 15:22:31 INF 🏁	Fetch succeeded
   ID                                                 Name                                                Result                  Reason                 
-------- ----------------------------------------------------------------------------------------------- -------- ---------------------------------------
 1.1.3    Ensure any change to code receives approval of two strongly authenticated users                 Passed                                         
 1.1.4    Ensure previous approvals are dismissed when updates are introduced to a code change proposal   Failed                                         
 1.1.5    Ensure that there are restrictions on who can dismiss code change reviews                       Failed                                         
 1.1.6    Ensure code owners are set for extra sensitive code or configuration                            Failed                                         
 1.1.8    Ensure inactive branches are reviewed and removed periodically                                  Failed   20 inactive branches                  
 1.1.9    Ensure all checks have passed before the merge of new code                                      Passed                                         
 1.1.10   Ensure open git branches are up to date before they can be merged into codebase                 Passed                                         
 1.1.11   Ensure all open comments are resolved before allowing to merge code changes                     Passed                                         
 1.1.12   Ensure verifying signed commits of new changes before merging                                   Failed                                         
 1.1.13   Ensure linear history is required                                                               Passed                                         
 1.1.14   Ensure branch protection rules are enforced on administrators                                   Failed                                         
 1.1.15   Ensure pushing of new code is restricted to specific individuals or teams                       Passed                                         
 1.1.16   Ensure force pushes code to branches is denied                                                  Failed                                         
 1.1.17   Ensure branch deletions are denied                                                              Failed                                         
 1.2.1    Ensure all public repositories contain a SECURITY.md file                                       Failed                                         
 1.2.2    Ensure repository creation is limited to specific members                                       Failed                                         
 1.2.3    Ensure repository deletion is limited to specific members                                       Passed                                         
 1.2.4    Ensure issue deletion is limited to specific members                                            Passed                                         
 1.3.1    Ensure inactive users are reviewed and removed periodically                                     Failed   22 inactive users                     
 1.3.3    Ensure minimum admins are set for the organization                                              Passed                                         
 1.3.5    Ensure the organization is requiring members to use MFA                                         Passed                                         
 1.3.7    Ensure 2 admins are set for each repository                                                     Failed                                         
 1.3.8    Ensure strict base permissions are set for repositories                                         Passed                                         
 1.3.9    Ensure an organization's identity is confirmed with a Verified badge                            Failed                                         
 2.3.1    Ensure all build steps are defined as code                                                      Failed   No build job was found in pipelines   
 2.3.5    Ensure access to the build process's triggering is minimized                                    Passed                                         
 2.3.7    Ensure pipelines are automatically scanned for vulnerabilities                                  Passed                                         
 2.3.8    Ensure scanners are in place to identify and prevent sensitive data in pipeline files           Failed   Repository is not scanned for secrets 
 2.4.2    Ensure all external dependencies used in the build process are locked                           Failed   16 task(s) are not pinned             
 2.4.6    Ensure pipeline steps produce an SBOM                                                           Passed                                         
 3.1.7    Ensure dependencies are pinned to a specific, verified version                                  Failed   16 dependenc(ies) are not pinned      
 3.2.2    Ensure packages are automatically scanned for known vulnerabilities                             Passed                                         
 3.2.3    Ensure packages are automatically scanned for license implications                              Passed                                         
 4.2.3    Ensure user's access to the package registry utilizes MFA                                       Passed                                         
 4.2.5    Ensure anonymous access to artifacts is revoked                                                 Passed                                         
 4.3.4    Ensure webhooks of the package registry are secured                                             Passed                                         
-------- ----------------------------------------------------------------------------------------------- -------- ---------------------------------------
 Total Passed Rules: 19 out of 36                                                                                                                        
2022-06-13 15:22:31 INF Scan completed: 13.108s
```
