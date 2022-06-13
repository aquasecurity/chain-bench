<p align="center">
  <img src="docs/imgs/banner.png">
</p>

<p align="center">
chain-bench is a tool that checks whether your software supply chain stack is deployed securely by running the checks documented in the
  <a href="https://www.cisecurity.org/benchmark/software_supply_chain">CIS Software Supply Chain Benchmark</a>.
</p>

[![GitHub Release][release-img]][release]
[![Downloads][download]][release]
[![Build Status](https://github.com/aquasecurity/chain-bench/workflows/Build/badge.svg?branch=main)](https://github.com/aquasecurity/chain-bench/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/aquasecurity/chain-bench/blob/main/LICENSE)

[download]: https://img.shields.io/github/downloads/aquasecurity/chain-bench/total?logo=github
[release-img]: https://img.shields.io/github/release/aquasecurity/chain-bench.svg?logo=github
[release]: https://github.com/aquasecurity/chain-bench/releases


<figure style="text-aligh: center">
  <img src="docs/imgs/demo.gif" width="1000" alt="Vulnerability Detection">
</figure>

# Quick start
There is a primarily way to run chain-bench as a stand alone cli, that requires the personal access token of your account and the repository url in order to access your SCM.

### For example 
```
chain-bench scan --repository-url <REPOSITORY_URL> --access-token <TOKEN> -o <OUTPUT_PATH>
```

<details>
<summary>Result</summary>

```
2022-05-11 14:46:18 INF 🚩 Fetch starting
2022-05-11 14:46:18 INF 🏢 Fetching Organization Settings Finished
2022-05-11 14:46:25 INF 🛢️ Fetching Repository Settings Finished
2022-05-11 14:46:26 INF 🌱 Fetching Branch Protection Settings Finished
2022-05-11 14:46:26 INF 👫 Fetching Members Finished
2022-05-11 14:46:27 INF 🔧 Fetching Pipelines Finished
2022-05-11 14:46:27 INF 🏁 Fetch succeeded
   ID                                             Name                                            Result                  Reason                 
-------- --------------------------------------------------------------------------------------- -------- ---------------------------------------
 1.1.3    Ensure any change to code receives approval of two strongly authenticated users         Passed                                         
 1.1.6    Ensure code owners are set for extra sensitive code or configuration                    Passed                                         
 1.1.8    Ensure inactive branches are reviewed and removed periodically                          Failed   21 inactive branches                  
 1.1.9    Ensure all checks have passed before the merge of new code                              Failed                                         
 1.1.13   Ensure linear history is required                                                       Failed   MergeCommit is enabled for repository 
 1.2.1    Ensure all public repositories contain a SECURITY.md file                               Failed                                         
 1.3.3    Ensure minimum admins are set for the organization                                      Passed                                         
 1.3.5    Ensure the organization is requiring members to use MFA                                 Passed                                         
 1.3.8    Ensure strict base permissions are set for repositories                                 Passed                                         
 1.3.9    Ensure an organization's identity is confirmed with a Verified badge                    Failed                                         
 2.3.1    Ensure all build steps are defined as code                                              Failed   No build job was found in pipelines   
 2.3.5    Ensure access to the build process's triggering is minimized                            Passed                                         
 2.3.7    Ensure pipelines are automatically scanned for vulnerabilities                          Passed                                         
 2.3.8    Ensure scanners are in place to identify and prevent sensitive data in pipeline files   Passed                                         
 2.4.2    Ensure all external dependencies used in the build process are locked                   Failed   16 task(s) are not pinned             
 2.4.6    Ensure pipeline steps produce an SBOM                                                   Passed                                         
-------- --------------------------------------------------------------------------------------- -------- ---------------------------------------
 Total Passed Rules: 9 out of 16                                                                                                                 
2022-05-11 14:46:28 INF Scan completed: 10.036s
```
</details>

## Please Note
Chain-bench implements the CIS Software Supply Chain Benchmark(TODO: add link) as closely as possible.
You can find the current implemented checks under [AVD - Software Supply Chain CIS - 1.0](https://avd.aquasec.com/compliance/softwaresupplychain/cis-1.0/) that update every night based chain-bench metadata.json files
Please raise issues here if chain-bench is not correctly implementing the test as described in the Benchmark. To report issues in the Benchmark itself (for example, tests that you believe are inappropriate), please join the CIS community.

## Contributing
Kindly read [Contributing](CONTRIBUTING.md) before contributing. 
We welcome PRs and issue reports.

## Roadmap
Going forward we plan to release updates to chain-bench to increase the benchmark coverage with more checks and support more platforms.
chain-bench is an Aqua Security open source project part of Trivy Family.
