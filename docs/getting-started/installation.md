# Installation

## Nix/NixOS

Direct issues installing `chain-bench` via `nix` through the channels mentioned [here](https://nixos.wiki/wiki/Support)

You can use `nix` on Linux or macOS and on other platforms unofficially.

`nix-env --install -A nixpkgs.chain-bench`

Or through your configuration as usual

NixOS:

```nix
  # your other config ...
  environment.systemPackages = with pkgs; [
    # your other packages ...
    chain-bench
  ];
```

home-manager:

```nix
  # your other config ...
  home.packages = with pkgs; [
    # your other packages ...
    chain-bench
  ];
```

## Binary

Download the archive file for your operating system/architecture from [here](https://github.com/aquasecurity/chain-bench/releases/latest).
<!-- TODO: swap to GH pages [here](https://github.com/aquasecurity/chain-bench/releases/tag/{{ git.tag }}). -->
Unpack the archive, and put the binary somewhere in your `$PATH` (on UNIX-y systems, `/usr/local/bin` or the like).
Make sure it has execution bits turned on.

## From source

```bash
mkdir -p $GOPATH/src/github.com/aquasecurity
cd $GOPATH/src/github.com/aquasecurity
git clone --depth 1 https://github.com/aquasecurity/chain-bench
cd chain-bench/cmd/chain-bench/
export GO111MODULE=on
go install
```
<!-- TODO: swap to GH pages git clone --depth 1 --branch {{ git.tag }} https://github.com/aquasecurity/chain-bench -->

## From source with `go install`

With a sufficient version of `go` you can install and build with `go install github.com/aquasecurity/chain-bench/cmd/chain-bench@latest`
<!-- TODO: swap to GH pages `go install github.com/aquasecurity/chain-bench/cmd/chain-bench@{{ git.tag }}` -->

## Docker

### Docker Hub

```bash
docker pull aquasec/chain-bench:latest
```
<!-- TODO: swap to GH pages {{ git.tag[1:] }} -->

Example:

    ``` bash
    docker run --rm aquasec/chain-bench:latest scan --repository-url <REPOSITORY_URL> --access-token <TOKEN>
    ```
