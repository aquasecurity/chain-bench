package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/aquasecurity/chain-bench/internal/checker"
	"github.com/aquasecurity/chain-bench/internal/checks"
	"github.com/aquasecurity/chain-bench/internal/config"
	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
	"github.com/aquasecurity/chain-bench/internal/scm-clients/clients"
)

func Scan(accessToken string, repositoryUrl string) ([]checkmodels.CheckRunResult, []error) {
	logger.Info("[WASM] Starting supply chain scan (Powered by https://github.com/aquasecurity/chain-bench)")

	assetsData, err := clients.FetchClientData(accessToken, repositoryUrl)
	if err != nil {
		return nil, []error{err}
	}
	checks := checks.GetChecks(assetsData)
	return checker.RunChecks(assetsData, &config.Configuration{AccessToken: accessToken, RepositoryUrl: repositoryUrl}, checks)

}

func WasmScanWrapper(this js.Value, args []js.Value) interface{} {

	if len(args) != 3 {
		panic("Invalid number of arguments")
	}

	accessToken := args[0].String()
	repositoryUrl := args[1].String()
	callback := args[2].String()

	if js.Global().Get(callback).IsUndefined() {
		panic("Callback is undefined")
	}

	go func() {
		results, errors := Scan(accessToken, repositoryUrl)
		jsonOutput, err := json.Marshal(results)
		if err != nil {
			panic(err)
		}

		parsedErrors := make([]interface{}, 0)
		for _, error := range errors {
			parsedErrors = append(parsedErrors, error.Error())
		}

		js.Global().Call(callback, string(jsonOutput), parsedErrors)
	}()

	return nil

}

func main() {
	c := make(chan int)
	js.Global().Set("scan", js.FuncOf(WasmScanWrapper))
	<-c
}
