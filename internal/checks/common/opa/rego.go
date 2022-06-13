package opa

import (
	"context"
	"errors"

	_ "embed"

	"github.com/argonsecurity/chain-bench/internal/consts"
	"github.com/argonsecurity/chain-bench/internal/models/checkmodels"
	"github.com/mitchellh/mapstructure"
	"github.com/open-policy-agent/opa/rego"
)

var (
	errorNoResultStatus = errors.New("Missing check result")
)

type RegoResult struct {
	Status  checkmodels.ResultStatus `json:"status,omitempty"`
	IDs     []string                 `json:"ids,omitempty"`
	Details string                   `json:"details,omitempty"`
}

func RunRego(input interface{}, regoModules []checkmodels.RegoCustomModule, checksMetadata *checkmodels.CheckMetadataMap) ([]*checkmodels.CheckRunResult, error) {
	regoInitOptions := []func(r *rego.Rego){
		rego.Input(input),
		rego.Query("data.main.CbPolicy"),
	}

	for _, m := range regoModules {
		regoInitOptions = append(regoInitOptions, rego.Module(m.Name, m.Content))
	}

	rego := rego.New(
		regoInitOptions...,
	)
	result, err := rego.Eval(context.TODO())
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	results := make([]*RegoResult, 0)
	for _, rule := range result[0].Expressions[0].Value.([]interface{}) {
		parsedRule, err := parseRegoRule(rule)
		if err != nil {
			return nil, err
		}
		results = append(results, parsedRule)
	}

	return parseRegoResult(results, checksMetadata), nil
}

func parseRegoRule(rule interface{}) (*RegoResult, error) {
	result := RegoResult{}
	if err := mapstructure.Decode(rule, &result); err != nil {
		return nil, err
	}

	if result.Status == "" {
		return nil, errorNoResultStatus
	}
	if result.IDs == nil {
		return nil, consts.ErrorNoCheckID
	}

	return &result, nil
}

func parseRegoResult(findings []*RegoResult, checksMetadata *checkmodels.CheckMetadataMap) []*checkmodels.CheckRunResult {
	mappedResults := parseRegoResultToMap(findings)

	results := make([]*checkmodels.CheckRunResult, 0)
	for id, cm := range checksMetadata.Checks {
		if cm.ScannerType == checkmodels.Rego {
			results = append(results, checkmodels.ToCheckRunResult(id, cm, checksMetadata.Url, getRunResult(id, mappedResults)))
		}
	}

	return results
}

func parseRegoResultToMap(findings []*RegoResult) checkmodels.CheckIdToCheckResultMap {
	resultMap := make(checkmodels.CheckIdToCheckResultMap)

	for _, f := range findings {
		for _, id := range f.IDs {
			resultMap[id] = checkmodels.CheckResult{
				Status:  f.Status,
				Details: f.Details,
			}
		}
	}
	return resultMap
}

func getRunResult(id string, resultsMap checkmodels.CheckIdToCheckResultMap) *checkmodels.CheckResult {
	if val, ok := resultsMap[id]; ok {
		return &checkmodels.CheckResult{Status: val.Status, Details: val.Details}
	} else {
		return &checkmodels.CheckResult{Status: checkmodels.Passed}
	}
}
