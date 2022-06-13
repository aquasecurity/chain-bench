package checker

import (
	"sync"

	"github.com/aquasecurity/chain-bench/internal/config"
	"github.com/aquasecurity/chain-bench/internal/models/checkmodels"
)

func RunChecks(ad *checkmodels.AssetsData, c *config.Configuration, checks []*checkmodels.Check) ([]checkmodels.CheckRunResult, []error) {
	checksCount := getChecksCount(checks)
	resultsChan := make(chan checkmodels.CheckRunResult, checksCount)
	errsChan := make(chan error, checksCount)

	var wg sync.WaitGroup

	checkData := checkmodels.CheckData{
		AssetsMetadata: ad,
		Configuration:  c,
	}

	for _, check := range checks {
		wg.Add(1)

		go func(wg *sync.WaitGroup, action checkmodels.CheckAction, checkData *checkmodels.CheckData) {
			defer wg.Done()
			results, err := action(checkData)
			if err != nil {
				errsChan <- err
				return
			}

			for _, r := range results {
				resultsChan <- checkmodels.CheckRunResult{
					ID:       r.ID,
					Metadata: r.Metadata,
					Result:   r.Result,
				}
			}

		}(&wg, check.Action, &checkData)
	}

	wg.Wait()
	close(resultsChan)
	close(errsChan)

	return readChan(resultsChan), readChan(errsChan)
}

func readChan[T any](dataChan <-chan T) []T {
	data := make([]T, 0)
	for d := range dataChan {
		data = append(data, d)
	}
	return data
}

func getChecksCount(checks []*checkmodels.Check) int {
	ids := map[string]bool{}
	for _, action := range checks {
		for key := range action.CheckMetadataMap.Checks {
			ids[key] = true
		}
	}
	return len(ids)
}
