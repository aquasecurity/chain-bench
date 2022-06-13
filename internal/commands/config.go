package commands

import "github.com/aquasecurity/chain-bench/internal/config"

func generateCliConfig() *config.Configuration {
	return &config.Configuration{
		LogConfiguration: &config.LogConfiguration{
			LogFilePath: logFilePath,
			LogLevel:    logLevel,
			LogFormat:   logFormat,
			NoColor:     noColor,
		},
		OutputFilePath: outputFilePath,
		RepositoryUrl:  repositoryUrl,
		AccessToken:    accessToken,
	}
}
