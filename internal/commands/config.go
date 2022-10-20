package commands

import (
	"github.com/aquasecurity/chain-bench/internal/config"
	"github.com/aquasecurity/chain-bench/internal/logger"
)

func generateCliConfig() *config.Configuration {
	return &config.Configuration{
		LogConfiguration: &config.LogConfiguration{
			LogFilePath: logFilePath,
			LogLevel:    determineLogLevel(),
			LogFormat:   logFormat,
			NoColor:     noColor,
		},
		OutputFilePath:         outputFilePath,
		RepositoryUrl:          repositoryUrl,
		OutputTemplateFilePath: outputTemplateFilePath,
		AccessToken:            accessToken,
	}
}

func determineLogLevel() logger.LogLevel {
	if isQuiet {
		return logger.ErrorLevel
	}

	if verbosity == 0 { // if no cli flag, prefer default/config file
		return ""
	}

	if verbosity == 1 {
		return logger.DebugLevel
	}

	return logger.TraceLevel
}
