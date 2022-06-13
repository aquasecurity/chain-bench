package config

import (
	"github.com/aquasecurity/chain-bench/internal/logger"
)

func loadDefaultConfiguration() *Configuration {
	return &Configuration{
		LogConfiguration: &LogConfiguration{
			LogLevel:  "info",
			LogFormat: logger.NormalFormat,
		},
	}
}
