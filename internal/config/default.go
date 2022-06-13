package config

import (
	"github.com/argonsecurity/chain-bench/internal/logger"
)

func loadDefaultConfiguration() *Configuration {
	return &Configuration{
		LogConfiguration: &LogConfiguration{
			LogLevel:  "info",
			LogFormat: logger.NormalFormat,
		},
	}
}
