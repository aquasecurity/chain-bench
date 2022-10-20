package config

import "github.com/aquasecurity/chain-bench/internal/logger"

type Configuration struct {
	LogConfiguration       *LogConfiguration `mapstructure:"logs"`
	OutputFilePath         string            `mapstructure:"output_path"`
	OutputTemplateFilePath string            `mapstructure:"output_template_path"`
	RepositoryUrl          string            `mapstructure:"repository_url"`
	AccessToken            string            `mapstructure:"access_token"`
}

type LogConfiguration struct {
	LogFilePath string          `mapstructure:"log_path"`
	LogLevel    logger.LogLevel `mapstructure:"log_level"`
	LogFormat   string          `mapstructure:"log_format"`
	NoColor     bool            `mapstructure:"no_color"`
}
