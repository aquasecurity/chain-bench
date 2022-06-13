package commands

import (
	"fmt"

	"github.com/aquasecurity/chain-bench/internal/config"
	"github.com/aquasecurity/chain-bench/internal/logger"
	"github.com/imdario/mergo"
	"github.com/spf13/cobra"
)

var (
	chainbenchConfig *config.Configuration
)

func Execute(version string) error {
	rootCmd := NewChainBenchCommand(version)

	initialize(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		return err
	}

	return nil
}

func NewChainBenchCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:     "chain-bench",
		Short:   "Run CIS Benchmarks checks against your software supply chain",
		Version: version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			if chainbenchConfig, err = config.LoadConfiguration(configFilePath); err != nil {
				return err
			}

			if err = mergo.Merge(chainbenchConfig, generateCliConfig(), mergo.WithOverride); err != nil {
				return err
			}

			return initLogger()
		},
	}
}

func initLogger() error {
	logConfig := chainbenchConfig.LogConfiguration

	if err := logger.InitLogger(logConfig.LogLevel, logConfig.LogFormat, logConfig.LogFilePath, logConfig.NoColor); err != nil {
		return fmt.Errorf("failed to init logger - %s", err.Error())
	}

	return nil
}

func initialize(rootCmd *cobra.Command) {
	rootCmd.AddCommand(NewScanCommand())

	rootCmd.PersistentFlags().BoolVarP(&isQuiet,
		isQuietFlagName, isQuietShortFlag, false,
		"silence logs and report findings, cannot be used without using the -o flag")
	rootCmd.PersistentFlags().StringVarP(&outputFilePath,
		outputFilePathFlagName, outputFilePathShortFlag, "",
		"the path to a file that will contain the results of the scanning")
	rootCmd.PersistentFlags().StringVarP(&configFilePath,
		configFilePathFlagName, configFilePathShortFlag, "",
		"the path to a local configuration file")
	rootCmd.PersistentFlags().StringVarP(&logFilePath,
		logFilePathFlagName, logFilePathShortFlag, "",
		"set to print logs into a file")
	rootCmd.PersistentFlags().StringVar(&logLevel, logLevelFlagName, "",
		"sets the minimum log level (debug, info, warning, error, panic)")
	rootCmd.PersistentFlags().StringVar(&logFormat, logFormatFlagName, "",
		fmt.Sprintf("sets the format of the logs (%s, %s)", logger.NormalFormat, logger.JsonFormat))
	rootCmd.PersistentFlags().BoolVarP(&verbose, verboseFlagName, verboseShortFlag, false,
		"set to print logs to console")
	rootCmd.PersistentFlags().BoolVar(&noColor, noColorFlagName, false,
		"disables output color")

}
