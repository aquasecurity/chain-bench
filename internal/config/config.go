package config

import (
	"fmt"
	"os"

	"github.com/imdario/mergo"
	"github.com/spf13/viper"
)

func loadConfigFile(configFilePath string) (*Configuration, error) {
	if configFilePath != "" {
		viper.SetConfigFile(configFilePath)
	} else if wd, err := os.Getwd(); err != nil {
		return nil, err
	} else {
		viper.AddConfigPath(wd)
		viper.SetConfigName("config")
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var loadedConfig *Configuration
	if err := viper.Unmarshal(&loadedConfig); err != nil {
		return nil, fmt.Errorf("failed to load config to object - %s", err.Error())
	}

	return loadedConfig, nil
}

func LoadConfiguration(configFilePath string) (*Configuration, error) {
	loadedConfig, err := loadConfigFile(configFilePath)
	if err != nil {
		return nil, err
	}

	defaultConfig := loadDefaultConfiguration()

	if loadedConfig == nil {
		return defaultConfig, nil
	}

	if err := mergo.Merge(loadedConfig, defaultConfig); err != nil {
		return nil, err
	}

	return loadedConfig, nil
}
