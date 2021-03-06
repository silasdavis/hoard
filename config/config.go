package config

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/BurntSushi/toml"
	yaml "gopkg.in/yaml.v2"
)

const DefaultListenAddress = "tcp://:53431"

var DefaultHoardConfig = NewHoardConfig(DefaultListenAddress,
	DefaultStorage, DefaultLogging)

type HoardConfig struct {
	ListenAddress string
	Storage       *Storage
	Logging       *Logging
	Secrets       *Secrets
}

func NewHoardConfig(listenAddress string, storageConfig *Storage, loggingConfig *Logging) *HoardConfig {
	return &HoardConfig{
		ListenAddress: listenAddress,
		Storage:       storageConfig,
		Logging:       loggingConfig,
	}
}

func HoardConfigFromYAMLString(yamlString string) (*HoardConfig, error) {
	hoardConfig := new(HoardConfig)
	buf := bytes.NewBufferString(yamlString)
	decoder := yaml.NewDecoder(buf)
	err := decoder.Decode(hoardConfig)
	if err != nil {
		return nil, err
	}
	return hoardConfig, nil
}

func HoardConfigFromJSONString(jsonString string) (*HoardConfig, error) {
	hoardConfig := new(HoardConfig)
	buf := bytes.NewBufferString(jsonString)
	decoder := json.NewDecoder(buf)
	err := decoder.Decode(hoardConfig)
	if err != nil {
		return nil, err
	}
	return hoardConfig, nil
}

func HoardConfigFromTOMLString(tomlString string) (*HoardConfig, error) {
	hoardConfig := new(HoardConfig)
	_, err := toml.Decode(tomlString, hoardConfig)
	if err != nil {
		return nil, err
	}
	return hoardConfig, nil
}

func (hoardConfig *HoardConfig) TOMLString() string {
	buf := new(bytes.Buffer)
	encoder := toml.NewEncoder(buf)
	err := encoder.Encode(hoardConfig)
	if err != nil {
		return fmt.Sprintf("<Could not serialise HoardConfig>")
	}
	return buf.String()
}

func (hoardConfig *HoardConfig) JSONString() string {
	buf := new(bytes.Buffer)
	encoder := json.NewEncoder(buf)
	err := encoder.Encode(hoardConfig)
	if err != nil {
		return fmt.Sprintf("<Could not serialise HoardConfig>")
	}
	return buf.String()
}

func (hoardConfig *HoardConfig) YAMLString() string {
	buf := new(bytes.Buffer)
	encoder := yaml.NewEncoder(buf)
	err := encoder.Encode(hoardConfig)
	if err != nil {
		return fmt.Sprintf("<Could not serialise HoardConfig>")
	}
	return buf.String()
}
