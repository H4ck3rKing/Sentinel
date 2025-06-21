package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const ConfigFileName = "config.yaml"

// Config defines the structure for our project configuration.
type Config struct {
	// Workspace defines a name for the current project, used for output directories.
	Workspace string `yaml:"workspace"`

	// Targets is a list of root domains or IPs to include in the scope.
	Targets []string `yaml:"targets"`

	// Exclude is a list of domains or IPs to explicitly exclude from scans.
	Exclude []string `yaml:"exclude,omitempty"`

	// APIKeys for various services.
	APIKeys struct {
		GitHub string `yaml:"github,omitempty"`
		// Future keys: Shodan, Virustotal, etc.
	} `yaml:"api_keys,omitempty"`

	// Reconnaissance module settings
	Recon struct {
		Threads int `yaml:"threads"`
	} `yaml:"recon"`

	// Add other module configurations here, e.g., Fuzz, Scan, etc.
}

// CreateDefaultConfig generates a default config.yaml file.
func CreateDefaultConfig() (*Config, error) {
	cfg := &Config{
		Workspace: "my-first-project",
		Targets:   []string{"example.com"},
		Exclude:   []string{"docs.example.com"},
		Recon: struct {
			Threads int `yaml:"threads"`
		}{
			Threads: 50,
		},
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(ConfigFileName, data, 0644)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// SaveConfig saves the current configuration back to the config.yaml file.
func SaveConfig(cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigFileName, data, 0644)
}

// LoadConfig reads and parses the config.yaml file.
func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(ConfigFileName)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
} 