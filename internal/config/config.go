package config

import (
	"bytes"
	"os"
	"path/filepath"
	"text/template"

	"gopkg.in/yaml.v3"
)

const ConfigFileName = ".localproxy.yaml"

type ProjectConfig struct {
	Name      string            `yaml:"name"`
	Subdomain string            `yaml:"subdomain,omitempty"`
	Port      int               `yaml:"port,omitempty"`
	Env       map[string]string `yaml:"env,omitempty"`
}

type TemplateData struct {
	Port int
}

func LoadConfig(dir string) (*ProjectConfig, error) {
	path := filepath.Join(dir, ConfigFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Subdomain == "" {
		cfg.Subdomain = cfg.Name
	}

	return &cfg, nil
}

func SaveConfig(dir string, cfg *ProjectConfig) error {
	path := filepath.Join(dir, ConfigFileName)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (c *ProjectConfig) RenderEnv(port int) (map[string]string, error) {
	result := make(map[string]string)
	data := TemplateData{Port: port}

	for key, val := range c.Env {
		tmpl, err := template.New(key).Parse(val)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return nil, err
		}
		result[key] = buf.String()
	}

	return result, nil
}

func ConfigExists(dir string) bool {
	path := filepath.Join(dir, ConfigFileName)
	_, err := os.Stat(path)
	return err == nil
}
