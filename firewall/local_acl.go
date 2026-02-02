package firewall

import (
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/exp/slog"

	"github.com/gravitl/netclient/config"
)

const localACLComment = "NETMAKER-LOCAL-ACL"

// LocalACLRule defines a single local ACL rule
type LocalACLRule struct {
	Source   string `json:"source"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Comment  string `json:"comment"`
}

// LocalACLConfig defines the local ACL configuration file format
type LocalACLConfig struct {
	Enabled    bool           `json:"enabled"`
	LogDropped bool           `json:"log_dropped"`
	LogPrefix  string         `json:"log_prefix"`
	Rules      []LocalACLRule `json:"rules"`
}

// LoadLocalACLConfig reads the local ACL config from the netclient config directory.
// Returns nil if the file does not exist or cannot be parsed.
func LoadLocalACLConfig() *LocalACLConfig {
	path := filepath.Join(config.GetNetclientPath(), "local-acl.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("failed to read local ACL config", "path", path, "error", err)
		}
		return nil
	}
	var cfg LocalACLConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		slog.Warn("failed to parse local ACL config", "path", path, "error", err)
		return nil
	}
	return &cfg
}
