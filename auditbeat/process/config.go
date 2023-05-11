package process

import (
	"time"

	"github.com/elastic/beats/v7/auditbeat/helper/hasher"
)

// Config defines the host metricset's configuration options.
type Config struct {
	StatePeriod        time.Duration `config:"state.period"`
	ProcessStatePeriod time.Duration `config:"process.state.period"`

	HasherConfig hasher.Config `cnfig:"process.hash"`
}

// Validate validates the config.
func (c *Config) Validate() error {
	return c.HasherConfig.Validate()
}

func (c *Config) effectiveStatePeriod() time.Duration {
	if c.ProcessStatePeriod != 0 {
		return c.ProcessStatePeriod
	}
	return c.StatePeriod
}

var defaultConfig = Config{
	StatePeriod: 12 * time.Hour,

	HasherConfig: hasher.Config{
		HashTypes:           []hasher.HashType{hasher.SHA1},
		MaxFileSize:         "100 MiB",
		MaxFileSizeBytes:    100 * 1024 * 1024,
		ScanRatePerSec:      "50 MiB",
		ScanRateBytesPerSec: 50 * 1024 * 1024,
	},
}
