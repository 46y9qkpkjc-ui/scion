// Copyright 2018 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config contains the configuration of the SCION Daemon.
package config

import (
	"fmt"
	"io"
	"time"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/env"
	api "github.com/scionproto/scion/private/mgmtapi"
	"github.com/scionproto/scion/private/storage"
	trustengine "github.com/scionproto/scion/private/trust/config"
)

var (
	DefaultQueryInterval = 5 * time.Minute
)

var _ config.Config = (*Config)(nil)

type Config struct {
	General       env.General        `toml:"general,omitempty"`
	Features      env.Features       `toml:"features,omitempty"`
	Logging       log.Config         `toml:"log,omitempty"`
	Metrics       env.Metrics        `toml:"metrics,omitempty"`
	API           api.Config         `toml:"api,omitempty"`
	Tracing       env.Tracing        `toml:"tracing,omitempty"`
	TrustDB       storage.DBConfig   `toml:"trust_db,omitempty"`
	PathDB        storage.DBConfig   `toml:"path_db,omitempty"`
	SD            SDConfig           `toml:"sd,omitempty"`
	TrustEngine   trustengine.Config `toml:"trustengine,omitempty"`
	DRKeyLevel2DB storage.DBConfig   `toml:"drkey_level2_db,omitempty"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Tracing,
		cfg.TrustDB.WithDefault(fmt.Sprintf(storage.DefaultTrustDBPath, "sd")),
		cfg.PathDB.WithDefault(fmt.Sprintf(storage.DefaultPathDBPath, "sd")),
		&cfg.SD,
		&cfg.TrustEngine,
	)
}

func (cfg *Config) Validate() error {
	return config.ValidateAll(
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.TrustDB,
		&cfg.PathDB,
		&cfg.SD,
		&cfg.TrustEngine,
		cfg.DRKeyLevel2DB.WithAllowEmptyConn(),
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteSample(dst, path, config.CtxMap{config.ID: idSample},
		&cfg.General,
		&cfg.Features,
		&cfg.Logging,
		&cfg.Metrics,
		&cfg.API,
		&cfg.Tracing,
		config.OverrideName(
			config.FormatData(
				&cfg.TrustDB,
				fmt.Sprintf(storage.DefaultTrustDBPath, "sd"),
			),
			"trust_db",
		),
		config.OverrideName(
			config.FormatData(
				&cfg.PathDB,
				fmt.Sprintf(storage.DefaultPathDBPath, "sd"),
			),
			"path_db",
		),
		&cfg.SD,
		&cfg.TrustEngine,
		config.OverrideName(
			config.FormatData(
				&cfg.DRKeyLevel2DB,
				fmt.Sprintf(storage.DefaultDRKeyLevel2DBPath, "sd"),
			),
			"drkey_level2_db",
		),
	)
}

var _ config.Config = (*SDConfig)(nil)

type SDConfig struct {
	// Address is the local address to listen on for SCION messages, and to send out messages to
	// other nodes.
	Address string `toml:"address,omitempty"`
	// DisableSegVerification indicates that segment verification should be
	// disabled.
	DisableSegVerification bool `toml:"disable_seg_verification,omitempty"`
	// QueryInterval specifies after how much time segments
	// for a destination should be refetched.
	QueryInterval util.DurWrap `toml:"query_interval,omitempty"`
	// HiddenPathGroup is a file that contains the hiddenpath groups.
	// If HiddenPathGroups begins with http:// or https://, it will be fetched
	// over the network from the specified URL instead.
	HiddenPathGroups string `toml:"hidden_path_groups,omitempty"`
	// PathQuality configures quality-aware path monitoring and rerouting.
	PathQuality PathQualityConfig `toml:"path_quality,omitempty"`
}

// PathQualityConfig configures the quality-aware path monitoring.
type PathQualityConfig struct {
	// Enable activates quality-aware path monitoring. (default false)
	Enable bool `toml:"enable,omitempty"`
	// ProbeInterval is how often probes are sent per path. (default 500ms)
	ProbeInterval util.DurWrap `toml:"probe_interval,omitempty"`
	// PathRefreshInterval is how often the path list is refreshed. (default 10s)
	PathRefreshInterval util.DurWrap `toml:"path_refresh_interval,omitempty"`
	// MaxRTT is the RTT threshold for path degradation. (default 200ms)
	MaxRTT util.DurWrap `toml:"max_rtt,omitempty"`
	// MaxLossRate is the loss rate threshold for path degradation. (default 0.05)
	MaxLossRate float64 `toml:"max_loss_rate,omitempty"`
	// MaxJitter is the jitter threshold for path degradation. (default 30ms)
	MaxJitter util.DurWrap `toml:"max_jitter,omitempty"`
}

func (cfg *SDConfig) InitDefaults() {
	if cfg.Address == "" {
		cfg.Address = daemon.DefaultAPIAddress
	}
	if cfg.QueryInterval.Duration == 0 {
		cfg.QueryInterval.Duration = DefaultQueryInterval
	}
	cfg.PathQuality.InitDefaults()
}

func (cfg *SDConfig) Validate() error {
	if cfg.QueryInterval.Duration == 0 {
		return serrors.New("QueryInterval must not be zero")
	}
	return cfg.PathQuality.Validate()
}

func (cfg *SDConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, sdSample)
}

func (cfg *SDConfig) ConfigName() string {
	return "sd"
}

// InitDefaults sets sensible defaults for PathQualityConfig.
func (cfg *PathQualityConfig) InitDefaults() {
	if cfg.ProbeInterval.Duration == 0 {
		cfg.ProbeInterval.Duration = 500 * time.Millisecond
	}
	if cfg.PathRefreshInterval.Duration == 0 {
		cfg.PathRefreshInterval.Duration = 10 * time.Second
	}
	if cfg.MaxRTT.Duration == 0 {
		cfg.MaxRTT.Duration = 200 * time.Millisecond
	}
	if cfg.MaxLossRate == 0 {
		cfg.MaxLossRate = 0.05
	}
	if cfg.MaxJitter.Duration == 0 {
		cfg.MaxJitter.Duration = 30 * time.Millisecond
	}
}

// Validate checks PathQualityConfig for invalid values.
func (cfg *PathQualityConfig) Validate() error {
	if cfg.MaxLossRate < 0 || cfg.MaxLossRate > 1 {
		return serrors.New("path_quality.max_loss_rate must be between 0 and 1",
			"value", cfg.MaxLossRate)
	}
	return nil
}
