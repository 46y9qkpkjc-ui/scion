// Copyright 2026 Nexus-SCION Contributors
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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/private/app/flag"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/scion/pathquality"
)

func newPathquality(pather CommandPather) *cobra.Command {
	var envFlags flag.SCIONEnvironment
	var flags struct {
		timeout       time.Duration
		probeDuration time.Duration
		probeInterval time.Duration
		maxPaths      int
		refresh       bool
		format        string
		logLevel      string
		noColor       bool
		tracer        string
	}

	var cmd = &cobra.Command{
		Use:     "pathquality",
		Short:   "Probe and display path quality metrics to a SCION AS",
		Aliases: []string{"pq"},
		Args:    cobra.ExactArgs(1),
		Example: fmt.Sprintf(`  %[1]s pathquality 1-ff00:0:110
  %[1]s pathquality 1-ff00:0:110 --probe-duration 10s
  %[1]s pathquality 1-ff00:0:110 --probe-interval 200ms --format json
  %[1]s pathquality 1-ff00:0:110 --maxpaths 5 --format csv`, pather.CommandPath()),
		Long: `'pathquality' probes available paths to a destination SCION AS and
displays detailed quality metrics for each path.

Unlike 'showpaths' which only tests binary alive/dead status, pathquality
performs continuous probing to measure:

  \* RTT (round-trip time) — EWMA-smoothed latency
  \* Jitter — variation in RTT
  \* Packet Loss — percentage of dropped probes
  \* Quality Score — composite score (0.0-1.0) combining all metrics

Paths are ranked by quality score, with the best path shown first.
The daemon's quality-aware path selector uses these same metrics to
automatically choose the best path for SCION applications.

The quality score is computed as:
  40%% latency + 35%% loss + 25%% jitter (1.0 = best, 0.0 = worst)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dst, err := addr.ParseIA(args[0])
			if err != nil {
				return serrors.Wrap("invalid destination ISD-AS", err)
			}
			if err := app.SetupLog(flags.logLevel); err != nil {
				return serrors.Wrap("setting up logging", err)
			}
			closer, err := setupTracer("pathquality", flags.tracer)
			if err != nil {
				return serrors.Wrap("setting up tracing", err)
			}
			defer closer()

			cmd.SilenceUsage = true

			if err := envFlags.LoadExternalVars(); err != nil {
				return err
			}
			if err := envFlags.Validate(); err != nil {
				return err
			}

			span, traceCtx := tracing.CtxWith(context.Background(), "run")
			span.SetTag("dst.isd_as", dst)
			defer span.Finish()

			ctx, cancel := context.WithTimeout(traceCtx, flags.timeout)
			defer cancel()

			sd, err := daemon.NewAutoConnector(ctx,
				daemon.WithDaemon(envFlags.Daemon()),
				daemon.WithConfigDir(envFlags.ConfigDir()),
			)
			if err != nil {
				return serrors.Wrap("getting daemon connector", err)
			}
			defer func(sd daemon.Connector) {
				if err := sd.Close(); err != nil {
					log.Error("Closing SCION Daemon connection", "err", err)
				}
			}(sd)

			cfg := pathquality.Config{
				Connector:     sd,
				ProbeInterval: flags.probeInterval,
				ProbeDuration: flags.probeDuration,
				MaxPaths:      flags.maxPaths,
				Refresh:       flags.refresh,
			}

			res, err := pathquality.Run(ctx, dst, cfg)
			if err != nil {
				return err
			}

			switch flags.format {
			case "human":
				if len(res.Paths) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "No paths found to %s\n", dst)
					return app.WithExitCode(serrors.New("no paths found"), 1)
				}
				res.Human(cmd.OutOrStdout(), flags.noColor)
				if res.Alive() == 0 {
					return app.WithExitCode(serrors.New("no path alive"), 1)
				}
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				return enc.Encode(res)
			case "yaml":
				enc := yaml.NewEncoder(os.Stdout)
				return enc.Encode(res)
			case "csv":
				res.WriteCSV(cmd.OutOrStdout())
			default:
				return serrors.New("output format not supported", "format", flags.format)
			}
			return nil
		},
	}

	envFlags.Register(cmd.Flags())
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 15*time.Second,
		"Overall command timeout")
	cmd.Flags().DurationVar(&flags.probeDuration, "probe-duration", 5*time.Second,
		"How long to probe paths before displaying results")
	cmd.Flags().DurationVar(&flags.probeInterval, "probe-interval", 500*time.Millisecond,
		"Interval between probe packets per path")
	cmd.Flags().IntVarP(&flags.maxPaths, "maxpaths", "m", 10,
		"Maximum number of paths to probe and display")
	cmd.Flags().BoolVarP(&flags.refresh, "refresh", "r", false,
		"Force refresh of paths from the SCION Daemon")
	cmd.Flags().StringVar(&flags.format, "format", "human",
		"Output format (human|json|yaml|csv)")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false,
		"Disable colored output")
	cmd.Flags().StringVar(&flags.logLevel, "log.level", "", app.LogLevelUsage)
	cmd.Flags().StringVar(&flags.tracer, "tracing.agent", "", "Tracing agent address")

	return cmd
}
