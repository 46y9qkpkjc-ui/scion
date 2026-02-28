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

// Package integration wires the pathquality monitor into the SCION daemon.
// It provides the bridge between the daemon engine (which fetches paths)
// and the quality monitor (which probes and ranks them).
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/scionproto/scion/daemon/pathquality"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/snet"
)

// Config holds configuration for the quality-aware daemon integration.
type Config struct {
	// LocalIA is the local ISD-AS.
	LocalIA addr.IA
	// LocalIP is the IP to use for probe connections.
	LocalIP netip.Addr
	// Topology is the local SCION topology.
	Topology snet.Topology
	// Fetcher provides paths to remote ASes.
	Fetcher fetcher.Fetcher
	// ProbeInterval is how often to send probes per path. Default: 500ms.
	ProbeInterval time.Duration
	// PathRefreshInterval is how often to refresh path lists. Default: 10s.
	PathRefreshInterval time.Duration
	// ReroutePolicy defines thresholds for quality-aware rerouting.
	ReroutePolicy pathquality.ReroutePolicy
	// ConnMetrics are optional SCION packet connection metrics.
	ConnMetrics snet.SCIONPacketConnMetrics
}

// fetcherRouter adapts a fetcher.Fetcher to the pathquality.PathRouter interface.
type fetcherRouter struct {
	ia      addr.IA
	fetcher fetcher.Fetcher
}

func (r *fetcherRouter) AllRoutes(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	return r.fetcher.GetPaths(ctx, dst, r.ia, false)
}

// QualityDaemon wraps the pathquality.Monitor and integrates it with the daemon.
type QualityDaemon struct {
	Monitor *pathquality.Monitor
	localIA addr.IA
}

// New creates a new QualityDaemon that wraps a quality monitor.
func New(cfg Config) *QualityDaemon {
	router := &fetcherRouter{
		ia:      cfg.LocalIA,
		fetcher: cfg.Fetcher,
	}

	monitor := pathquality.NewMonitor(pathquality.MonitorConfig{
		LocalIA:             cfg.LocalIA,
		LocalIP:             cfg.LocalIP,
		Topology:            cfg.Topology,
		Router:              router,
		ProbeInterval:       cfg.ProbeInterval,
		PathRefreshInterval: cfg.PathRefreshInterval,
		ReroutePolicy:       cfg.ReroutePolicy,
		ConnMetrics:         cfg.ConnMetrics,
	})

	return &QualityDaemon{
		Monitor: monitor,
		localIA: cfg.LocalIA,
	}
}

// Start begins quality monitoring. Register remote ASes to monitor
// via RegisterDestination before or after starting.
func (qd *QualityDaemon) Start(ctx context.Context) {
	qd.Monitor.Start(ctx)
}

// Stop terminates quality monitoring.
func (qd *QualityDaemon) Stop() {
	qd.Monitor.Stop()
}

// RegisterDestination begins monitoring path quality to a remote AS.
func (qd *QualityDaemon) RegisterDestination(remote addr.IA) {
	qd.Monitor.Register(remote)
}

// UnregisterDestination stops monitoring a remote AS.
func (qd *QualityDaemon) UnregisterDestination(remote addr.IA) {
	qd.Monitor.Unregister(remote)
}

// BestPath returns the highest quality path to a destination, or nil.
func (qd *QualityDaemon) BestPath(remote addr.IA) snet.Path {
	return qd.Monitor.GetBestPath(remote)
}

// RankedPaths returns all paths to a destination, sorted by quality score.
func (qd *QualityDaemon) RankedPaths(remote addr.IA) []pathquality.RankedPath {
	return qd.Monitor.GetRankedPaths(remote)
}

// QualityStats returns quality metrics for all monitored paths to a destination.
func (qd *QualityDaemon) QualityStats(remote addr.IA) map[snet.PathFingerprint]pathquality.QualityStats {
	return qd.Monitor.GetQualityStats(remote)
}

// QualityAwarePaths enhances the standard daemon Paths() response by:
// 1. Auto-registering the destination for quality monitoring
// 2. Returning paths sorted by quality score instead of randomly
//
// This is the main integration point - call this instead of the standard
// DaemonEngine.Paths() when quality-aware routing is desired.
func (qd *QualityDaemon) QualityAwarePaths(
	ctx context.Context,
	f fetcher.Fetcher,
	dst, src addr.IA,
	refresh bool,
) ([]snet.Path, error) {
	// Fetch paths normally — match DaemonEngine parameter order
	paths, err := f.GetPaths(ctx, dst, src, refresh)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return paths, nil
	}

	// Auto-register the destination for quality monitoring
	qd.Monitor.Register(dst)

	// Check if we have quality data
	stats := qd.Monitor.GetQualityStats(dst)
	if len(stats) == 0 {
		// No quality data yet, return paths in original order
		return paths, nil
	}

	// Sort paths by quality score (descending)
	sort.SliceStable(paths, func(i, j int) bool {
		fpI := paths[i].Metadata().Fingerprint()
		fpJ := paths[j].Metadata().Fingerprint()
		statsI, okI := stats[fpI]
		statsJ, okJ := stats[fpJ]
		if !okI && !okJ {
			return false
		}
		if !okI {
			return false
		}
		if !okJ {
			return true
		}
		return statsI.Score > statsJ.Score
	})

	return paths, nil
}

// HTTPHandler returns an HTTP handler that exposes path quality metrics
// as a JSON REST API. This can be mounted on the daemon's management API.
//
// Endpoints:
//
//	GET /pathquality/destinations         - list monitored destinations
//	GET /pathquality/paths?dst=<ISD-AS>   - quality metrics for paths to dst
//	POST /pathquality/register?dst=<ISD-AS> - register a destination for monitoring
//	DELETE /pathquality/register?dst=<ISD-AS> - unregister a destination
func (qd *QualityDaemon) HTTPHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/pathquality/destinations", func(w http.ResponseWriter, r *http.Request) {
		monitored := qd.Monitor.ListMonitored()
		result := make([]string, len(monitored))
		for i, ia := range monitored {
			result[i] = ia.String()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"destinations": result,
		})
	})

	mux.HandleFunc("/pathquality/paths", func(w http.ResponseWriter, r *http.Request) {
		dstStr := r.URL.Query().Get("dst")
		if dstStr == "" {
			http.Error(w, "missing 'dst' query parameter", http.StatusBadRequest)
			return
		}
		dst, err := addr.ParseIA(dstStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid ISD-AS: %v", err), http.StatusBadRequest)
			return
		}

		ranked := qd.Monitor.GetRankedPaths(dst)
		response := pathquality.QualityResponseJSON{
			Paths: make([]pathquality.PathQualityJSON, len(ranked)),
		}
		for i, rp := range ranked {
			response.Paths[i] = pathquality.RankedPathToJSON(rp)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/pathquality/register", func(w http.ResponseWriter, r *http.Request) {
		dstStr := r.URL.Query().Get("dst")
		if dstStr == "" {
			http.Error(w, "missing 'dst' query parameter", http.StatusBadRequest)
			return
		}
		dst, err := addr.ParseIA(dstStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid ISD-AS: %v", err), http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodPost:
			qd.Monitor.Register(dst)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "registered",
				"dst":    dst.String(),
			})
		case http.MethodDelete:
			qd.Monitor.Unregister(dst)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "unregistered",
				"dst":    dst.String(),
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return mux
}

// FormatQualityTable returns a human-readable table of path quality metrics
// for a destination. Used by CLI tools.
func FormatQualityTable(ranked []pathquality.RankedPath) string {
	if len(ranked) == 0 {
		return "No quality data available.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-4s %-50s %8s %8s %8s %8s %6s %6s\n",
		"#", "Path", "RTT", "MinRTT", "Jitter", "Loss", "Score", "Alive"))
	sb.WriteString(strings.Repeat("-", 100) + "\n")

	for i, rp := range ranked {
		meta := rp.Path.Metadata()
		pathStr := formatPathInterfaces(meta.Interfaces)
		alive := "no"
		if rp.Stats.IsAlive {
			alive = "yes"
		}
		sb.WriteString(fmt.Sprintf("%-4d %-50s %8s %8s %8s %5.1f%% %6.3f %6s\n",
			i,
			truncate(pathStr, 50),
			rp.Stats.RTT.Round(100*time.Microsecond),
			rp.Stats.MinRTT.Round(100*time.Microsecond),
			rp.Stats.Jitter.Round(100*time.Microsecond),
			rp.Stats.LossRate*100,
			rp.Stats.Score,
			alive,
		))
	}

	return sb.String()
}

func formatPathInterfaces(intfs []snet.PathInterface) string {
	if len(intfs) == 0 {
		return "<empty>"
	}
	var parts []string
	for i := 0; i < len(intfs); i += 2 {
		if i+1 < len(intfs) {
			parts = append(parts, fmt.Sprintf("%s#%d>%d",
				intfs[i].IA, intfs[i].ID, intfs[i+1].ID))
		} else {
			parts = append(parts, fmt.Sprintf("%s#%d", intfs[i].IA, intfs[i].ID))
		}
	}
	return strings.Join(parts, " ")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// AutoDiscover monitors paths to ASes that the daemon fetches paths for.
// It registers destinations automatically when paths are requested.
// This runs as a goroutine and logs activity.
func (qd *QualityDaemon) AutoDiscover(ctx context.Context, destinations []addr.IA) {
	logger := log.FromCtx(ctx)
	for _, dst := range destinations {
		qd.Monitor.Register(dst)
		logger.Info("Auto-registered quality monitoring", "dst", dst)
	}
}
