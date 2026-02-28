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

package pathquality

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	// defaultPathRefreshInterval is how often paths are refreshed from the daemon.
	defaultPathRefreshInterval = 10 * time.Second

	// defaultPathFetchTimeout is the timeout for fetching paths.
	defaultPathFetchTimeout = 10 * time.Second

	// graceInterval is how long to keep watching paths that are no longer advertised.
	graceInterval = time.Minute
)

// PathRouter provides paths to remote ASes.
type PathRouter interface {
	AllRoutes(ctx context.Context, dst addr.IA) ([]snet.Path, error)
}

// MonitorConfig configures the quality monitor.
type MonitorConfig struct {
	// LocalIA is the local AS identifier.
	LocalIA addr.IA
	// LocalIP is the local IP address for probe connections.
	LocalIP netip.Addr
	// Topology provides control-plane topology information.
	Topology snet.Topology
	// Router provides paths to remote ASes.
	Router PathRouter
	// ProbeInterval is how often probes are sent per path. Default: 500ms.
	ProbeInterval time.Duration
	// PathRefreshInterval is how often paths are refreshed. Default: 10s.
	PathRefreshInterval time.Duration
	// ReroutePolicy defines thresholds for automatic rerouting.
	ReroutePolicy ReroutePolicy
	// SCIONPacketConnMetrics are metrics for SCION packet connections.
	ConnMetrics snet.SCIONPacketConnMetrics
}

// Monitor manages quality watchers for all monitored remote ASes.
// It periodically fetches paths, creates/destroys watchers as paths appear/disappear,
// and provides quality-ranked path selections to callers.
type Monitor struct {
	cfg MonitorConfig

	mu       sync.RWMutex
	remotes  map[addr.IA]*remoteEntry
	selector *QualitySelector

	cancel context.CancelFunc
}

type remoteEntry struct {
	watchers  map[snet.PathFingerprint]*watcherEntry
	bestPath  snet.PathFingerprint
	lastFetch time.Time
}

type watcherEntry struct {
	watcher  *QualityWatcher
	cancel   context.CancelFunc
	pktChan  chan QualityProbeReply
	lastSeen time.Time
}

// NewMonitor creates a new quality monitor.
func NewMonitor(cfg MonitorConfig) *Monitor {
	if cfg.ProbeInterval == 0 {
		cfg.ProbeInterval = DefaultProbeInterval
	}
	if cfg.PathRefreshInterval == 0 {
		cfg.PathRefreshInterval = defaultPathRefreshInterval
	}
	if cfg.ReroutePolicy == (ReroutePolicy{}) {
		cfg.ReroutePolicy = DefaultReroutePolicy()
	}

	return &Monitor{
		cfg:      cfg,
		remotes:  make(map[addr.IA]*remoteEntry),
		selector: NewQualitySelector(cfg.ReroutePolicy),
	}
}

// Start begins monitoring. Call Stop() to terminate.
func (m *Monitor) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	go func() {
		defer log.HandlePanic()
		m.run(ctx)
	}()
}

// Stop terminates all monitoring.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

// Register adds a remote AS to be monitored for path quality.
// If already registered, this is a no-op.
func (m *Monitor) Register(remote addr.IA) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.remotes[remote]; exists {
		return
	}
	m.remotes[remote] = &remoteEntry{
		watchers: make(map[snet.PathFingerprint]*watcherEntry),
	}
}

// Unregister removes a remote AS from monitoring.
func (m *Monitor) Unregister(remote addr.IA) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.remotes[remote]
	if !exists {
		return
	}
	for _, we := range entry.watchers {
		we.cancel()
	}
	delete(m.remotes, remote)
}

// GetQualityStats returns quality stats for all monitored paths to a remote AS.
func (m *Monitor) GetQualityStats(remote addr.IA) map[snet.PathFingerprint]QualityStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.remotes[remote]
	if !exists {
		return nil
	}

	result := make(map[snet.PathFingerprint]QualityStats, len(entry.watchers))
	for fp, we := range entry.watchers {
		result[fp] = we.watcher.Stats()
	}
	return result
}

// GetBestPath returns the best quality path to a remote AS, or nil if none available.
func (m *Monitor) GetBestPath(remote addr.IA) snet.Path {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.remotes[remote]
	if !exists || len(entry.watchers) == 0 {
		return nil
	}

	paths := make([]PathWithQuality, 0, len(entry.watchers))
	for fp, we := range entry.watchers {
		stats := we.watcher.Stats()
		paths = append(paths, PathWithQuality{
			Fingerprint: string(fp),
			Stats:       stats,
			IsCurrent:   fp == entry.bestPath,
		})
	}

	bestIdx := m.selector.SelectBest(paths)
	if bestIdx < 0 {
		return nil
	}

	bestFP := snet.PathFingerprint(paths[bestIdx].Fingerprint)
	entry.bestPath = bestFP
	return entry.watchers[bestFP].watcher.Path()
}

// GetRankedPaths returns all paths to a remote AS, ranked by quality score.
func (m *Monitor) GetRankedPaths(remote addr.IA) []RankedPath {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.remotes[remote]
	if !exists {
		return nil
	}

	ranked := make([]RankedPath, 0, len(entry.watchers))
	for _, we := range entry.watchers {
		stats := we.watcher.Stats()
		ranked = append(ranked, RankedPath{
			Path:  we.watcher.Path(),
			Stats: stats,
		})
	}

	// Sort by score descending
	for i := 0; i < len(ranked); i++ {
		for j := i + 1; j < len(ranked); j++ {
			if ranked[j].Stats.Score > ranked[i].Stats.Score {
				ranked[i], ranked[j] = ranked[j], ranked[i]
			}
		}
	}

	return ranked
}

// RankedPath pairs a path with its quality stats.
type RankedPath struct {
	Path  snet.Path
	Stats QualityStats
}

// ListMonitored returns all currently monitored remote ASes.
func (m *Monitor) ListMonitored() []addr.IA {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]addr.IA, 0, len(m.remotes))
	for ia := range m.remotes {
		result = append(result, ia)
	}
	return result
}

func (m *Monitor) run(ctx context.Context) {
	logger := log.FromCtx(ctx)
	logger.Info("Starting path quality monitor",
		"local_ia", m.cfg.LocalIA,
		"probe_interval", m.cfg.ProbeInterval,
		"refresh_interval", m.cfg.PathRefreshInterval,
	)

	refreshTicker := time.NewTicker(m.cfg.PathRefreshInterval)
	defer refreshTicker.Stop()

	// Do an initial path refresh
	m.refreshAllPaths(ctx)

	for {
		select {
		case <-refreshTicker.C:
			m.refreshAllPaths(ctx)
		case <-ctx.Done():
			m.stopAllWatchers()
			logger.Info("Stopped path quality monitor")
			return
		}
	}
}

func (m *Monitor) refreshAllPaths(ctx context.Context) {
	m.mu.Lock()
	remotes := make([]addr.IA, 0, len(m.remotes))
	for ia := range m.remotes {
		remotes = append(remotes, ia)
	}
	m.mu.Unlock()

	for _, remote := range remotes {
		m.refreshPathsForRemote(ctx, remote)
	}
}

func (m *Monitor) refreshPathsForRemote(ctx context.Context, remote addr.IA) {
	fetchCtx, cancel := context.WithTimeout(ctx, defaultPathFetchTimeout)
	defer cancel()

	paths, err := m.cfg.Router.AllRoutes(fetchCtx, remote)
	if err != nil {
		log.FromCtx(ctx).Debug("Failed to fetch paths for quality monitoring",
			"remote", remote, "err", err,
		)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.remotes[remote]
	if !exists {
		return
	}
	entry.lastFetch = time.Now()

	// Track which fingerprints are still current
	seen := make(map[snet.PathFingerprint]bool, len(paths))

	for _, path := range paths {
		fp := path.Metadata().Fingerprint()
		seen[fp] = true

		if we, exists := entry.watchers[fp]; exists {
			// Update existing watcher with refreshed path data
			we.watcher.UpdatePath(path)
			we.lastSeen = time.Now()
			continue
		}

		// Create new watcher for this path
		pktChan := make(chan QualityProbeReply, 10)
		scmpHandler := &qualitySCMPHandler{
			wrappedHandler: snet.DefaultSCMPHandler{},
			pkts:           pktChan,
		}

		watcher, err := NewQualityWatcher(ctx, remote, path, pktChan, QualityWatcherConfig{
			LocalIA:       m.cfg.LocalIA,
			Topology:      m.cfg.Topology,
			LocalIP:       m.cfg.LocalIP,
			ProbeInterval: m.cfg.ProbeInterval,
			SCMPHandler:   scmpHandler,
			ConnMetrics:   m.cfg.ConnMetrics,
		})
		if err != nil {
			log.FromCtx(ctx).Debug("Failed to create quality watcher",
				"remote", remote,
				"path", fmt.Sprint(path),
				"err", err,
			)
			continue
		}

		watcherCtx, watcherCancel := context.WithCancel(ctx)
		entry.watchers[fp] = &watcherEntry{
			watcher:  watcher,
			cancel:   watcherCancel,
			pktChan:  pktChan,
			lastSeen: time.Now(),
		}

		go func() {
			defer log.HandlePanic()
			watcher.Run(watcherCtx)
		}()
	}

	// Clean up watchers for paths no longer seen (after grace period)
	now := time.Now()
	for fp, we := range entry.watchers {
		if !seen[fp] && now.Sub(we.lastSeen) > graceInterval {
			we.cancel()
			delete(entry.watchers, fp)
		}
	}
}

func (m *Monitor) stopAllWatchers() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range m.remotes {
		for _, we := range entry.watchers {
			we.cancel()
		}
	}
}

// qualitySCMPHandler intercepts SCMP traceroute replies and forwards them
// to the quality watcher's channel with timing information. Non-traceroute
// SCMP messages (e.g., revocations) are delegated to the wrapped handler.
type qualitySCMPHandler struct {
	wrappedHandler snet.SCMPHandler
	pkts           chan<- QualityProbeReply
}

func (h *qualitySCMPHandler) Handle(pkt *snet.Packet) error {
	if pkt.Payload == nil {
		return fmt.Errorf("no payload found")
	}
	tr, ok := pkt.Payload.(snet.SCMPTracerouteReply)
	if !ok {
		// Not a traceroute reply — delegate to wrapped handler
		// (handles revocations, interface-down, etc.)
		return h.wrappedHandler.Handle(pkt)
	}
	select {
	case h.pkts <- QualityProbeReply{
		Sequence: tr.Sequence,
		RecvTime: time.Now(),
	}:
	default:
		// Channel full, drop to avoid blocking
	}
	return nil
}

// Ensure qualitySCMPHandler implements snet.SCMPHandler at compile time.
var _ snet.SCMPHandler = (*qualitySCMPHandler)(nil)

// ResolveLocalIP returns a local IP that can reach the SCION network.
func ResolveLocalIP() (netip.Addr, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(8, 8, 8, 8),
		Port: 53,
	})
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	addr, ok := netip.AddrFromSlice(localAddr.IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("failed to parse local IP")
	}
	return addr, nil
}
