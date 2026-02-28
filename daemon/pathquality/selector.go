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
	"time"
)

// ReroutePolicy defines the thresholds that trigger automatic path rerouting.
// When any metric exceeds its threshold, the monitor will prefer alternative
// paths with better quality scores.
type ReroutePolicy struct {
	// MaxRTT is the maximum acceptable smoothed RTT before considering reroute.
	// Default: 200ms.
	MaxRTT time.Duration
	// MaxLossRate is the maximum acceptable packet loss rate [0.0, 1.0].
	// Default: 0.05 (5%).
	MaxLossRate float64
	// MaxJitter is the maximum acceptable jitter before considering reroute.
	// Default: 30ms.
	MaxJitter time.Duration
	// MinScore is the minimum composite quality score [0.0, 1.0].
	// If a path's score drops below this, rerouting is triggered.
	// Default: 0.5.
	MinScore float64
	// HysteresisMargin is the minimum score improvement required to switch paths.
	// Prevents oscillation between paths with similar quality.
	// Default: 0.15 (15%).
	HysteresisMargin float64
	// StabilityWindow is how long a path must maintain better quality before
	// switching to it. Prevents reacting to transient quality changes.
	// Default: 5s.
	StabilityWindow time.Duration
}

// DefaultReroutePolicy returns sensible default thresholds.
func DefaultReroutePolicy() ReroutePolicy {
	return ReroutePolicy{
		MaxRTT:           200 * time.Millisecond,
		MaxLossRate:      0.05,
		MaxJitter:        30 * time.Millisecond,
		MinScore:         0.5,
		HysteresisMargin: 0.15,
		StabilityWindow:  5 * time.Second,
	}
}

// QualitySelector selects the best path based on measured quality metrics.
// It implements quality-aware path selection with hysteresis to prevent
// oscillation between paths with similar quality.
type QualitySelector struct {
	policy ReroutePolicy
}

// NewQualitySelector creates a selector with the given reroute policy.
func NewQualitySelector(policy ReroutePolicy) *QualitySelector {
	return &QualitySelector{policy: policy}
}

// PathWithQuality pairs a path fingerprint with its quality stats for selection.
type PathWithQuality struct {
	Fingerprint string
	Stats       QualityStats
	IsCurrent   bool
}

// ShouldReroute returns true if the current path's quality has degraded enough
// to warrant switching, and the candidate path is sufficiently better.
func (s *QualitySelector) ShouldReroute(current, candidate QualityStats) bool {
	// Never reroute if current path is fine
	if !s.isDegraded(current) {
		return false
	}

	// Only reroute if candidate is sufficiently better (hysteresis)
	scoreDiff := candidate.Score - current.Score
	return scoreDiff >= s.policy.HysteresisMargin && candidate.Score >= s.policy.MinScore
}

// isDegraded returns true if any quality metric exceeds its threshold.
func (s *QualitySelector) isDegraded(stats QualityStats) bool {
	if !stats.IsAlive {
		return true
	}
	if stats.RTT > s.policy.MaxRTT {
		return true
	}
	if stats.LossRate > s.policy.MaxLossRate {
		return true
	}
	if stats.Jitter > s.policy.MaxJitter {
		return true
	}
	if stats.Score < s.policy.MinScore {
		return true
	}
	return false
}

// SelectBest selects the best path from a set of paths with quality data.
// It prefers the current path unless a significantly better alternative exists
// (hysteresis prevents oscillation).
func (s *QualitySelector) SelectBest(paths []PathWithQuality) int {
	if len(paths) == 0 {
		return -1
	}

	currentIdx := -1
	bestIdx := 0
	bestScore := -1.0

	for i, p := range paths {
		if p.IsCurrent {
			currentIdx = i
		}
		if p.Stats.IsAlive && p.Stats.Score > bestScore {
			bestScore = p.Stats.Score
			bestIdx = i
		}
	}

	// If no current path or current is dead, pick best alive
	if currentIdx == -1 || !paths[currentIdx].Stats.IsAlive {
		return bestIdx
	}

	// If current is fine, stick with it (stability)
	currentStats := paths[currentIdx].Stats
	if !s.isDegraded(currentStats) {
		return currentIdx
	}

	// Current is degraded - only switch if candidate is significantly better
	if bestIdx != currentIdx && s.ShouldReroute(currentStats, paths[bestIdx].Stats) {
		return bestIdx
	}

	// Stay on current even though it's degraded (no sufficiently better alternative)
	return currentIdx
}

// Better implements the gateway/pathhealth/policies.PerfPolicy interface.
// Returns true if stats x represents a better path than stats y.
func (s *QualitySelector) Better(x, y *QualityStats) bool {
	// Dead paths are always worse
	if !x.IsAlive && y.IsAlive {
		return false
	}
	if x.IsAlive && !y.IsAlive {
		return true
	}
	if !x.IsAlive && !y.IsAlive {
		return false
	}
	return x.Score > y.Score
}

// DegradationReport describes why a path is considered degraded.
type DegradationReport struct {
	IsDegraded     bool
	RTTExceeded    bool
	LossExceeded   bool
	JitterExceeded bool
	ScoreBelowMin  bool
}

// Diagnose returns a detailed report of why a path might be degraded.
func (s *QualitySelector) Diagnose(stats QualityStats) DegradationReport {
	report := DegradationReport{}
	if !stats.IsAlive {
		report.IsDegraded = true
		return report
	}
	if stats.RTT > s.policy.MaxRTT {
		report.IsDegraded = true
		report.RTTExceeded = true
	}
	if stats.LossRate > s.policy.MaxLossRate {
		report.IsDegraded = true
		report.LossExceeded = true
	}
	if stats.Jitter > s.policy.MaxJitter {
		report.IsDegraded = true
		report.JitterExceeded = true
	}
	if stats.Score < s.policy.MinScore {
		report.IsDegraded = true
		report.ScoreBelowMin = true
	}
	return report
}
