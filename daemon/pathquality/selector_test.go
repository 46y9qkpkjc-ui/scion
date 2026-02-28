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
	"testing"
	"time"
)

func TestDefaultReroutePolicy(t *testing.T) {
	p := DefaultReroutePolicy()
	if p.MaxRTT != 200*time.Millisecond {
		t.Errorf("expected MaxRTT 200ms, got %v", p.MaxRTT)
	}
	if p.MaxLossRate != 0.05 {
		t.Errorf("expected MaxLossRate 0.05, got %v", p.MaxLossRate)
	}
	if p.MaxJitter != 30*time.Millisecond {
		t.Errorf("expected MaxJitter 30ms, got %v", p.MaxJitter)
	}
	if p.MinScore != 0.5 {
		t.Errorf("expected MinScore 0.5, got %v", p.MinScore)
	}
}

func TestShouldReroute_DegradedCurrent(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	current := QualityStats{
		RTT:      300 * time.Millisecond, // Exceeds MaxRTT
		LossRate: 0.10,                   // Exceeds MaxLossRate
		IsAlive:  true,
		Score:    0.3,
	}
	candidate := QualityStats{
		RTT:      20 * time.Millisecond,
		LossRate: 0.0,
		IsAlive:  true,
		Score:    0.95,
	}

	if !selector.ShouldReroute(current, candidate) {
		t.Error("expected reroute recommendation when current is degraded and candidate is better")
	}
}

func TestShouldReroute_CurrentFine(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	current := QualityStats{
		RTT:      20 * time.Millisecond,
		LossRate: 0.0,
		IsAlive:  true,
		Score:    0.95,
	}
	candidate := QualityStats{
		RTT:      15 * time.Millisecond,
		LossRate: 0.0,
		IsAlive:  true,
		Score:    0.97,
	}

	if selector.ShouldReroute(current, candidate) {
		t.Error("should not reroute when current path is performing well")
	}
}

func TestShouldReroute_Hysteresis(t *testing.T) {
	policy := DefaultReroutePolicy()
	policy.HysteresisMargin = 0.15
	selector := NewQualitySelector(policy)

	// Current is just barely degraded
	current := QualityStats{
		RTT:      250 * time.Millisecond,
		LossRate: 0.06,
		IsAlive:  true,
		Score:    0.45,
	}
	// Candidate is only slightly better (within hysteresis margin)
	candidate := QualityStats{
		RTT:      200 * time.Millisecond,
		LossRate: 0.04,
		IsAlive:  true,
		Score:    0.55, // 0.55 - 0.45 = 0.10 < 0.15 hysteresis
	}

	if selector.ShouldReroute(current, candidate) {
		t.Error("should not reroute when candidate is within hysteresis margin")
	}

	// Candidate significantly better
	candidate.Score = 0.85 // 0.85 - 0.45 = 0.40 > 0.15 hysteresis
	if !selector.ShouldReroute(current, candidate) {
		t.Error("should reroute when candidate exceeds hysteresis margin")
	}
}

func TestSelectBest_StayOnCurrent(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	paths := []PathWithQuality{
		{
			Fingerprint: "path-a",
			Stats: QualityStats{
				RTT: 20 * time.Millisecond, LossRate: 0.0,
				IsAlive: true, Score: 0.95,
			},
			IsCurrent: true,
		},
		{
			Fingerprint: "path-b",
			Stats: QualityStats{
				RTT: 15 * time.Millisecond, LossRate: 0.0,
				IsAlive: true, Score: 0.97,
			},
			IsCurrent: false,
		},
	}

	// Should stay on current (path-a) since it's not degraded,
	// even though path-b has slightly better score
	idx := selector.SelectBest(paths)
	if idx != 0 {
		t.Errorf("expected to stay on current path (idx 0), got %d", idx)
	}
}

func TestSelectBest_SwitchWhenDegraded(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	paths := []PathWithQuality{
		{
			Fingerprint: "path-a",
			Stats: QualityStats{
				RTT: 300 * time.Millisecond, LossRate: 0.1,
				IsAlive: true, Score: 0.3,
			},
			IsCurrent: true,
		},
		{
			Fingerprint: "path-b",
			Stats: QualityStats{
				RTT: 15 * time.Millisecond, LossRate: 0.0,
				IsAlive: true, Score: 0.97,
			},
			IsCurrent: false,
		},
	}

	idx := selector.SelectBest(paths)
	if idx != 1 {
		t.Errorf("expected to switch to better path (idx 1), got %d", idx)
	}
}

func TestSelectBest_PreferAlive(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	paths := []PathWithQuality{
		{
			Fingerprint: "dead-path",
			Stats:       QualityStats{IsAlive: false, Score: 0.0},
			IsCurrent:   true,
		},
		{
			Fingerprint: "alive-path",
			Stats: QualityStats{
				RTT: 50 * time.Millisecond, LossRate: 0.02,
				IsAlive: true, Score: 0.8,
			},
			IsCurrent: false,
		},
	}

	idx := selector.SelectBest(paths)
	if idx != 1 {
		t.Errorf("expected alive path (idx 1), got %d", idx)
	}
}

func TestSelectBest_AllDead(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	paths := []PathWithQuality{
		{Fingerprint: "dead-1", Stats: QualityStats{IsAlive: false, Score: 0.0}},
		{Fingerprint: "dead-2", Stats: QualityStats{IsAlive: false, Score: 0.0}},
	}

	idx := selector.SelectBest(paths)
	if idx < 0 {
		t.Errorf("expected valid index even when all dead, got %d", idx)
	}
}

func TestSelectBest_Empty(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	idx := selector.SelectBest(nil)
	if idx != -1 {
		t.Errorf("expected -1 for empty paths, got %d", idx)
	}
}

func TestDiagnose(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	stats := QualityStats{
		RTT:      300 * time.Millisecond,
		LossRate: 0.1,
		Jitter:   50 * time.Millisecond,
		Score:    0.3,
	}

	report := selector.Diagnose(stats)
	if !report.IsDegraded {
		t.Error("expected degraded report")
	}
	if !report.RTTExceeded {
		t.Error("expected RTT exceeded")
	}
	if !report.LossExceeded {
		t.Error("expected loss exceeded")
	}
	if !report.JitterExceeded {
		t.Error("expected jitter exceeded")
	}
	if !report.ScoreBelowMin {
		t.Error("expected score below min")
	}
}

func TestDiagnose_Healthy(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	stats := QualityStats{
		RTT:      20 * time.Millisecond,
		LossRate: 0.0,
		Jitter:   2 * time.Millisecond,
		Score:    0.95,
	}

	report := selector.Diagnose(stats)
	if report.IsDegraded {
		t.Error("expected healthy report")
	}
}

func TestBetter(t *testing.T) {
	selector := NewQualitySelector(DefaultReroutePolicy())

	alive := &QualityStats{IsAlive: true, Score: 0.5}
	dead := &QualityStats{IsAlive: false, Score: 0.0}
	better := &QualityStats{IsAlive: true, Score: 0.9}

	if !selector.Better(alive, dead) {
		t.Error("alive should be better than dead")
	}
	if selector.Better(dead, alive) {
		t.Error("dead should not be better than alive")
	}
	if !selector.Better(better, alive) {
		t.Error("higher score should be better")
	}
}
