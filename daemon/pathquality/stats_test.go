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
	"math"
	"testing"
	"time"
)

func TestNewQualityTracker(t *testing.T) {
	tracker := NewQualityTracker()
	stats := tracker.Stats()

	if stats.RTT != 0 {
		t.Errorf("expected RTT 0, got %v", stats.RTT)
	}
	if stats.LossRate != 0 {
		t.Errorf("expected LossRate 0, got %v", stats.LossRate)
	}
	if stats.IsAlive {
		t.Error("expected not alive initially")
	}
	if stats.Score != 1.0 {
		t.Errorf("expected score 1.0 initially (no data = benefit of doubt), got %v", stats.Score)
	}
}

func TestRecordProbeRTT(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	// Send a probe
	tracker.RecordProbeSent(1, now)
	// Receive reply 10ms later
	rtt, ok := tracker.RecordProbeReply(1, now.Add(10*time.Millisecond))
	if !ok {
		t.Fatal("expected successful reply recording")
	}
	if rtt != 10*time.Millisecond {
		t.Errorf("expected RTT 10ms, got %v", rtt)
	}

	stats := tracker.Stats()
	if stats.RTT != 10*time.Millisecond {
		t.Errorf("expected EWMA RTT 10ms (first sample), got %v", stats.RTT)
	}
	if stats.MinRTT != 10*time.Millisecond {
		t.Errorf("expected MinRTT 10ms, got %v", stats.MinRTT)
	}
	if stats.MaxRTT != 10*time.Millisecond {
		t.Errorf("expected MaxRTT 10ms, got %v", stats.MaxRTT)
	}
}

func TestEWMASmoothing(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	// Send 10 probes with consistent RTT
	for i := 0; i < 10; i++ {
		seq := uint16(i)
		sendTime := now.Add(time.Duration(i) * 500 * time.Millisecond)
		tracker.RecordProbeSent(seq, sendTime)
		tracker.RecordProbeReply(seq, sendTime.Add(20*time.Millisecond))
	}

	stats := tracker.Stats()
	// After 10 consistent samples, EWMA should converge close to 20ms
	if math.Abs(float64(stats.RTT-20*time.Millisecond)) > float64(2*time.Millisecond) {
		t.Errorf("expected RTT ~20ms after convergence, got %v", stats.RTT)
	}
}

func TestJitterComputation(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	// Send probes with varying RTTs to produce jitter
	rtts := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		15 * time.Millisecond,
		25 * time.Millisecond,
		12 * time.Millisecond,
	}

	for i, rtt := range rtts {
		seq := uint16(i)
		sendTime := now.Add(time.Duration(i) * 500 * time.Millisecond)
		tracker.RecordProbeSent(seq, sendTime)
		tracker.RecordProbeReply(seq, sendTime.Add(rtt))
	}

	stats := tracker.Stats()
	if stats.Jitter == 0 {
		t.Error("expected non-zero jitter with varying RTTs")
	}
}

func TestLossTracking(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	// Send 10 probes, reply to only 7
	for i := 0; i < 10; i++ {
		seq := uint16(i)
		sendTime := now.Add(time.Duration(i) * 500 * time.Millisecond)
		tracker.RecordProbeSent(seq, sendTime)
		if i < 7 {
			tracker.RecordProbeReply(seq, sendTime.Add(10*time.Millisecond))
		} else {
			tracker.RecordProbeTimeout(seq)
		}
	}

	stats := tracker.Stats()
	expectedLoss := 0.3
	if math.Abs(stats.LossRate-expectedLoss) > 0.05 {
		t.Errorf("expected loss rate ~%.1f, got %v", expectedLoss, stats.LossRate)
	}
}

func TestAliveStatus(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	// Initially not alive
	if tracker.Stats().IsAlive {
		t.Error("expected not alive initially")
	}

	// After 3 successful probes, should be alive
	for i := 0; i < 3; i++ {
		seq := uint16(i)
		sendTime := now.Add(time.Duration(i) * 500 * time.Millisecond)
		tracker.RecordProbeSent(seq, sendTime)
		tracker.RecordProbeReply(seq, sendTime.Add(10*time.Millisecond))
	}

	if !tracker.Stats().IsAlive {
		t.Error("expected alive after 3 successful probes")
	}

	// After consecutive failures, should become not alive
	for i := 3; i < 6; i++ {
		seq := uint16(i)
		sendTime := now.Add(time.Duration(i) * 500 * time.Millisecond)
		tracker.RecordProbeSent(seq, sendTime)
		tracker.RecordProbeTimeout(seq)
	}

	if tracker.Stats().IsAlive {
		t.Error("expected not alive after 3 consecutive failures")
	}
}

func TestDuplicateReply(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	tracker.RecordProbeSent(1, now)
	_, ok1 := tracker.RecordProbeReply(1, now.Add(10*time.Millisecond))
	_, ok2 := tracker.RecordProbeReply(1, now.Add(15*time.Millisecond))

	if !ok1 {
		t.Error("expected first reply to succeed")
	}
	if ok2 {
		t.Error("expected duplicate reply to fail")
	}
}

func TestUnknownSequenceReply(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	// Reply without a matching sent probe
	_, ok := tracker.RecordProbeReply(999, now)
	if ok {
		t.Error("expected unknown sequence reply to fail")
	}
}

func TestCompositeScore(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	// Perfect conditions: low RTT, no loss
	for i := 0; i < 20; i++ {
		seq := uint16(i)
		sendTime := now.Add(time.Duration(i) * 500 * time.Millisecond)
		tracker.RecordProbeSent(seq, sendTime)
		tracker.RecordProbeReply(seq, sendTime.Add(5*time.Millisecond))
	}

	stats := tracker.Stats()
	if stats.Score < 0.9 {
		t.Errorf("expected high score (>0.9) for good conditions, got %v", stats.Score)
	}
}

func TestHighLossLowScore(t *testing.T) {
	tracker := NewQualityTracker()
	now := time.Now()

	// 50% loss
	for i := 0; i < 20; i++ {
		seq := uint16(i)
		sendTime := now.Add(time.Duration(i) * 500 * time.Millisecond)
		tracker.RecordProbeSent(seq, sendTime)
		if i%2 == 0 {
			tracker.RecordProbeReply(seq, sendTime.Add(5*time.Millisecond))
		} else {
			tracker.RecordProbeTimeout(seq)
		}
	}

	stats := tracker.Stats()
	if stats.Score > 0.7 {
		t.Errorf("expected low score (<0.7) for 50%% loss, got %v", stats.Score)
	}
}

func TestCleanupStaleProbes(t *testing.T) {
	tracker := NewQualityTracker()
	past := time.Now().Add(-10 * time.Second)

	// Send probes in the past that never got replies
	for i := 0; i < 5; i++ {
		tracker.RecordProbeSent(uint16(i), past.Add(time.Duration(i)*100*time.Millisecond))
	}

	tracker.CleanupStaleProbes(5 * time.Second)

	// Try to reply — should fail since they were cleaned up
	_, ok := tracker.RecordProbeReply(0, time.Now())
	if ok {
		t.Error("expected cleaned up probe to not accept reply")
	}
}
