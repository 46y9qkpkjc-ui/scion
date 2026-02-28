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

// Package pathquality provides quality-aware path monitoring for the SCION daemon.
// It extends the existing binary alive/dead path probing with continuous measurement
// of latency (RTT), packet loss, jitter, and estimated bandwidth. This enables
// automatic rerouting when path quality degrades, not just when paths fail completely.
package pathquality

import (
	"math"
	"sync"
	"time"
)

const (
	// maxSamples is the number of RTT samples kept in the sliding window.
	maxSamples = 60

	// ewmaAlpha is the exponential weighted moving average smoothing factor.
	// Higher values give more weight to recent samples.
	ewmaAlpha = 0.3

	// defaultProbeInterval is how often quality probes are sent.
	DefaultProbeInterval = 500 * time.Millisecond
)

// QualityStats contains measured real-time quality metrics for a path.
// Unlike PathMetadata.Latency (static beacon-announced values), these are
// actively measured via SCMP probes.
type QualityStats struct {
	// RTT is the smoothed round-trip time (EWMA).
	RTT time.Duration
	// MinRTT is the minimum RTT observed in the current window.
	MinRTT time.Duration
	// MaxRTT is the maximum RTT observed in the current window.
	MaxRTT time.Duration
	// Jitter is the smoothed jitter (variation between consecutive RTT samples).
	Jitter time.Duration
	// LossRate is the fraction of probes that timed out, in range [0.0, 1.0].
	LossRate float64
	// ProbesSent is the total number of probes sent.
	ProbesSent uint64
	// ProbesReceived is the total number of probe replies received.
	ProbesReceived uint64
	// IsAlive indicates the path is currently responding to probes.
	IsAlive bool
	// LastProbeTime is the timestamp of the last probe sent.
	LastProbeTime time.Time
	// LastReplyTime is the timestamp of the last reply received.
	LastReplyTime time.Time
	// Score is a composite quality score (0.0 = worst, 1.0 = best).
	Score float64
}

// QualityTracker maintains a sliding window of quality measurements for a single path.
// It computes EWMA-smoothed RTT, jitter, and loss rate from SCMP probe round-trips.
type QualityTracker struct {
	mu sync.Mutex

	// Sliding window of RTT samples
	samples    [maxSamples]rttSample
	sampleHead int
	sampleLen  int

	// EWMA smoothed values
	smoothedRTT    float64 // nanoseconds
	smoothedJitter float64 // nanoseconds
	lastRTT        float64 // nanoseconds, for jitter computation

	// Counters
	probesSent     uint64
	probesReceived uint64
	probesLost     uint64

	// Loss tracking (sliding window of recent probe outcomes)
	recentOutcomes [maxSamples]bool // true = received, false = lost
	outcomeHead    int
	outcomeLen     int
	recentReceived int
	recentTotal    int

	// Alive tracking (consecutive successful probes)
	consecutiveSuccess int
	consecutiveFailure int
	isAlive            bool

	// Timestamps
	lastProbeTime time.Time
	lastReplyTime time.Time

	// Pending probes: map of sequence number -> send time
	pendingProbes map[uint16]time.Time
}

type rttSample struct {
	rtt  time.Duration
	time time.Time
}

// NewQualityTracker creates a new tracker for measuring path quality.
func NewQualityTracker() *QualityTracker {
	return &QualityTracker{
		pendingProbes: make(map[uint16]time.Time),
	}
}

// RecordProbeSent records that a probe was sent with the given sequence number.
func (t *QualityTracker) RecordProbeSent(seq uint16, sendTime time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.probesSent++
	t.lastProbeTime = sendTime
	t.pendingProbes[seq] = sendTime
}

// RecordProbeReply records that a reply was received for the given sequence number.
// Returns the measured RTT if the corresponding send time was found.
func (t *QualityTracker) RecordProbeReply(seq uint16, recvTime time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	sendTime, ok := t.pendingProbes[seq]
	if !ok {
		return 0, false
	}
	delete(t.pendingProbes, seq)

	rtt := recvTime.Sub(sendTime)
	t.probesReceived++
	t.lastReplyTime = recvTime

	// Add RTT sample to sliding window
	t.samples[t.sampleHead] = rttSample{rtt: rtt, time: recvTime}
	t.sampleHead = (t.sampleHead + 1) % maxSamples
	if t.sampleLen < maxSamples {
		t.sampleLen++
	}

	// Update EWMA RTT
	rttNs := float64(rtt.Nanoseconds())
	if t.smoothedRTT == 0 {
		t.smoothedRTT = rttNs
	} else {
		t.smoothedRTT = ewmaAlpha*rttNs + (1-ewmaAlpha)*t.smoothedRTT
	}

	// Update EWMA jitter (RFC 3550 style: jitter = avg |RTT_i - RTT_{i-1}|)
	if t.lastRTT > 0 {
		diff := math.Abs(rttNs - t.lastRTT)
		if t.smoothedJitter == 0 {
			t.smoothedJitter = diff
		} else {
			t.smoothedJitter = ewmaAlpha*diff + (1-ewmaAlpha)*t.smoothedJitter
		}
	}
	t.lastRTT = rttNs

	// Record outcome: received
	t.recordOutcome(true)

	// Update alive status
	t.consecutiveSuccess++
	t.consecutiveFailure = 0
	if t.consecutiveSuccess >= 2 {
		t.isAlive = true
	}

	return rtt, true
}

// RecordProbeTimeout records that a probe timed out (no reply within deadline).
func (t *QualityTracker) RecordProbeTimeout(seq uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.pendingProbes[seq]; ok {
		delete(t.pendingProbes, seq)
		t.probesLost++
	}

	// Record outcome: lost
	t.recordOutcome(false)

	// Update alive status
	t.consecutiveFailure++
	t.consecutiveSuccess = 0
	if t.consecutiveFailure >= 3 {
		t.isAlive = false
	}
}

// CleanupStaleProbes removes pending probes older than the given timeout.
// This prevents memory leaks from probes that never received a response.
func (t *QualityTracker) CleanupStaleProbes(timeout time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for seq, sendTime := range t.pendingProbes {
		if now.Sub(sendTime) > timeout {
			delete(t.pendingProbes, seq)
			t.probesLost++
			t.recordOutcome(false)
		}
	}
}

// recordOutcome adds a probe outcome to the sliding window (caller must hold lock).
func (t *QualityTracker) recordOutcome(received bool) {
	if t.outcomeLen == maxSamples {
		// Evict oldest entry
		if t.recentOutcomes[(t.outcomeHead-t.outcomeLen+maxSamples)%maxSamples] {
			t.recentReceived--
		}
		t.recentTotal--
	} else {
		t.outcomeLen++
	}

	t.recentOutcomes[t.outcomeHead] = received
	t.outcomeHead = (t.outcomeHead + 1) % maxSamples
	t.recentTotal++
	if received {
		t.recentReceived++
	}
}

// Stats returns the current quality statistics snapshot.
func (t *QualityTracker) Stats() QualityStats {
	t.mu.Lock()
	defer t.mu.Unlock()

	stats := QualityStats{
		RTT:            time.Duration(t.smoothedRTT),
		Jitter:         time.Duration(t.smoothedJitter),
		ProbesSent:     t.probesSent,
		ProbesReceived: t.probesReceived,
		IsAlive:        t.isAlive,
		LastProbeTime:  t.lastProbeTime,
		LastReplyTime:  t.lastReplyTime,
	}

	// Compute loss rate from recent window
	if t.recentTotal > 0 {
		stats.LossRate = 1.0 - float64(t.recentReceived)/float64(t.recentTotal)
	}

	// Compute min/max RTT from window
	if t.sampleLen > 0 {
		stats.MinRTT = time.Duration(math.MaxInt64)
		for i := 0; i < t.sampleLen; i++ {
			idx := (t.sampleHead - t.sampleLen + i + maxSamples) % maxSamples
			s := t.samples[idx]
			if s.rtt < stats.MinRTT {
				stats.MinRTT = s.rtt
			}
			if s.rtt > stats.MaxRTT {
				stats.MaxRTT = s.rtt
			}
		}
	}

	// Compute composite quality score
	stats.Score = computeScore(stats)

	return stats
}

// computeScore computes a composite quality score from 0.0 (worst) to 1.0 (best).
// The score weights: latency (40%), loss (35%), jitter (25%).
func computeScore(s QualityStats) float64 {
	if !s.IsAlive {
		return 0.0
	}

	// Latency score: 1.0 for <=10ms, 0.0 for >=500ms, linear in between
	latencyMs := float64(s.RTT.Milliseconds())
	latencyScore := 1.0 - clamp((latencyMs-10)/(500-10), 0, 1)

	// Loss score: 1.0 for 0% loss, 0.0 for >=10% loss
	lossScore := 1.0 - clamp(s.LossRate/0.10, 0, 1)

	// Jitter score: 1.0 for <=1ms, 0.0 for >=50ms
	jitterMs := float64(s.Jitter.Milliseconds())
	jitterScore := 1.0 - clamp((jitterMs-1)/(50-1), 0, 1)

	return 0.40*latencyScore + 0.35*lossScore + 0.25*jitterScore
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
