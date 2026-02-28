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

// Package pathquality_pb contains manually written proto stubs for the
// PathQuality RPC extension. These will be replaced by auto-generated code
// once protoc/buf is configured for the build.
//
// These types mirror the proto definitions in proto/daemon/v1/daemon.proto
// for the PathQuality messages.

package pathquality

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	sdpb "github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// PathQualityToPB converts a RankedPath to a proto PathQualityMetrics stub.
// Since we haven't regenerated protos yet, we return a map of quality data
// that can be serialized alongside the standard PathsResponse.
type PathQualityPB struct {
	Raw            []byte
	Interfaces     []*sdpb.PathInterface
	RTT            *durationpb.Duration
	MinRTT         *durationpb.Duration
	MaxRTT         *durationpb.Duration
	Jitter         *durationpb.Duration
	LossRate       float64
	ProbesSent     uint64
	ProbesReceived uint64
	IsAlive        bool
	Score          float64
	LastProbeTime  *timestamppb.Timestamp
	LastReplyTime  *timestamppb.Timestamp
}

// QualityToPB converts a RankedPath to a PathQualityPB.
func QualityToPB(rp RankedPath) *PathQualityPB {
	meta := rp.Path.Metadata()

	interfaces := make([]*sdpb.PathInterface, len(meta.Interfaces))
	for i, intf := range meta.Interfaces {
		interfaces[i] = &sdpb.PathInterface{
			Id:    uint64(intf.ID),
			IsdAs: uint64(intf.IA),
		}
	}

	var raw []byte
	if scionPath, ok := rp.Path.Dataplane().(snetpath.SCION); ok {
		raw = scionPath.Raw
	}

	pb := &PathQualityPB{
		Raw:            raw,
		Interfaces:     interfaces,
		RTT:            durationpb.New(rp.Stats.RTT),
		MinRTT:         durationpb.New(rp.Stats.MinRTT),
		MaxRTT:         durationpb.New(rp.Stats.MaxRTT),
		Jitter:         durationpb.New(rp.Stats.Jitter),
		LossRate:       rp.Stats.LossRate,
		ProbesSent:     uint64(rp.Stats.ProbesSent),
		ProbesReceived: uint64(rp.Stats.ProbesReceived),
		IsAlive:        rp.Stats.IsAlive,
		Score:          rp.Stats.Score,
	}

	if !rp.Stats.LastProbeTime.IsZero() {
		pb.LastProbeTime = timestamppb.New(rp.Stats.LastProbeTime)
	}
	if !rp.Stats.LastReplyTime.IsZero() {
		pb.LastReplyTime = timestamppb.New(rp.Stats.LastReplyTime)
	}

	return pb
}

// QualityResponseJSON is a JSON-serializable quality response for the REST/CLI
// interface until the proto is regenerated.
type QualityResponseJSON struct {
	Paths []PathQualityJSON `json:"paths"`
}

// PathQualityJSON is a single path's quality metrics in JSON format.
type PathQualityJSON struct {
	Fingerprint    string        `json:"fingerprint"`
	Interfaces     []IfaceJSON   `json:"interfaces"`
	Hops           int           `json:"hops"`
	RTT            time.Duration `json:"rtt_ns"`
	RTTHuman       string        `json:"rtt"`
	MinRTT         time.Duration `json:"min_rtt_ns"`
	MinRTTHuman    string        `json:"min_rtt"`
	MaxRTT         time.Duration `json:"max_rtt_ns"`
	MaxRTTHuman    string        `json:"max_rtt"`
	Jitter         time.Duration `json:"jitter_ns"`
	JitterHuman    string        `json:"jitter"`
	LossRate       float64       `json:"loss_rate"`
	LossPercent    string        `json:"loss_percent"`
	ProbesSent     uint64        `json:"probes_sent"`
	ProbesReceived uint64        `json:"probes_received"`
	IsAlive        bool          `json:"is_alive"`
	Score          float64       `json:"score"`
	LastProbeTime  time.Time     `json:"last_probe_time"`
	LastReplyTime  time.Time     `json:"last_reply_time"`
}

// IfaceJSON is a simplified interface representation.
type IfaceJSON struct {
	IA string `json:"ia"`
	ID uint64 `json:"id"`
}

// RankedPathToJSON converts a RankedPath to a JSON-serializable format.
func RankedPathToJSON(rp RankedPath) PathQualityJSON {
	meta := rp.Path.Metadata()
	ifaces := make([]IfaceJSON, len(meta.Interfaces))
	for i, intf := range meta.Interfaces {
		ifaces[i] = IfaceJSON{
			IA: intf.IA.String(),
			ID: uint64(intf.ID),
		}
	}

	fp := meta.Fingerprint()
	return PathQualityJSON{
		Fingerprint:    string(fp),
		Interfaces:     ifaces,
		Hops:           len(meta.Interfaces) / 2,
		RTT:            rp.Stats.RTT,
		RTTHuman:       rp.Stats.RTT.String(),
		MinRTT:         rp.Stats.MinRTT,
		MinRTTHuman:    rp.Stats.MinRTT.String(),
		MaxRTT:         rp.Stats.MaxRTT,
		MaxRTTHuman:    rp.Stats.MaxRTT.String(),
		Jitter:         rp.Stats.Jitter,
		JitterHuman:    rp.Stats.Jitter.String(),
		LossRate:       rp.Stats.LossRate,
		LossPercent:    formatLossPercent(rp.Stats.LossRate),
		ProbesSent:     rp.Stats.ProbesSent,
		ProbesReceived: rp.Stats.ProbesReceived,
		IsAlive:        rp.Stats.IsAlive,
		Score:          rp.Stats.Score,
		LastProbeTime:  rp.Stats.LastProbeTime,
		LastReplyTime:  rp.Stats.LastReplyTime,
	}
}

func formatLossPercent(rate float64) string {
	return fmt.Sprintf("%.1f%%", rate*100)
}

// QualityStatsToPathSelection determines the best path index from a set of
// paths returned by the daemon, using the quality monitor's data.
func QualityStatsToPathSelection(
	paths []snet.Path,
	monitor *Monitor,
	dst snet.SCIONAddress,
) (int, *QualityStats) {
	if monitor == nil || len(paths) == 0 {
		return 0, nil
	}

	stats := monitor.GetQualityStats(dst.IA)
	if len(stats) == 0 {
		return 0, nil
	}

	bestIdx := 0
	bestScore := -1.0
	var bestStats *QualityStats
	for i, p := range paths {
		fp := p.Metadata().Fingerprint()
		if qs, ok := stats[fp]; ok {
			if qs.Score > bestScore {
				bestIdx = i
				bestScore = qs.Score
				s := qs // copy
				bestStats = &s
			}
		}
	}

	return bestIdx, bestStats
}
