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
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// QualityWatcher monitors a specific SCION path and continuously measures its
// quality metrics (RTT, loss, jitter) using SCMP Traceroute probes.
// It extends the existing gateway/pathhealth/pathWatcher concept by actually
// measuring round-trip times rather than just tracking alive/dead status.
type QualityWatcher struct {
	// remote is the ID of the AS being monitored.
	remote addr.IA
	// probeInterval defines the interval at which probes are sent.
	probeInterval time.Duration
	// conn is the SCION packet connection for sending/receiving probes.
	conn snet.PacketConn
	// id is the SCMP traceroute identifier (derived from local port).
	id uint16
	// localAddr is the local SCION address.
	localAddr snet.SCIONAddress
	// pktChan receives incoming SCMP traceroute reply packets.
	pktChan <-chan QualityProbeReply

	// nextSeq is the sequence number to use for the next probe.
	nextSeq uint16
	// tracker computes quality stats from probe round-trips.
	tracker *QualityTracker

	pathMtx sync.RWMutex
	path    qualityPathWrap
	// packet is reused for sending probes to reduce allocations.
	packet *snet.Packet
}

// QualityProbeReply is sent on the channel when a probe reply is received.
type QualityProbeReply struct {
	Sequence uint16
	RecvTime time.Time
}

// QualityWatcherConfig configures the creation of a QualityWatcher.
type QualityWatcherConfig struct {
	LocalIA       addr.IA
	Topology      snet.Topology
	LocalIP       netip.Addr
	ProbeInterval time.Duration
	SCMPHandler   snet.SCMPHandler
	ConnMetrics   snet.SCIONPacketConnMetrics
}

// NewQualityWatcher creates a quality watcher for a specific path.
func NewQualityWatcher(
	ctx context.Context,
	remote addr.IA,
	path snet.Path,
	pktChan <-chan QualityProbeReply,
	cfg QualityWatcherConfig,
) (*QualityWatcher, error) {
	conn, err := (&snet.SCIONNetwork{
		SCMPHandler:       cfg.SCMPHandler,
		PacketConnMetrics: cfg.ConnMetrics,
		Topology:          cfg.Topology,
	}).OpenRaw(ctx, &net.UDPAddr{IP: cfg.LocalIP.AsSlice()})
	if err != nil {
		return nil, serrors.Wrap("creating quality probe connection", err)
	}

	interval := cfg.ProbeInterval
	if interval == 0 {
		interval = DefaultProbeInterval
	}

	return &QualityWatcher{
		remote:        remote,
		probeInterval: interval,
		conn:          conn,
		id:            uint16(conn.LocalAddr().(*net.UDPAddr).Port),
		localAddr: snet.SCIONAddress{
			IA:   cfg.LocalIA,
			Host: addr.HostIP(cfg.LocalIP),
		},
		pktChan: pktChan,
		tracker: NewQualityTracker(),
		path:    createQualityPathWrap(path),
		packet:  &snet.Packet{},
	}, nil
}

// Run runs the quality watcher until the context is cancelled.
// It sends periodic probes and processes replies, computing quality metrics.
func (w *QualityWatcher) Run(ctx context.Context) {
	ctx, logger := log.WithLabels(ctx,
		"debug_id", log.NewDebugID().String(),
		"qw_id", w.id,
	)
	var wg sync.WaitGroup
	wg.Go(func() {
		defer log.HandlePanic()
		w.drainConn(ctx)
	})

	logger.Info("Starting quality watcher",
		"remote", w.remote,
		"path", fmt.Sprint(w.path.Path),
	)
	defer logger.Info("Stopped quality watcher")

	probeTicker := time.NewTicker(w.probeInterval)
	defer probeTicker.Stop()

	// Cleanup stale pending probes every 10 probe intervals
	cleanupTicker := time.NewTicker(w.probeInterval * 10)
	defer cleanupTicker.Stop()

	for {
		select {
		case reply := <-w.pktChan:
			if rtt, ok := w.tracker.RecordProbeReply(reply.Sequence, reply.RecvTime); ok {
				logger.Debug("Probe reply received",
					"remote", w.remote,
					"seq", reply.Sequence,
					"rtt", rtt,
				)
			}
		case <-probeTicker.C:
			w.sendProbe(ctx)
		case <-cleanupTicker.C:
			w.tracker.CleanupStaleProbes(w.probeInterval * 5)
		case <-ctx.Done():
			w.conn.Close()
			wg.Wait()
			return
		}
	}
}

// UpdatePath updates the monitored path (same fingerprint, refreshed fields).
func (w *QualityWatcher) UpdatePath(path snet.Path) {
	w.pathMtx.Lock()
	defer w.pathMtx.Unlock()

	if fp := path.Metadata().Fingerprint(); w.path.fingerprint != fp {
		log.Error("QualityWatcher.UpdatePath with new fingerprint is invalid (BUG)",
			"current_fingerprint", w.path.fingerprint,
			"new_fingerprint", fp,
		)
		return
	}
	w.path = createQualityPathWrap(path)
}

// Path returns the currently monitored path.
func (w *QualityWatcher) Path() snet.Path {
	w.pathMtx.RLock()
	defer w.pathMtx.RUnlock()
	return w.path.Path
}

// Stats returns the current quality statistics for this path.
func (w *QualityWatcher) Stats() QualityStats {
	return w.tracker.Stats()
}

// Fingerprint returns the path fingerprint being watched.
func (w *QualityWatcher) Fingerprint() snet.PathFingerprint {
	w.pathMtx.RLock()
	defer w.pathMtx.RUnlock()
	return w.path.fingerprint
}

func (w *QualityWatcher) sendProbe(ctx context.Context) {
	w.pathMtx.RLock()
	defer w.pathMtx.RUnlock()

	seq := w.nextSeq
	w.nextSeq++
	sendTime := time.Now()
	w.tracker.RecordProbeSent(seq, sendTime)

	logger := log.FromCtx(ctx)
	if err := w.prepareProbePacket(seq); err != nil {
		// Mark as timeout since we couldn't even send
		w.tracker.RecordProbeTimeout(seq)
		logger.Debug("Failed to prepare quality probe", "err", err)
		return
	}
	if err := w.conn.WriteTo(w.packet, w.path.UnderlayNextHop()); err != nil {
		w.tracker.RecordProbeTimeout(seq)
		logger.Debug("Failed to send quality probe", "err", err)
	}
}

func (w *QualityWatcher) prepareProbePacket(seq uint16) error {
	if err := w.path.err; err != nil {
		return err
	}
	if w.path.expiry.Before(time.Now()) {
		return serrors.New("expired path", "expiration", w.path.expiry)
	}
	w.packet.PacketInfo = snet.PacketInfo{
		Destination: snet.SCIONAddress{
			IA:   w.remote,
			Host: addr.HostSVC(addr.SvcNone),
		},
		Source: w.localAddr,
		Path:   w.path.dpPath,
		Payload: snet.SCMPTracerouteRequest{
			Identifier: w.id,
			Sequence:   seq,
		},
	}
	return nil
}

func (w *QualityWatcher) drainConn(ctx context.Context) {
	logger := log.FromCtx(ctx)
	var pkt snet.Packet
	var ov net.UDPAddr
	for {
		err := w.conn.ReadFrom(&pkt, &ov)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if _, ok := err.(*snet.OpError); ok {
				continue
			}
			logger.Debug("Unexpected error reading quality probe reply", "err", err)
		}
	}
}

// qualityPathWrap contains preprocessed path data for probe sending.
type qualityPathWrap struct {
	snet.Path
	fingerprint snet.PathFingerprint
	expiry      time.Time
	dpPath      snet.DataplanePath
	err         error
}

func createQualityPathWrap(path snet.Path) qualityPathWrap {
	p := qualityPathWrap{
		Path:        path,
		fingerprint: path.Metadata().Fingerprint(),
		expiry:      path.Metadata().Expiry,
	}

	original, ok := p.Dataplane().(snetpath.SCION)
	if !ok {
		p.err = serrors.New("not a scion path", "type", common.TypeOf(p.Dataplane()))
		return p
	}

	var decoded scion.Decoded
	if err := decoded.DecodeFromBytes(original.Raw); err != nil {
		p.err = serrors.Wrap("decoding path", err)
		return p
	}
	// Set router alert on last hop to get SCMP traceroute replies
	if len(decoded.InfoFields) > 0 {
		info := decoded.InfoFields[len(decoded.InfoFields)-1]
		if info.ConsDir {
			decoded.HopFields[len(decoded.HopFields)-1].IngressRouterAlert = true
		} else {
			decoded.HopFields[len(decoded.HopFields)-1].EgressRouterAlert = true
		}
	}

	alert, err := snetpath.NewSCIONFromDecoded(decoded)
	if err != nil {
		p.err = serrors.Wrap("serializing path", err)
		return p
	}
	p.dpPath = alert
	return p
}
