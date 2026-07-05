// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/proto/generated/proto"
)

const unknownStreamPeer = "<unknown>"

type admittedStream struct {
	peer   string
	cancel context.CancelFunc
}

// streamAdmission owns receiver-wide stream accounting. grpc.MaxConcurrentStreams
// applies independently to each HTTP/2 transport; this additional registry makes
// the configured limit global across every accepted connection.
type streamAdmission struct {
	mu           sync.Mutex
	active       map[uint64]admittedStream
	activeByPeer map[string]int
	nextID       uint64
	globalLimit  int
	perPeerLimit int
	shuttingDown bool
}

func newStreamAdmission(globalLimit, perPeerLimit int) *streamAdmission {
	return &streamAdmission{
		active:       make(map[uint64]admittedStream),
		activeByPeer: make(map[string]int),
		globalLimit:  max(globalLimit, 1),
		perPeerLimit: max(perPeerLimit, 1),
	}
}

func (a *streamAdmission) admit(parent context.Context) (context.Context, func(), error) {
	ctx, cancel := context.WithCancel(parent)
	peerKey := streamPeerKey(parent)

	a.mu.Lock()
	if a.shuttingDown {
		a.mu.Unlock()
		cancel()
		return nil, nil, status.Error(codes.Unavailable, "telemetry receiver is shutting down")
	}
	if len(a.active) >= a.globalLimit {
		a.mu.Unlock()
		cancel()
		return nil, nil, status.Error(codes.ResourceExhausted, "maximum active telemetry streams reached")
	}
	if a.activeByPeer[peerKey] >= a.perPeerLimit {
		a.mu.Unlock()
		cancel()
		return nil, nil, status.Error(codes.ResourceExhausted, "maximum active telemetry streams for client reached")
	}

	id := a.nextID
	a.nextID++
	a.active[id] = admittedStream{peer: peerKey, cancel: cancel}
	a.activeByPeer[peerKey]++
	a.mu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			a.mu.Lock()
			if admitted, ok := a.active[id]; ok {
				delete(a.active, id)
				a.activeByPeer[admitted.peer]--
				if a.activeByPeer[admitted.peer] == 0 {
					delete(a.activeByPeer, admitted.peer)
				}
			}
			a.mu.Unlock()
		})
	}
	return ctx, release, nil
}

// beginShutdown prevents new admissions and cancels every registered stream
// context before grpc.GracefulStop begins waiting for handlers.
func (a *streamAdmission) beginShutdown() {
	a.mu.Lock()
	a.shuttingDown = true
	cancels := make([]context.CancelFunc, 0, len(a.active))
	for _, stream := range a.active {
		cancels = append(cancels, stream.cancel)
	}
	a.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
}

func (a *streamAdmission) activeCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active)
}

func streamPeerKey(ctx context.Context) string {
	remote, ok := peer.FromContext(ctx)
	if !ok || remote.Addr == nil {
		return unknownStreamPeer
	}
	address := remote.Addr.String()
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return strings.ToLower(host)
	}
	return remote.Addr.Network() + ":" + address
}

type streamContextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *streamContextServerStream) Context() context.Context {
	return s.ctx
}

func (y *yangReceiver) createStreamAdmissionInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, release, err := y.streamAdmission.admit(stream.Context())
		if err != nil {
			return err
		}
		defer release()
		return handler(srv, &streamContextServerStream{ServerStream: stream, ctx: ctx})
	}
}

type receivedTelemetryFrame struct {
	request   *pb.MdtDialoutArgs
	err       error
	processed chan struct{}
}

// telemetryStreamReader keeps at most one decoded, unprocessed frame per
// admitted stream. Together with receiver-wide stream admission, this bounds
// aggregate in-flight frames by MaxConcurrentStreams without letting idle
// streams reserve the smaller conversion semaphore.
type telemetryStreamReader struct {
	ctx         context.Context
	cancel      context.CancelFunc
	stream      pb.GRPCMdtDialout_MdtDialoutServer
	received    chan receivedTelemetryFrame
	idleTimeout time.Duration
	idleTimer   *time.Timer
}

func newTelemetryStreamReader(
	ctx context.Context,
	stream pb.GRPCMdtDialout_MdtDialoutServer,
	idleTimeout time.Duration,
) *telemetryStreamReader {
	readerCtx, cancel := context.WithCancel(ctx)
	return &telemetryStreamReader{
		ctx:         readerCtx,
		cancel:      cancel,
		stream:      stream,
		received:    make(chan receivedTelemetryFrame),
		idleTimeout: idleTimeout,
	}
}

func (r *telemetryStreamReader) read() {
	for {
		request, err := r.stream.Recv()
		frame := receivedTelemetryFrame{request: request, err: err, processed: make(chan struct{})}
		select {
		case r.received <- frame:
		case <-r.ctx.Done():
			return
		}
		if err != nil {
			return
		}
		select {
		case <-frame.processed:
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *telemetryStreamReader) receive() (*pb.MdtDialoutArgs, func(), error) {
	r.resetIdleTimer()
	select {
	case frame := <-r.received:
		r.stopIdleTimer()
		if frame.err != nil {
			return nil, nil, frame.err
		}
		var once sync.Once
		return frame.request, func() { once.Do(func() { close(frame.processed) }) }, nil
	case <-r.idleTimer.C:
		// Returning from the handler causes grpc-go to cancel the transport stream,
		// which unblocks the in-progress Recv. Cancel the reader first so it also
		// exits immediately when it is waiting to publish a decoded frame.
		r.cancel()
		return nil, nil, status.Errorf(codes.DeadlineExceeded, "telemetry stream idle timeout exceeded after %s", r.idleTimeout)
	case <-r.ctx.Done():
		r.stopIdleTimer()
		return nil, nil, status.FromContextError(r.ctx.Err()).Err()
	}
}

func (r *telemetryStreamReader) resetIdleTimer() {
	if r.idleTimer == nil {
		r.idleTimer = time.NewTimer(r.idleTimeout)
		return
	}
	r.stopIdleTimer()
	r.idleTimer.Reset(r.idleTimeout)
}

func (r *telemetryStreamReader) stopIdleTimer() {
	if r.idleTimer == nil || r.idleTimer.Stop() {
		return
	}
	select {
	case <-r.idleTimer.C:
	default:
	}
}

func (r *telemetryStreamReader) stop() {
	r.cancel()
	r.stopIdleTimer()
}
