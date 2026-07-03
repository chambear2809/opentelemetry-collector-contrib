// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ciscoosreceiver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	legacyGNMICapabilitiesTimeout   = 15 * time.Second
	legacyGNMIReconnectBackoff      = 5 * time.Second
	legacyGNMIAuthenticationBackoff = 5 * time.Minute
)

// legacyGNMISession keeps the fork's legacy ClientConfig surface and metric
// decoders while sharing the gNMI connection and subscription state machine.
type legacyGNMISession struct {
	settings receiver.Settings
	host     component.Host

	clientConfig     configgrpc.ClientConfig
	username         string
	password         string
	skipCapabilities bool
	pollInterval     time.Duration
	targetName       string
	onceCloseLog     string

	buildRequest func(*gnmi.CapabilityResponse) (*gnmi.SubscribeRequest, error)
	onSubscribed func()
	handleUpdate func(context.Context, *gnmi.Notification) error
	handleSync   func()
}

type legacyGNMIResponseEvent struct {
	synced bool
	err    error
}

func (s legacyGNMISession) run(ctx context.Context) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := s.clientConfig.ToClientConn(
		sessionCtx,
		s.host.GetExtensions(),
		s.settings.TelemetrySettings,
		configgrpc.WithGrpcDialOption(grpc.WithBlock()), //nolint:staticcheck // Preserve legacy blocking ClientConfig dialing for one compatibility release.
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := gnmi.NewGNMIClient(conn)
	capabilities := &gnmi.CapabilityResponse{}
	if !s.skipCapabilities {
		capCtx, capCancel := context.WithTimeout(s.outgoingContext(sessionCtx), legacyGNMICapabilitiesTimeout)
		capabilities, err = client.Capabilities(capCtx, &gnmi.CapabilityRequest{})
		capCancel()
		if err != nil {
			return fmt.Errorf("capabilities: %w", err)
		}
	}

	request, err := s.buildRequest(capabilities)
	if err != nil {
		return err
	}
	if request == nil || request.GetSubscribe() == nil {
		return errors.New("legacy gNMI session requires a subscription request")
	}

	stream, err := client.Subscribe(s.outgoingContext(sessionCtx))
	if err != nil {
		return err
	}
	if err := stream.Send(request); err != nil {
		return err
	}
	if s.onSubscribed != nil {
		s.onSubscribed()
	}

	events := make(chan legacyGNMIResponseEvent, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		s.readResponses(sessionCtx, stream, events)
	}()
	defer func() {
		// Cancel the exact context passed to Subscribe so Recv is interrupted,
		// then join the reader before the session releases receiver-owned state.
		// If handleUpdate is still in a downstream consumer, this intentionally
		// keeps the session (and receiver shutdown) incomplete until it returns.
		cancel()
		<-readerDone
	}()

	switch request.GetSubscribe().GetMode() {
	case gnmi.SubscriptionList_ONCE:
		if closeErr := stream.CloseSend(); closeErr != nil {
			s.settings.Logger.Debug(s.onceCloseLog, zap.String("target", s.targetName), zap.Error(closeErr))
		}
		if err := waitLegacyGNMISync(sessionCtx, events); err != nil {
			return err
		}
		return waitLegacyGNMITerminal(sessionCtx, events)
	case gnmi.SubscriptionList_POLL:
		if err := waitLegacyGNMISync(sessionCtx, events); err != nil {
			return err
		}
		return s.runPoll(sessionCtx, stream, events)
	case gnmi.SubscriptionList_STREAM:
		return waitLegacyGNMITerminal(sessionCtx, events)
	default:
		return fmt.Errorf("unsupported legacy gNMI subscription mode %s", request.GetSubscribe().GetMode())
	}
}

func (s legacyGNMISession) runPoll(
	ctx context.Context,
	stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse],
	events <-chan legacyGNMIResponseEvent,
) error {
	if s.pollInterval <= 0 {
		return errors.New("legacy gNMI poll interval must be positive")
	}
	for {
		if err := stream.Send(&gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Poll{Poll: &gnmi.Poll{}}}); err != nil {
			return err
		}
		if err := waitLegacyGNMISync(ctx, events); err != nil {
			return err
		}
		terminal, err := waitLegacyGNMIPollInterval(ctx, events, s.pollInterval)
		if err != nil || terminal {
			return err
		}
	}
}

//nolint:staticcheck // Legacy targets can still send the deprecated in-band gNMI Error response.
func (s legacyGNMISession) readResponses(
	ctx context.Context,
	stream grpc.BidiStreamingClient[gnmi.SubscribeRequest, gnmi.SubscribeResponse],
	events chan<- legacyGNMIResponseEvent,
) {
	publish := func(event legacyGNMIResponseEvent) bool {
		select {
		case events <- event:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for {
		response, err := stream.Recv()
		if err != nil {
			publish(legacyGNMIResponseEvent{err: err})
			return
		}
		switch body := response.GetResponse().(type) {
		case *gnmi.SubscribeResponse_Update:
			if body.Update != nil && s.handleUpdate != nil {
				if err := s.handleUpdate(ctx, body.Update); err != nil {
					publish(legacyGNMIResponseEvent{err: err})
					return
				}
			}
		case *gnmi.SubscribeResponse_SyncResponse:
			if body.SyncResponse {
				if s.handleSync != nil {
					s.handleSync()
				}
				if !publish(legacyGNMIResponseEvent{synced: true}) {
					return
				}
			}
		case *gnmi.SubscribeResponse_Error:
			if body.Error != nil {
				publish(legacyGNMIResponseEvent{err: sanitizedGNMISubscribeStatusError(body.Error)})
				return
			}
		}
	}
}

func (s legacyGNMISession) outgoingContext(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "username", s.username, "password", s.password)
}

func waitLegacyGNMISync(ctx context.Context, events <-chan legacyGNMIResponseEvent) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-events:
			if event.err != nil {
				if errors.Is(event.err, io.EOF) {
					return io.ErrUnexpectedEOF
				}
				return event.err
			}
			if event.synced {
				return nil
			}
		}
	}
}

func waitLegacyGNMITerminal(ctx context.Context, events <-chan legacyGNMIResponseEvent) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-events:
			if event.err == nil {
				continue
			}
			if errors.Is(event.err, io.EOF) {
				return nil
			}
			return event.err
		}
	}
}

func waitLegacyGNMIPollInterval(
	ctx context.Context,
	events <-chan legacyGNMIResponseEvent,
	interval time.Duration,
) (bool, error) {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
			return false, nil
		case event := <-events:
			if event.err == nil {
				continue
			}
			if errors.Is(event.err, io.EOF) {
				return true, nil
			}
			return false, event.err
		}
	}
}

func legacyGNMIRetryDelay(err error) time.Duration {
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return legacyGNMIAuthenticationBackoff
	default:
		return legacyGNMIReconnectBackoff
	}
}
