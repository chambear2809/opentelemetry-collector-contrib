// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package yanggrpcreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver"

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal"
	pb "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/yanggrpcreceiver/internal/proto/generated/proto"
)

type yangReceiver struct {
	config          *Config
	settings        receiver.Settings
	logger          *zap.Logger
	consumer        consumer.Metrics
	server          *grpc.Server
	wg              sync.WaitGroup
	securityManager *internal.SecurityManager
	shutdownOnce    sync.Once
	forceStopOnce   sync.Once
	shutdownDone    chan struct{}
}

func createMetricsReceiver(_ context.Context, settings receiver.Settings, cfg component.Config, next consumer.Metrics) receiver.Metrics {
	return &yangReceiver{
		config:       cfg.(*Config),
		settings:     settings,
		logger:       settings.Logger,
		consumer:     next,
		wg:           sync.WaitGroup{},
		shutdownDone: make(chan struct{}),
	}
}

func (y *yangReceiver) Start(ctx context.Context, host component.Host) error {
	// 1. Setup Network Listener
	listener, err := y.config.NetAddr.Listen(ctx)
	if err != nil {
		return err
	}

	// 2. Initialize Security Management (Rate Limiting & Allowlist)
	securityManager := internal.NewSecurityManager(
		y.config.Security.AllowedClients,
		y.settings.Logger,
		y.config.Security.RateLimiting.Enabled,
		y.config.Security.RateLimiting.RequestsPerSecond,
		y.config.Security.RateLimiting.BurstSize,
		y.config.Security.RateLimiting.CleanupInterval,
	)

	// 3. Configure gRPC Server with Security Interceptors
	server, err := y.config.ToServer(ctx, host.GetExtensions(), y.settings.TelemetrySettings,
		configgrpc.WithGrpcServerOption(grpc.UnaryInterceptor(securityManager.CreateSecurityInterceptor())),
		configgrpc.WithGrpcServerOption(grpc.StreamInterceptor(securityManager.CreateStreamSecurityInterceptor())))
	if err != nil {
		securityManager.Shutdown()
		return errors.Join(err, listener.Close())
	}
	y.securityManager = securityManager
	y.server = server

	// 4. Initialize YANG Parsers
	// Standard Parser for structural analysis
	yangParser := internal.NewYANGParser()
	yangParser.LoadBuiltinModules()

	// Load external Cisco/IETF modules from configured paths for key and type enrichment.
	for _, path := range y.config.YANG.ModulePaths {
		y.settings.Logger.Info("Loading YANG modules from path", zap.String("path", path))
		if err := yangParser.ExtractYANGFromFiles(path); err != nil {
			server.Stop()
			securityManager.Shutdown()
			y.server = nil
			y.securityManager = nil
			return errors.Join(fmt.Errorf("load YANG modules from %q: %w", path, err), listener.Close())
		}
	}

	// 5. Register the Dial-out Service
	service := &grpcService{
		receiver:   y,
		yangParser: yangParser,
	}
	pb.RegisterGRPCMdtDialoutServer(y.server, service)

	// 6. Start Serving
	y.wg.Go(func() {
		y.settings.Logger.Info("Starting YANG gRPC receiver",
			zap.String("endpoint", y.config.NetAddr.Endpoint))
		if err := y.server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			y.settings.Logger.Error("gRPC server error", zap.Error(err))
		}
	})

	return nil
}

func (y *yangReceiver) Shutdown(ctx context.Context) error {
	if y.securityManager != nil {
		defer y.securityManager.Shutdown()
	}
	done := y.beginShutdown()
	select {
	case <-done:
	case <-ctx.Done():
		// GracefulStop waits for handlers as well as transports. A handler may
		// be blocked in a downstream consumer that does not honor cancellation,
		// so do not wait on the graceful goroutine after the shutdown deadline.
		// Start the forced stop asynchronously as grpc-go serializes Stop with the
		// already-running GracefulStop; waiting for that lock can itself wait on a
		// non-cooperative handler. Stop closes listeners and transports as soon as
		// it acquires the server lock, cancelling every stream context.
		if y.server != nil {
			y.forceStopOnce.Do(func() { go y.server.Stop() })
		}
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (y *yangReceiver) beginShutdown() <-chan struct{} {
	y.shutdownOnce.Do(func() {
		go func() {
			if y.server != nil {
				y.settings.Logger.Info("Stopping YANG gRPC receiver")
				y.server.GracefulStop()
			}
			y.wg.Wait()
			close(y.shutdownDone)
		}()
	})
	return y.shutdownDone
}
