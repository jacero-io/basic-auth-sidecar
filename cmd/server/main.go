package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/jacero-io/basic-auth-sidecar/internal/auth"
	"github.com/jacero-io/basic-auth-sidecar/internal/config"
	"github.com/jacero-io/basic-auth-sidecar/internal/errors"
	"github.com/jacero-io/basic-auth-sidecar/internal/httpserver"
	"github.com/jacero-io/basic-auth-sidecar/internal/ratelimit"
	authv3 "github.com/jacero-io/basic-auth-sidecar/pkg/auth/v3"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	if err := run(logger); err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			logger.Fatal("Application failed to run",
				zap.Error(appErr.Err),
				zap.String("message", appErr.Message),
				zap.String("code", appErr.Code),
				zap.String("stack", appErr.Stack))
		} else {
			logger.Fatal("Application failed to run", zap.Error(err))
		}
	}
}

func run(logger *zap.Logger) error {
	configPath := flag.String("config", "/config/config.yaml", "Path to configuration file")
	flag.Parse()

	logger.Info("Loading configuration", zap.String("path", *configPath))
	cfg, err := config.Load(*configPath, logger)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	authenticator := auth.NewAuthenticator(cfg, logger)
	rateLimiter := ratelimit.NewIPRateLimiter(
		rate.Limit(cfg.RateLimit.RequestsPerSecond),
		cfg.RateLimit.Burst,
		cfg.RateLimit.CleanupInterval,
		cfg.RateLimit.MaxInactivity,
		authenticator,
	)

	grpcServer := createGRPCServer(authenticator, rateLimiter, logger)
	httpServer, err := createHTTPServer(cfg, authenticator, rateLimiter, logger)
	if err != nil {
		return err
	}

	errChan := make(chan error, 2)
	go startGRPCServer(grpcServer, cfg.Server.GRPCPort, errChan, logger)
	go startHTTPServer(httpServer, cfg.Server.HTTPPort, errChan, logger)

	return gracefulShutdown(grpcServer, httpServer, errChan, logger)
}

func createGRPCServer(authenticator *auth.Authenticator, rateLimiter *ratelimit.IPRateLimiter, logger *zap.Logger) *grpc.Server {
	grpcServer := grpc.NewServer()
	authServer := authv3.New(authenticator, rateLimiter, logger)
	envoy_service_auth_v3.RegisterAuthorizationServer(grpcServer, authServer)
	return grpcServer
}

func createHTTPServer(cfg *config.Config, authenticator *auth.Authenticator, rateLimiter *ratelimit.IPRateLimiter, logger *zap.Logger) (*http.Server, error) {
	handler, err := httpserver.NewServer(authenticator, rateLimiter, logger)
	if err != nil {
		return nil, errors.New(err, "Failed to create HTTP server", "HTTP_SERVER_CREATION_ERROR")
	}
	return &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler: handler,
	}, nil
}

func startGRPCServer(grpcServer *grpc.Server, port int, errChan chan<- error, logger *zap.Logger) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		errChan <- errors.ErrServerStart(err)
		return
	}
	logger.Info("Starting gRPC server", zap.Int("port", port))
	errChan <- grpcServer.Serve(lis)
}

func startHTTPServer(httpServer *http.Server, port int, errChan chan<- error, logger *zap.Logger) {
	logger.Info("Starting HTTP server", zap.Int("port", port))
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		errChan <- errors.ErrServerStart(err)
	}
}

func gracefulShutdown(grpcServer *grpc.Server, httpServer *http.Server, errChan <-chan error, logger *zap.Logger) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return err
	case sig := <-quit:
		logger.Info("Shutting down servers", zap.String("signal", sig.String()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	grpcServer.GracefulStop()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown failed", zap.Error(err))
		return errors.ErrServerShutdown(err)
	}

	logger.Info("Servers exited")
	return nil
}
