package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/grpc/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
	listener   net.Listener
}

func New(
	log *slog.Logger,
	port int,
	authSvc auth.AuthService,
	accessTTL time.Duration,
	refreshTTL time.Duration,
) (*App, error) {
	const op = "grpc.New"

	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(
			logging.StartCall,
			logging.FinishCall,
		),
		logging.WithFieldsFromContext(func(ctx context.Context) logging.Fields {
			traceID, _ := ctx.Value("trace_id").(string)

			return logging.Fields{
				"trace_id", traceID,
			}
		}),
	}

	recoveryOpts := []recovery.Option{
		recovery.WithRecoveryHandler(func(p interface{}) (err error) {
			log.Error("Recovered from panic", slog.Any("panic", p))

			return status.Errorf(codes.Internal, "internal error")
		}),
	}

	gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		func(
			ctx context.Context,
			req any,
			info *grpc.UnaryServerInfo,
			handler grpc.UnaryHandler,
		) (any, error) {

			traceID := uuid.NewString()
			ctx = context.WithValue(ctx, "trace_id", traceID)

			return handler(ctx, req)
		},
		recovery.UnaryServerInterceptor(recoveryOpts...),
		logging.UnaryServerInterceptor(
			InterceptorLogger(log),
			loggingOpts...,
		),
	))

	auth.Register(gRPCServer, authSvc, accessTTL, refreshTTL)

	addr := fmt.Sprintf(":%d", port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to listen: %w", op, err)
	}

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
		listener:   lis,
	}, nil
}

func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func (app *App) Run() error {
	const op = "app.grpc.Run"

	log := app.log.With(
		slog.String("op", op),
		slog.Int("port", app.port),
	)

	log.Info("starting gRPC server")

	if err := app.gRPCServer.Serve(app.listener); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Shutdown(ctx context.Context) {
	done := make(chan struct{})

	go func() {
		a.gRPCServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		a.log.Info("gRPC server stopped gracefully")
	case <-ctx.Done():
		a.log.Warn("force stopping gRPC server")
		a.gRPCServer.Stop()
	}
}
