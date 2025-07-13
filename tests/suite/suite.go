package suite

import (
	"context"
	"github.com/kxddry/sso-auth/internal/config"
	ssov2 "github.com/kxddry/sso-protos/v2/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"strconv"
	"testing"
)

const grpcHost = "localhost"

type Suite struct {
	*testing.T
	Cfg        *config.Config
	AuthClient ssov2.AuthClient
}

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()   // so that New() isn't the final function in case of a failed test
	t.Parallel() // to run tests in parallel

	cfg := config.MustLoadByPath("../config/local_tests.yaml")
	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
	})

	cc, err := grpc.DialContext(ctx, grpcAddress(cfg), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create grpc client: %v", err)
	}

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: ssov2.NewAuthClient(cc),
	}
}

func grpcAddress(cfg *config.Config) string {
	return net.JoinHostPort(grpcHost, strconv.Itoa(cfg.GRPC.Port))
}
