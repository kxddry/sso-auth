package auth

import (
	"context"
	"errors"
	"github.com/kxddry/sso-auth/internal/lib/validator"
	"github.com/kxddry/sso-auth/internal/services/auth"
	ssov1 "github.com/kxddry/sso-protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

type Auth interface {
	Login(ctx context.Context, placeholder string, typeOfPlaceholder int, password string, appID int64) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		username string,
		password string,
	) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error)
}

const (
	empty = 0
)

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if req.Placeholder == "" {
		return nil, status.Error(codes.InvalidArgument, "placeholder is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if req.AppId == empty {
		return nil, status.Error(codes.InvalidArgument, "app id is required")
	}

	valid := validator.ValidatePlaceholder(req.Placeholder)
	if valid == -1 {
		return nil, status.Error(codes.InvalidArgument, "invalid placeholder")
	}

	// note that the Login() function only gets called when the placeholder is valid.
	token, err := s.auth.Login(ctx, req.GetPlaceholder(), valid, req.GetPassword(), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if !validator.ValidateEmail(req.GetEmail()) {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}
	if !validator.ValidateUsername(req.GetUsername()) {
		return nil, status.Error(codes.InvalidArgument, "invalid username")
	}
	if !validator.ValidatePassword(req.Password) {
		return nil, status.Error(codes.InvalidArgument, "invalid password. Required: 8 <= length <= 72; lower, upper, numeric, special characters.")
	}
	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetUsername(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.RegisterResponse{UserId: userId}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if req.UserId == empty {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	a, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.IsAdminResponse{IsAdmin: a}, nil
}

func (s *serverAPI) mustEmbedUnimplementedAuthServer() {
	// This method is required to ensure that the serverAPI struct
	// implements the UnimplementedAuthServer interface.
	// It is used to prevent breaking changes in future versions of the API.
}
