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
	AppID(ctx context.Context, name, secret string) (appID int64, err error)
}

const (
	empty = 0

	InternalError = "internal error"

	// login
	PlaceholderIsRequired = "placeholder is required"
	PasswordIsRequired    = "password is required"
	InvalidPlaceholder    = "invalid placeholder"
	InvalidCredentials    = "invalid credentials"

	// registration
	EmailIsRequired    = "email is required"
	UsernameIsRequired = "username is required"
	AppIdIsRequired    = "app id is required"
	InvalidEmail       = "invalid email"
	InvalidUsername    = "invalid username"
	InvalidPassword    = "invalid password. Required: 8 <= length <= 72; lower, upper, numeric, special characters."
	UserAlreadyExists  = "user already exists"

	// IsAdmin
	UserNotFound = "user not found"

	// AppID
	WrongAppSecret         = "wrong app secret"
	AppSecretAlreadyExists = "app secret already exists for another app! generate a new one."
	NameIsRequired         = "name is required"
	SecretIsRequired       = "secret is required"
	InvalidUserID          = "invalid user id"
)

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if req.Placeholder == "" {
		return nil, status.Error(codes.InvalidArgument, PlaceholderIsRequired)
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, PasswordIsRequired)
	}
	if req.AppId == empty {
		return nil, status.Error(codes.InvalidArgument, AppIdIsRequired)
	}

	valid := validator.ValidatePlaceholder(req.Placeholder)
	if valid == -1 {
		return nil, status.Error(codes.InvalidArgument, InvalidPlaceholder)
	}

	// note that the Login() function only gets called when the placeholder is valid.
	token, err := s.auth.Login(ctx, req.GetPlaceholder(), valid, req.GetPassword(), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, InvalidCredentials)
		}
		return nil, status.Error(codes.Internal, InternalError)
	}
	return &ssov1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, EmailIsRequired)
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, UsernameIsRequired)
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, PasswordIsRequired)
	}
	if !validator.ValidateEmail(req.GetEmail()) {
		return nil, status.Error(codes.InvalidArgument, InvalidEmail)
	}
	if !validator.ValidateUsername(req.GetUsername()) {
		return nil, status.Error(codes.InvalidArgument, InvalidUsername)
	}
	if !validator.ValidatePassword(req.Password) {
		return nil, status.Error(codes.InvalidArgument, InvalidPassword)
	}
	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetUsername(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, UserAlreadyExists)
		}

		return nil, status.Error(codes.Internal, InternalError)
	}
	return &ssov1.RegisterResponse{UserId: userId}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if req.UserId == empty {
		return nil, status.Error(codes.InvalidArgument, InvalidUserID)
	}
	a, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, UserNotFound)
		}

		return nil, status.Error(codes.Internal, InternalError)
	}
	return &ssov1.IsAdminResponse{IsAdmin: a}, nil
}

func (s *serverAPI) AppID(ctx context.Context, req *ssov1.AppRequest) (*ssov1.AppResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, NameIsRequired)
	}
	if req.Secret == "" {
		return nil, status.Error(codes.InvalidArgument, SecretIsRequired)
	}

	appId, err := s.auth.AppID(ctx, req.GetName(), req.GetSecret())
	if err != nil {
		if errors.Is(err, auth.ErrAppSecretExists) {
			return nil, status.Error(codes.InvalidArgument, AppSecretAlreadyExists)
		}
		if errors.Is(err, auth.ErrWrongAppSecret) {
			return nil, status.Error(codes.Unauthenticated, WrongAppSecret)
		}
		return nil, status.Error(codes.Internal, InternalError)
	}

	return &ssov1.AppResponse{AppId: appId}, nil
}

func (s *serverAPI) mustEmbedUnimplementedAuthServer() {
	// This method is required to ensure that the serverAPI struct
	// implements the UnimplementedAuthServer interface.
	// It is used to prevent breaking changes in future versions of the API.
}
