package auth

import (
	"context"
	"errors"
	"github.com/kxddry/sso-auth/internal/lib/validator"
	"github.com/kxddry/sso-auth/internal/services/auth"
	cds "github.com/kxddry/sso-auth/output-error-codes"
	ssov2 "github.com/kxddry/sso-protos/v2/gen/go/sso"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverAPI struct {
	ssov2.UnimplementedAuthServer
	auth Auth
}

type Auth interface {
	Login(ctx context.Context, email string, password string, appID int64) (token string, err error)
	RegisterNewUser(ctx context.Context, email string, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error)
	AppID(ctx context.Context, name, secret string) (appID int64, err error)
}

const (
	empty = 0

	InternalError = cds.InternalError

	// login
	EmailIsRequired    = cds.EmailIsRequired
	PasswordIsRequired = cds.PasswordIsRequired
	InvalidCredentials = cds.InvalidCredentials

	// registration
	AppIdIsRequired   = cds.AppIdIsRequired
	InvalidEmail      = cds.InvalidEmail
	InvalidPassword   = cds.InvalidPassword
	UserAlreadyExists = cds.UserAlreadyExists

	// IsAdmin
	UserNotFound = cds.UserNotFound

	// AppID
	WrongAppSecret         = cds.WrongAppSecret
	AppSecretAlreadyExists = cds.AppSecretAlreadyExists
	NameIsRequired         = cds.NameIsRequired
	SecretIsRequired       = cds.SecretIsRequired
	InvalidUserID          = cds.InvalidUserID
)

func Register(gRPC *grpc.Server, auth Auth) {
	ssov2.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov2.LoginRequest) (*ssov2.LoginResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, EmailIsRequired)
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, PasswordIsRequired)
	}
	if req.AppId == empty {
		return nil, status.Error(codes.InvalidArgument, AppIdIsRequired)
	}

	if !validator.ValidateEmail(req.Email) {
		return nil, status.Error(codes.InvalidArgument, InvalidEmail)
	}

	token, err := s.auth.Login(ctx, req.Email, req.Password, req.AppId)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, InvalidCredentials)
		}
		return nil, status.Error(codes.Internal, InternalError)
	}
	return &ssov2.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov2.RegisterRequest) (*ssov2.RegisterResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, EmailIsRequired)
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, PasswordIsRequired)
	}
	if !validator.ValidateEmail(req.GetEmail()) {
		return nil, status.Error(codes.InvalidArgument, InvalidEmail)
	}
	if !validator.ValidatePassword(req.Password) {
		return nil, status.Error(codes.InvalidArgument, InvalidPassword)
	}
	userId, err := s.auth.RegisterNewUser(ctx, req.Email, req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, UserAlreadyExists)
		}

		return nil, status.Error(codes.Internal, InternalError)
	}
	return &ssov2.RegisterResponse{UserId: userId}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov2.IsAdminRequest) (*ssov2.IsAdminResponse, error) {
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
	return &ssov2.IsAdminResponse{IsAdmin: a}, nil
}

func (s *serverAPI) AppID(ctx context.Context, req *ssov2.AppRequest) (*ssov2.AppResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, NameIsRequired)
	}
	if req.Pubkey == "" {
		return nil, status.Error(codes.InvalidArgument, SecretIsRequired)
	}

	appId, err := s.auth.AppID(ctx, req.GetName(), req.GetPubkey())
	if err != nil {
		if errors.Is(err, auth.ErrAppSecretExists) {
			return nil, status.Error(codes.InvalidArgument, AppSecretAlreadyExists)
		}
		if errors.Is(err, auth.ErrWrongAppSecret) {
			return nil, status.Error(codes.Unauthenticated, WrongAppSecret)
		}
		return nil, status.Error(codes.Internal, InternalError)
	}

	return &ssov2.AppResponse{AppId: appId}, nil
}

// mustEmbedUnimplementedAuthServer is required to ensure that the serverAPI struct
// implements the UnimplementedAuthServer interface.
//
// It is used to prevent breaking changes in future versions of the API.
func (s *serverAPI) mustEmbedUnimplementedAuthServer() {}
