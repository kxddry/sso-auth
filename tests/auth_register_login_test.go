package tests

import (
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/kxddry/sso-protos/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sso-auth/tests/suite"
	"testing"
	"time"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	user := gofakeit.Username()
	pass := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Username: user,
		Password: pass,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	assertLogin := func(placeholder string) {
		respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
			Placeholder: placeholder,
			Password:    pass,
			AppId:       appID,
		})
		require.NoError(t, err)

		loginTime := time.Now()

		token := respLogin.GetToken()
		require.NotEmpty(t, token)

		tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(appSecret), nil
		})
		require.NoError(t, err)
		claims, ok := tokenParsed.Claims.(jwt.MapClaims)
		assert.True(t, ok)

		assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
		assert.Equal(t, email, claims["email"].(string))
		assert.Equal(t, appID, int(claims["app_id"].(float64)))

		const deltaSeconds = 1
		assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
	}

	assertLogin(email)
	assertLogin(user)
}

func randomFakePassword() string {
	// gofakeit.Password() doesn't always return a correct password. We accommodate for that by adding "Aa4_", indicating
	// a symbol for each type of required types of symbols.
	return gofakeit.Password(true, true, true, true, false, passDefaultLen) + "Aa4_"
}

func TestRegisterLogin_InvalidPassword(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	user := gofakeit.Username()
	pass := gofakeit.Password(false, true, true, true, false, passDefaultLen)

	check := func(pass string) {
		_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
			Email:    email,
			Username: user,
			Password: pass,
		})
		require.Error(t, err)
	}
	check(pass)

	pass = gofakeit.Password(true, false, true, true, false, passDefaultLen)
	check(pass)

	pass = gofakeit.Password(true, true, false, true, false, passDefaultLen)
	check(pass)

	pass = gofakeit.Password(true, true, true, false, false, passDefaultLen)
	check(pass)
}

func TestRegisterLogin_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	user := gofakeit.Username()
	pass := randomFakePassword()

	register := func() error {
		_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
			Email:    email,
			Username: user,
			Password: pass,
		})
		return err
	}

	// the first registration should go okay
	err := register()
	require.NoError(t, err)

	// the user is already registered
	err = register()
	require.Error(t, err)

	// the user with a different password is already registered
	pass = randomFakePassword()
	err = register()
	require.Error(t, err)

	// the user with a different username but the same email is already registered
	old_user := user
	user = gofakeit.Username()
	err = register()
	require.Error(t, err)

	// the user with the same username but a different email is already registered
	user = old_user
	email = gofakeit.Email()
	err = register()
	require.Error(t, err)
}

func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		username    string
		password    string
		expectedErr string
	}{
		{
			name:        "Register with Empty Password",
			email:       gofakeit.Email(),
			username:    gofakeit.Username(),
			password:    "",
			expectedErr: "password is required",
		},
		{
			name:        "Register with Empty Email",
			email:       "",
			username:    gofakeit.Username(),
			password:    randomFakePassword(),
			expectedErr: "email is required",
		},
		{
			name:        "Register with Empty Username",
			email:       gofakeit.Email(),
			username:    "",
			password:    randomFakePassword(),
			expectedErr: "username is required",
		},
		{
			name:        "Register with All Empty",
			email:       "",
			username:    "",
			password:    "",
			expectedErr: "email is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Username: tt.username,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)

		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		placeholder string
		password    string
		appID       int64
		expectedErr string
	}{
		{
			name:        "Login with Empty Password",
			placeholder: gofakeit.Email(),
			password:    "",
			appID:       appID,
			expectedErr: "password is required",
		},
		{
			name:        "Login with Empty Email",
			placeholder: "",
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "placeholder is required",
		},
		{
			name:        "Login with Username and Empty Password",
			placeholder: gofakeit.Username(),
			password:    "",
			appID:       appID,
			expectedErr: "password is required",
		},
		{
			name:        "Login with Both Empty Placeholder and Password",
			placeholder: "",
			password:    "",
			appID:       appID,
			expectedErr: "placeholder is required",
		},
		{
			name:        "Login with Non-Matching Password",
			placeholder: gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			expectedErr: "invalid credentials",
		},
		{
			name:        "Login without AppID",
			placeholder: gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       emptyAppID,
			expectedErr: "app id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    gofakeit.Email(),
				Username: gofakeit.Username(),
				Password: randomFakePassword(),
			})
			require.NoError(t, err)

			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
				Placeholder: tt.placeholder,
				Password:    tt.password,
				AppId:       tt.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}
