package tests

import (
	"fmt"
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

func TestGenerateCredentials(t *testing.T) {
	ctx, st := suite.New(t)

	_ = ctx
	_ = st
	email := gofakeit.Email()
	user := gofakeit.Username()
	pass := randomFakePassword()

	fmt.Println(email, user, pass)
	assert.Equal(t, 1, 1)
}

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
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
