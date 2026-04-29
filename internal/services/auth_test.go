package auth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	authgrpc "github.com/n0f4ph4mst3r/TokenCraft/internal/grpc/auth"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo"
	auth "github.com/n0f4ph4mst3r/TokenCraft/internal/services"
	hasherMocks "github.com/n0f4ph4mst3r/TokenCraft/internal/services/mocks/helpers/hasher"
	signerMocks "github.com/n0f4ph4mst3r/TokenCraft/internal/services/mocks/helpers/signer"
	authMocks "github.com/n0f4ph4mst3r/TokenCraft/internal/services/mocks/providers/auth"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	dummy                   = "Dummy"
	dummyEmail              = "dummy@gmail.com"
	dummyPassword           = "qwerty"
	dummyHashedPwd          = "$2a$12$zhgqlNmukTIR3pHuqnxE/e1cdr/.TJP/RT4Mic0ej5ESAEPJMgwxy"
	dummyAccessToken        = "sha256_random_access_token_123"
	dummyRefreshToken       = "random_string_123"
	dummyHashedRefreshToken = "hashed_random_string_123"
)

func TestRegisterUser(t *testing.T) {

	cases := []struct {
		name     string
		email    string
		username string
		password string

		hashError     error
		expectedError error

		response models.User
	}{
		{
			name:          "Success",
			email:         dummyEmail,
			username:      dummy,
			password:      dummyPassword,
			hashError:     nil,
			expectedError: nil,
			response: models.User{
				Email:    dummyEmail,
				Username: dummy,
				Password: []byte(dummyHashedPwd),
			},
		},
		{
			name:          "ErrorUserAlreadyExists",
			email:         "existingemail@gmail.com",
			username:      dummy,
			password:      dummyPassword,
			hashError:     nil,
			expectedError: repo.ErrUserExists,
		},
		{
			name:          "ErrorEmptyPassword",
			email:         dummyEmail,
			username:      dummy,
			password:      "",
			expectedError: auth.ErrInternal,
		},
		{
			name:          "ErrorPasswordTooShort",
			email:         dummyEmail,
			username:      dummy,
			password:      "123",
			hashError:     bcrypt.ErrHashTooShort,
			expectedError: bcrypt.ErrHashTooShort,
		},
		{
			name:          "ErrorPasswordTooLong",
			email:         dummyEmail,
			username:      dummy,
			password:      string(make([]byte, 1000)),
			hashError:     bcrypt.ErrPasswordTooLong,
			expectedError: bcrypt.ErrPasswordTooLong,
		},
		{
			name:          "ErrorUnknownHashError",
			email:         dummyEmail,
			username:      dummy,
			password:      "21213:::--234@!#",
			hashError:     errors.New("bcrypt error"),
			expectedError: auth.ErrInternal,
		},
		{
			name:          "ErrorEmptyEmail",
			email:         "",
			username:      dummy,
			password:      dummyPassword,
			expectedError: auth.ErrInternal,
		},
		{
			name:          "ErrorEmptyUsername",
			email:         dummyEmail,
			username:      "",
			password:      dummyPassword,
			expectedError: auth.ErrInternal,
		},
		{
			name:          "ErrorEmptyRequest",
			email:         "",
			username:      "",
			password:      "",
			expectedError: auth.ErrInternal,
		},
		{
			name:          "ErrorInternal",
			email:         dummyEmail,
			username:      dummy,
			password:      dummyPassword,
			expectedError: auth.ErrInternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			authProviderMock := authMocks.NewMockAuthProvider(t)
			hasherMock := hasherMocks.NewMockHasher(t)

			hasherMock.
				EXPECT().
				Hash(tc.password).
				Return(tc.response.Password, tc.hashError).
				Once()

			if tc.hashError == nil {
				authProviderMock.
					EXPECT().
					RegisterUser(mock.Anything, tc.email, tc.username, tc.response.Password).
					Return(tc.response, tc.expectedError).
					Once()
			}

			service := auth.NewAuthService(
				log,
				authProviderMock,
				time.Minute,
				time.Hour,
				"random_secret_123",
				hasherMock,
				nil,
				nil,
			)

			user, err := service.RegisterUser(ctx, tc.email, tc.username, tc.password)

			if tc.expectedError != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError.Error())
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.response.Email, user.Email)
			require.Equal(t, tc.response.Username, user.Username)
			require.Equal(t, tc.response.Password, user.Password)
		})
	}
}

func TestLogin(t *testing.T) {

	cases := []struct {
		name string

		email    string
		password string
		appId    int64

		setup func(
			email string,
			appId int64,
			provider *authMocks.MockAuthProvider,
			signer *signerMocks.MockTokenSigner,
			hasher *hasherMocks.MockHasher,
		)

		user   models.User
		tokens authgrpc.TokenPair

		expectedError error
	}{
		{
			name: "Success",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    1,

			setup: func(
				email string,
				appId int64,
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				app := models.App{
					ID: appId,
				}

				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(mock.Anything, appId).
					Return(app, nil).
					Once()

				signer.EXPECT().
					SignJWT(user, app, mock.Anything).
					Return(dummyAccessToken, nil).
					Once()

				signer.EXPECT().
					SignOpaque(user, app, mock.Anything).
					Return(dummyRefreshToken, nil).
					Once()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return([]byte(dummyHashedRefreshToken), nil).
					Once()

				provider.EXPECT().
					SaveToken(
						mock.Anything,
						user.ID,
						app.ID,
						base64.RawURLEncoding.EncodeToString([]byte(dummyHashedRefreshToken)),
						mock.AnythingOfType("time.Time"),
					).
					Return(nil).
					Once()
			},

			user: models.User{
				Email:    dummyEmail,
				Username: dummy,
				Password: []byte(dummyHashedPwd),
			},

			tokens: authgrpc.TokenPair{
				AccessToken:  dummyAccessToken,
				RefreshToken: dummyRefreshToken,
			},

			expectedError: nil,
		},
		{
			name: "ErrorUserNotFound",

			email:    "notexistingemail@gmail.com",
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(models.User{}, repo.ErrUserNotFound).
					Once()
			},

			expectedError: repo.ErrUserNotFound,
		},
		{
			name: "ErrorEmptyEmail",

			email:    "",
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(models.User{}, auth.ErrInternal).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorInvalidEmailFormat",

			email:    "invalid_email",
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(models.User{}, auth.ErrInternal).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorUserFetch",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(models.User{}, auth.ErrInternal).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorAppNotFound",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    9999,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(mock.Anything, appId).
					Return(models.App{}, repo.ErrAppNotFound).
					Once()
			},

			expectedError: repo.ErrAppNotFound,
		},
		{
			name: "ErrorEmptyAppID",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    0,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(mock.Anything, appId).
					Return(models.App{}, auth.ErrInternal).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorAppFetch",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(mock.Anything, appId).
					Return(models.App{}, auth.ErrInternal).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorInvalidPassword",

			email:    dummyEmail,
			password: "wrong_pass",
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(user, nil).
					Once()
			},

			expectedError: repo.ErrInvalidPass,
		},
		{
			name: "ErrorEmptyPassword",

			email:    dummyEmail,
			password: "",
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(user, nil).
					Once()
			},

			expectedError: repo.ErrInvalidPass,
		},
		{
			name: "ErrorPasswordCompare",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte("invalid_hash"),
				}

				provider.EXPECT().
					UserByEmail(mock.Anything, email).
					Return(user, nil).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorSignJWT",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				app := models.App{ID: appId}

				provider.EXPECT().UserByEmail(mock.Anything, email).Return(user, nil).Once()
				provider.EXPECT().AppById(mock.Anything, appId).Return(app, nil).Once()

				signer.EXPECT().
					SignJWT(user, app, mock.Anything).
					Return("", errors.New("jwt signing error")).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorSignOpaque",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				app := models.App{ID: appId}

				provider.EXPECT().UserByEmail(mock.Anything, email).Return(user, nil).Once()
				provider.EXPECT().AppById(mock.Anything, appId).Return(app, nil).Once()

				signer.EXPECT().SignJWT(user, app, mock.Anything).Return(dummyAccessToken, nil).Once()
				signer.EXPECT().SignOpaque(user, app, mock.Anything).Return("", errors.New("opaque error")).Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorHashRefreshToken",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				app := models.App{ID: appId}

				provider.EXPECT().UserByEmail(mock.Anything, email).Return(user, nil).Once()
				provider.EXPECT().AppById(mock.Anything, appId).Return(app, nil).Once()

				signer.EXPECT().SignJWT(user, app, mock.Anything).Return(dummyAccessToken, nil).Once()
				signer.EXPECT().SignOpaque(user, app, mock.Anything).Return(dummyRefreshToken, nil).Once()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return([]byte{}, errors.New("hash error")).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorSaveToken",

			email:    dummyEmail,
			password: dummyPassword,
			appId:    1,

			setup: func(email string, appId int64, provider *authMocks.MockAuthProvider, signer *signerMocks.MockTokenSigner, hasher *hasherMocks.MockHasher) {
				user := models.User{
					Email:    email,
					Username: dummy,
					Password: []byte(dummyHashedPwd),
				}

				app := models.App{ID: appId}

				provider.EXPECT().UserByEmail(mock.Anything, email).Return(user, nil).Once()
				provider.EXPECT().AppById(mock.Anything, appId).Return(app, nil).Once()

				signer.EXPECT().SignJWT(user, app, mock.Anything).Return(dummyAccessToken, nil).Once()
				signer.EXPECT().SignOpaque(user, app, mock.Anything).Return(dummyRefreshToken, nil).Once()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return([]byte(dummyHashedRefreshToken), nil).
					Once()

				provider.EXPECT().
					SaveToken(
						mock.Anything,
						user.ID,
						app.ID,
						base64.RawURLEncoding.EncodeToString([]byte(dummyHashedRefreshToken)),
						mock.AnythingOfType("time.Time"),
					).
					Return(auth.ErrInternal).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			authProvider := authMocks.NewMockAuthProvider(t)
			hasherMock := hasherMocks.NewMockHasher(t)
			signerMock := signerMocks.NewMockTokenSigner(t)

			tc.setup(tc.email, tc.appId, authProvider, signerMock, hasherMock)

			service := auth.NewAuthService(
				log,
				authProvider,
				time.Minute,
				time.Hour,
				"random_secret_123",
				hasherMock,
				hasherMock,
				signerMock,
			)

			user, tokens, err := service.Login(ctx, tc.email, tc.password, tc.appId)
			if tc.expectedError != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError.Error())
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.user.Email, user.Email)
			require.Equal(t, tc.user.Username, user.Username)
			require.Equal(t, tc.user.Password, user.Password)
			require.Equal(t, tc.tokens.AccessToken, tokens.AccessToken)
			require.Equal(t, tc.tokens.RefreshToken, tokens.RefreshToken)
		})
	}
}

func TestLogout(t *testing.T) {
	cases := []struct {
		name  string
		token string

		expectedHashedToken string

		hashErr       error
		expectedError error
	}{
		{
			name:                "Success",
			token:               dummyRefreshToken,
			expectedHashedToken: dummyHashedRefreshToken,
		},
		{
			name:  "ErrorTokenNotFound",
			token: dummyRefreshToken,
		},
		{
			name:          "ErrorEmptyToken",
			token:         "",
			expectedError: auth.ErrInternal,
		},
		{
			name:          "ErrorHashToken",
			token:         dummyRefreshToken,
			hashErr:       errors.New("sha256 error"),
			expectedError: auth.ErrInternal,
		},
		{
			name:                "ErrorRemoveToken",
			token:               dummyRefreshToken,
			expectedHashedToken: dummyHashedRefreshToken,
			expectedError:       auth.ErrInternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			authProvider := authMocks.NewMockAuthProvider(t)
			hasherMock := hasherMocks.NewMockHasher(t)

			hasherMock.EXPECT().
				Hash(tc.token).
				Return([]byte(tc.expectedHashedToken), tc.hashErr).
				Once()

			if tc.hashErr == nil {
				authProvider.EXPECT().
					RemoveToken(
						mock.Anything,
						base64.RawURLEncoding.EncodeToString([]byte(tc.expectedHashedToken)),
					).
					Return(tc.expectedError).
					Once()
			}

			service := auth.NewAuthService(
				log,
				authProvider,
				time.Minute,
				time.Hour,
				"random_secret_123",
				hasherMock,
				hasherMock,
				nil,
			)

			err := service.Logout(ctx, tc.token)
			if tc.expectedError != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError.Error())
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestUpdateToken(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	const (
		newRefreshToken = "new_random_string_456"
		app_secret      = "app_secret_123456789"
	)

	oldHashed := []byte(dummyHashedRefreshToken)
	newHashed := []byte("new_hashed_new_refresh_456")
	oldHashedB64 := base64.RawURLEncoding.EncodeToString(oldHashed)
	newHashedB64 := base64.RawURLEncoding.EncodeToString(newHashed)

	userID := uuid.New()
	appID := int64(1)

	newTokenData := func(expiresAt time.Time) models.Token {
		return models.Token{
			UserID:    userID,
			AppID:     appID,
			ExpiresAt: expiresAt,
		}
	}

	newUser := func() models.User {
		return models.User{
			ID:       userID,
			Email:    dummyEmail,
			Username: dummy,
			Password: []byte("hashed_password"),
		}
	}

	newApp := func() models.App {
		return models.App{ID: appID}
	}

	cases := []struct {
		name         string
		refreshToken string
		setup        func(
			provider *authMocks.MockAuthProvider,
			signer *signerMocks.MockTokenSigner,
			hasher *hasherMocks.MockHasher,
		)
		expectedError error
		expectedPair  authgrpc.TokenPair
	}{
		{
			name:         "Success",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))
				user := newUser()
				app := newApp()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Times(2)

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(ctx, appID).
					Return(app, nil).
					Once()

				provider.EXPECT().
					RemoveToken(ctx, oldHashedB64).
					Return(nil).
					Once()

				signer.EXPECT().
					SignJWT(user, app, time.Minute).
					Return(dummyAccessToken, nil).
					Once()

				signer.EXPECT().
					SignOpaque(user, app, app_secret).
					Return(newRefreshToken, nil).
					Once()

				hasher.EXPECT().
					Hash(newRefreshToken).
					Return(newHashed, nil).
					Once()

				provider.EXPECT().
					SaveToken(ctx, userID, appID, newHashedB64, mock.MatchedBy(func(t time.Time) bool { return true })).
					Return(nil).
					Once()
			},
			expectedError: nil,
			expectedPair: authgrpc.TokenPair{
				AccessToken:  dummyAccessToken,
				RefreshToken: newRefreshToken,
			},
		},
		{
			name:         "ErrorGetTokenNotFound",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Once()

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(models.Token{}, repo.ErrTokenNotFound).
					Once()
			},
			expectedError: repo.ErrTokenNotFound,
		},
		{
			name:         "ErrorGetTokenOther",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Once()

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(models.Token{}, errors.New("db error")).
					Once()
			},
			expectedError: auth.ErrInternal,
		},
		{
			name:         "ErrorTokenExpired",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(-time.Hour))

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Times(2)

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					RemoveToken(ctx, oldHashedB64).
					Return(nil).
					Once()
			},
			expectedError: repo.ErrTokenExpired,
		},
		{
			name:         "ErrorUserNotFound",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Times(2)

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(models.User{}, repo.ErrUserNotFound).
					Once()

				provider.EXPECT().
					RemoveToken(ctx, oldHashedB64).
					Return(nil).
					Once()
			},
			expectedError: repo.ErrUserNotFound,
		},
		{
			name:         "ErrorUserOther",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Once()

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(models.User{}, errors.New("db error")).
					Once()
			},
			expectedError: auth.ErrInternal,
		},
		{
			name:         "ErrorAppNotFound",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))
				user := newUser()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Times(2)

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(ctx, appID).
					Return(models.App{}, repo.ErrAppNotFound).
					Once()

				provider.EXPECT().
					RemoveToken(ctx, oldHashedB64).
					Return(nil).
					Once()
			},
			expectedError: repo.ErrAppNotFound,
		},
		{
			name:         "ErrorAppOther",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))
				user := newUser()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Once()

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(ctx, appID).
					Return(models.App{}, errors.New("db error")).
					Once()
			},
			expectedError: auth.ErrInternal,
		},
		{
			name:         "ErrorRemoveToken",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))
				user := newUser()
				app := newApp()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Times(2)

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(ctx, appID).
					Return(app, nil).
					Once()

				provider.EXPECT().
					RemoveToken(ctx, oldHashedB64).
					Return(errors.New("remove error")).
					Once()
			},
			expectedError: auth.ErrInternal,
		},
		{
			name:         "ErrorSignJWT",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))
				user := newUser()
				app := newApp()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Times(2)

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(ctx, appID).
					Return(app, nil).
					Once()

				provider.EXPECT().
					RemoveToken(ctx, oldHashedB64).
					Return(nil).
					Once()

				signer.EXPECT().
					SignJWT(user, app, time.Minute).
					Return("", errors.New("jwt error")).
					Once()
			},
			expectedError: auth.ErrInternal,
		},
		{
			name:         "ErrorSignOpaque",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))
				user := newUser()
				app := newApp()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Times(2)

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(ctx, appID).
					Return(app, nil).
					Once()

				provider.EXPECT().
					RemoveToken(ctx, oldHashedB64).
					Return(nil).
					Once()

				signer.EXPECT().
					SignJWT(user, app, time.Minute).
					Return(dummyAccessToken, nil).
					Once()

				signer.EXPECT().
					SignOpaque(user, app, app_secret).
					Return("", errors.New("opaque error")).
					Once()
			},
			expectedError: auth.ErrInternal,
		},
		{
			name:         "ErrorSaveToken",
			refreshToken: dummyRefreshToken,
			setup: func(
				provider *authMocks.MockAuthProvider,
				signer *signerMocks.MockTokenSigner,
				hasher *hasherMocks.MockHasher,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))
				user := newUser()
				app := newApp()

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return(oldHashed, nil).
					Times(2)

				provider.EXPECT().
					GetToken(ctx, oldHashedB64).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					UserById(ctx, userID).
					Return(user, nil).
					Once()

				provider.EXPECT().
					AppById(ctx, appID).
					Return(app, nil).
					Once()

				provider.EXPECT().
					RemoveToken(ctx, oldHashedB64).
					Return(nil).
					Once()

				signer.EXPECT().
					SignJWT(user, app, time.Minute).
					Return(dummyAccessToken, nil).
					Once()

				signer.EXPECT().
					SignOpaque(user, app, app_secret).
					Return(newRefreshToken, nil).
					Once()

				hasher.EXPECT().
					Hash(newRefreshToken).
					Return(newHashed, nil).
					Once()

				provider.EXPECT().
					SaveToken(ctx, userID, appID, newHashedB64, mock.MatchedBy(func(t time.Time) bool { return true })).
					Return(errors.New("save error")).
					Once()
			},
			expectedError: auth.ErrInternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := authMocks.NewMockAuthProvider(t)
			signer := signerMocks.NewMockTokenSigner(t)
			hasher := hasherMocks.NewMockHasher(t)

			tc.setup(provider, signer, hasher)

			service := auth.NewAuthService(
				log,
				provider,
				time.Minute,
				time.Hour,
				app_secret,
				nil,
				hasher,
				signer,
			)

			pair, err := service.UpdateToken(ctx, tc.refreshToken)

			if tc.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedPair.AccessToken, pair.AccessToken)
			require.Equal(t, tc.expectedPair.RefreshToken, pair.RefreshToken)
		})
	}
}

func TestRoleCheck(t *testing.T) {
	userID := uuid.New()
	appID := int64(1)

	encodedToken := base64.RawURLEncoding.EncodeToString([]byte(dummyHashedRefreshToken))

	newTokenData := func(expiresAt time.Time) models.Token {
		return models.Token{
			UserID:    userID,
			AppID:     appID,
			ExpiresAt: expiresAt,
		}
	}

	cases := []struct {
		name         string
		token        string
		requiredRole string
		setup        func(
			provider *authMocks.MockAuthProvider,
			hasher *hasherMocks.MockHasher,
			token string,
			requiredRole string,
		)
		expectedError error
	}{
		{
			name: "Success",

			token:        dummyRefreshToken,
			requiredRole: "admin",

			setup: func(
				provider *authMocks.MockAuthProvider,
				hasher *hasherMocks.MockHasher,
				token string,
				requiredRole string,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))

				hasher.EXPECT().
					Hash(dummyRefreshToken).
					Return([]byte(dummyHashedRefreshToken), nil).
					Times(2)

				provider.EXPECT().
					GetToken(mock.Anything, encodedToken).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					RoleCheck(mock.Anything, encodedToken, "admin").
					Return(nil).
					Once()
			},

			expectedError: nil,
		},
		{
			name: "ErrorForbidden",

			token:        dummyRefreshToken,
			requiredRole: "sudo",

			setup: func(
				provider *authMocks.MockAuthProvider,
				hasher *hasherMocks.MockHasher,
				token string,
				requiredRole string,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))

				hasher.EXPECT().
					Hash(token).
					Return([]byte(dummyHashedRefreshToken), nil).
					Times(2)

				provider.EXPECT().
					GetToken(mock.Anything, encodedToken).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					RoleCheck(mock.Anything, encodedToken, requiredRole).
					Return(repo.ErrForbidden).
					Once()
			},

			expectedError: repo.ErrForbidden,
		},
		{
			name: "ErrorUserNotFound",

			token:        dummyRefreshToken,
			requiredRole: "admin",

			setup: func(
				provider *authMocks.MockAuthProvider,
				hasher *hasherMocks.MockHasher,
				token string,
				requiredRole string,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))

				hasher.EXPECT().
					Hash(token).
					Return([]byte(dummyHashedRefreshToken), nil).
					Times(2)

				provider.EXPECT().
					GetToken(mock.Anything, encodedToken).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					RoleCheck(mock.Anything, encodedToken, requiredRole).
					Return(repo.ErrUserNotFound).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorTokenExpired",

			token:        dummyRefreshToken,
			requiredRole: "admin",

			setup: func(
				provider *authMocks.MockAuthProvider,
				hasher *hasherMocks.MockHasher,
				token string,
				requiredRole string,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))

				hasher.EXPECT().
					Hash(token).
					Return([]byte(dummyHashedRefreshToken), nil).
					Times(2)

				provider.EXPECT().
					GetToken(mock.Anything, encodedToken).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					RoleCheck(mock.Anything, encodedToken, requiredRole).
					Return(repo.ErrTokenExpired).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
		{
			name: "ErrorInternal",

			token:        dummyRefreshToken,
			requiredRole: "admin",

			setup: func(
				provider *authMocks.MockAuthProvider,
				hasher *hasherMocks.MockHasher,
				token string,
				requiredRole string,
			) {
				tokenData := newTokenData(time.Now().Add(time.Hour))

				hasher.EXPECT().
					Hash(token).
					Return([]byte(dummyHashedRefreshToken), nil).
					Times(2)

				provider.EXPECT().
					GetToken(mock.Anything, encodedToken).
					Return(tokenData, nil).
					Once()

				provider.EXPECT().
					RoleCheck(mock.Anything, encodedToken, requiredRole).
					Return(auth.ErrInternal).
					Once()
			},

			expectedError: auth.ErrInternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			provider := authMocks.NewMockAuthProvider(t)
			hasher := hasherMocks.NewMockHasher(t)

			tc.setup(provider, hasher, tc.token, tc.requiredRole)

			service := auth.NewAuthService(
				log,
				provider,
				time.Minute,
				time.Hour,
				"secret",
				nil,
				hasher,
				nil,
			)

			ok, err := service.RoleCheck(ctx, tc.token, tc.requiredRole)

			if tc.expectedError != nil {
				require.Error(t, err)
				require.False(t, ok)
				require.ErrorIs(t, err, tc.expectedError)
				return
			}

			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}
