package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/grpc/auth"
	authMocks "github.com/n0f4ph4mst3r/TokenCraft/internal/grpc/auth/mocks"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo"
	authSvc "github.com/n0f4ph4mst3r/TokenCraft/internal/services"
	ssov1 "github.com/n0f4ph4mst3r/TokenCraft/protos/gen/go/sso"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	dummy             = "Dummy"
	dummyEmail        = "dummy@gmail.com"
	dummyPassword     = "securePass123"
	dummyAccessToken  = "sha256_random_access_token_123"
	dummyRefreshToken = "random_string_123"
)

func TestRegisterUser(t *testing.T) {

	sampleUser := models.User{
		ID:       uuid.New(),
		Username: dummy,
		Email:    dummyEmail,
	}

	cases := []struct {
		name string
		req  *ssov1.RegisterRequest

		serviceResp  models.User
		serviceError error

		expectedCode  codes.Code
		expectedResp  *ssov1.RegisterResponse
		expectedError string
	}{
		{
			name: "Success",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: dummy,
				Password: dummyPassword,
			},

			serviceResp:  sampleUser,
			serviceError: nil,

			expectedCode: codes.OK,
			expectedResp: &ssov1.RegisterResponse{
				UserId:   sampleUser.ID.String(),
				Username: sampleUser.Username,
				Email:    sampleUser.Email,
			},
		},
		{
			name: "ErrEmptyEmail",
			req: &ssov1.RegisterRequest{
				Email:    "",
				Username: dummy,
				Password: dummyPassword,
			},

			expectedCode:  codes.InvalidArgument,
			expectedError: "Email is required",
		},
		{
			name: "ErrInvalidEmailFormat",
			req: &ssov1.RegisterRequest{
				Email:    "not-an-email",
				Username: dummy,
				Password: dummyPassword,
			},

			expectedCode:  codes.InvalidArgument,
			expectedError: "Email must be valid",
		},
		{
			name: "ErrEmptyPassword",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: dummy,
				Password: "",
			},

			expectedCode:  codes.InvalidArgument,
			expectedError: "Password is required",
		},
		{
			name: "ErrPasswordTooShort",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: dummy,
				Password: "short",
			},

			expectedCode:  codes.InvalidArgument,
			expectedError: "Password must be at least 8 characters",
		},
		{
			name: "ErrPasswordTooLong",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: dummy,
				Password: "thispasswordiswaytoolong123",
			},

			expectedCode:  codes.InvalidArgument,
			expectedError: "Password must be at most 16 characters",
		},
		{
			name: "ErrEmptyUsername",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: "",
				Password: dummyPassword,
			},

			expectedCode:  codes.InvalidArgument,
			expectedError: "Username is required",
		},
		{
			name: "ErrUsernameTooShort",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: "a",
				Password: dummyPassword,
			},

			expectedCode:  codes.InvalidArgument,
			expectedError: "Username must be at least 2 characters",
		},
		{
			name: "ErrUsernameTooLong",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: "thisusernameiswaytoolongandexceedsfiftycharacterslimit1234567890",
				Password: dummyPassword,
			},

			expectedCode:  codes.InvalidArgument,
			expectedError: "Username must be at most 50 characters",
		},
		{
			name: "ErrAlreadyExists",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: dummy,
				Password: dummyPassword,
			},

			serviceResp:  models.User{},
			serviceError: repo.ErrUserExists,

			expectedCode:  codes.AlreadyExists,
			expectedError: "user already exists",
		},
		{
			name: "ErrHashTooShort",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: dummy,
				Password: dummyPassword,
			},

			serviceResp:  models.User{},
			serviceError: bcrypt.ErrHashTooShort,

			expectedCode:  codes.InvalidArgument,
			expectedError: "password hash error - too short",
		},
		{
			name: "ErrHashPasswordTooLong",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: dummy,
				Password: dummyPassword,
			},

			serviceResp:  models.User{},
			serviceError: bcrypt.ErrPasswordTooLong,

			expectedCode:  codes.InvalidArgument,
			expectedError: "password hash error - too long",
		},
		{
			name: "ErrInternal",
			req: &ssov1.RegisterRequest{
				Email:    dummyEmail,
				Username: dummy,
				Password: dummyPassword,
			},

			serviceResp:  models.User{},
			serviceError: authSvc.ErrInternal,

			expectedCode:  codes.Internal,
			expectedError: "internal service error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := authMocks.NewMockAuthService(t)

			if tc.serviceError != nil || (tc.expectedCode == codes.OK) {
				user := models.User{}
				if tc.expectedCode == codes.OK {
					user = sampleUser
				}

				mockAuth.EXPECT().RegisterUser(
					context.Background(),
					tc.req.Email,
					tc.req.Username,
					tc.req.Password,
				).Return(user, tc.serviceError)
			}

			srv := auth.NewAuthServer(mockAuth, time.Hour, 24*time.Hour)

			resp, err := srv.RegisterUser(context.Background(), tc.req)

			if tc.expectedCode != codes.OK {
				require.Error(t, err)

				st, ok := status.FromError(err)
				require.True(t, ok, "error should be a gRPC status")
				require.Equal(t, tc.expectedCode, st.Code())

				require.Contains(t, st.Message(), tc.expectedError)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedResp, resp)
		})
	}
}

func TestLogin(t *testing.T) {
	sampleUser := models.User{
		ID:       uuid.New(),
		Username: dummy,
		Email:    dummyEmail,
	}

	validAppID := int64(1)
	tokens := auth.TokenPair{
		AccessToken:  dummyAccessToken,
		RefreshToken: dummyRefreshToken,
	}

	cases := []struct {
		name string
		req  *ssov1.LoginRequest

		serviceUser  models.User
		serviceToken auth.TokenPair
		serviceError error

		expectedCode codes.Code
		expectedResp *ssov1.LoginResponse
		expectedErr  string
	}{
		{
			name: "Success",
			req: &ssov1.LoginRequest{
				Email:    dummyEmail,
				Password: dummyPassword,
				AppId:    validAppID,
			},

			serviceUser:  sampleUser,
			serviceToken: tokens,
			serviceError: nil,

			expectedCode: codes.OK,
			expectedResp: &ssov1.LoginResponse{
				UserId:                sampleUser.ID.String(),
				Username:              sampleUser.Username,
				Email:                 sampleUser.Email,
				AccessToken:           tokens.AccessToken,
				RefreshToken:          tokens.RefreshToken,
				AccessTokenExpiresIn:  int64(time.Hour / time.Second),
				RefreshTokenExpiresIn: int64(24 * time.Hour / time.Second),
			},
		},
		{
			name: "ErrEmptyEmail",
			req: &ssov1.LoginRequest{
				Email:    "",
				Password: dummyPassword,
				AppId:    validAppID,
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Email is required",
		},
		{
			name: "ErrInvalidEmail",
			req: &ssov1.LoginRequest{
				Email:    "not-an-email",
				Password: dummyPassword,
				AppId:    validAppID,
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Email must be valid",
		},
		{
			name: "ErrEmptyPassword",
			req: &ssov1.LoginRequest{
				Email:    dummyEmail,
				Password: "",
				AppId:    validAppID,
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Password is required",
		},
		{
			name: "ErrPasswordTooShort",
			req: &ssov1.LoginRequest{
				Email:    dummyEmail,
				Password: "short",
				AppId:    validAppID,
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Password must be at least 8 characters",
		},
		{
			name: "ErrPasswordTooLong",
			req: &ssov1.LoginRequest{
				Email:    dummyEmail,
				Password: "thispasswordiswaytoolong123",
				AppId:    validAppID,
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Password must be at most 16 characters",
		},
		{
			name: "ErrEmptyAppID",
			req: &ssov1.LoginRequest{
				Email:    dummyEmail,
				Password: dummyPassword,
				AppId:    0,
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "App ID is required",
		},
		{
			name: "ErrInvalidCredentials",
			req: &ssov1.LoginRequest{
				Email:    dummyEmail,
				Password: dummyPassword,
				AppId:    validAppID,
			},

			serviceError: repo.ErrUserNotFound,

			expectedCode: codes.Unauthenticated,
			expectedErr:  "invalid credentials",
		},
		{
			name: "ErrAppNotFound",
			req: &ssov1.LoginRequest{
				Email:    dummyEmail,
				Password: dummyPassword,
				AppId:    validAppID,
			},

			serviceError: repo.ErrAppNotFound,

			expectedCode: codes.NotFound,
			expectedErr:  "application not found",
		},
		{
			name: "ErrInternal",
			req: &ssov1.LoginRequest{
				Email:    dummyEmail,
				Password: dummyPassword,
				AppId:    validAppID,
			},

			serviceError: authSvc.ErrInternal,

			expectedCode: codes.Internal,
			expectedErr:  "internal service error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := authMocks.NewMockAuthService(t)

			if tc.serviceError != nil || (tc.expectedCode == codes.OK) {
				mockAuth.EXPECT().
					Login(
						context.Background(),
						tc.req.Email,
						tc.req.Password,
						tc.req.AppId,
					).
					Return(tc.serviceUser, tc.serviceToken, tc.serviceError)
			}

			srv := auth.NewAuthServer(mockAuth, time.Hour, 24*time.Hour)

			resp, err := srv.Login(context.Background(), tc.req)

			if tc.expectedCode != codes.OK {
				require.Error(t, err)

				st, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tc.expectedCode, st.Code())

				require.Contains(t, st.Message(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedResp, resp)
		})
	}
}

func TestLogout(t *testing.T) {
	validToken := dummyRefreshToken

	cases := []struct {
		name         string
		req          *ssov1.LogoutRequest
		serviceError error
		expectedCode codes.Code
		expectedErr  string
	}{
		{
			name: "Success",
			req: &ssov1.LogoutRequest{
				RefreshToken: validToken,
			},

			serviceError: nil,

			expectedCode: codes.OK,
		},
		{
			name: "ErrEmptyToken",
			req: &ssov1.LogoutRequest{
				RefreshToken: "",
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Refresh token is required",
		},
		{
			name: "ErrTokenNotFound",
			req: &ssov1.LogoutRequest{
				RefreshToken: validToken,
			},

			serviceError: repo.ErrTokenNotFound,

			expectedCode: codes.Unauthenticated,
			expectedErr:  "invalid or expired token",
		},
		{
			name: "ErrTokenExpired",
			req: &ssov1.LogoutRequest{
				RefreshToken: validToken,
			},

			serviceError: repo.ErrTokenExpired,

			expectedCode: codes.Unauthenticated,
			expectedErr:  "invalid or expired token",
		},
		{
			name: "ErrInternal",
			req: &ssov1.LogoutRequest{
				RefreshToken: validToken,
			},

			serviceError: authSvc.ErrInternal,

			expectedCode: codes.Internal,
			expectedErr:  "internal service error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := authMocks.NewMockAuthService(t)

			if tc.serviceError != nil || tc.expectedCode == codes.OK {
				mockAuth.EXPECT().
					Logout(context.Background(), tc.req.RefreshToken).
					Return(tc.serviceError)
			}

			srv := auth.NewAuthServer(mockAuth, time.Hour, 24*time.Hour)

			resp, err := srv.Logout(context.Background(), tc.req)

			if tc.expectedCode != codes.OK {
				require.Error(t, err)

				st, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tc.expectedCode, st.Code())

				require.Contains(t, st.Message(), tc.expectedErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, "logout successful", resp.Message)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	oldToken := "oldrefreshtoken"
	newTokens := auth.TokenPair{
		AccessToken:  dummyAccessToken,
		RefreshToken: dummyRefreshToken,
	}

	cases := []struct {
		name         string
		req          *ssov1.RefreshTokenRequest
		serviceToken auth.TokenPair
		serviceError error
		expectedCode codes.Code
		expectedResp *ssov1.RefreshTokenResponse
		expectedErr  string
	}{
		{
			name: "Success",
			req: &ssov1.RefreshTokenRequest{
				RefreshToken: oldToken,
			},

			serviceToken: newTokens,
			serviceError: nil,

			expectedCode: codes.OK,
			expectedResp: &ssov1.RefreshTokenResponse{
				AccessToken:           newTokens.AccessToken,
				RefreshToken:          newTokens.RefreshToken,
				AccessTokenExpiresIn:  int64(time.Hour / time.Second),
				RefreshTokenExpiresIn: int64(24 * time.Hour / time.Second),
			},
		},
		{
			name: "ErrEmptyToken",
			req: &ssov1.RefreshTokenRequest{
				RefreshToken: "",
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Refresh token is required",
		},
		{
			name: "ErrTokenNotFound",
			req: &ssov1.RefreshTokenRequest{
				RefreshToken: oldToken,
			},

			serviceError: repo.ErrTokenNotFound,

			expectedCode: codes.Unauthenticated,
			expectedErr:  "invalid or expired token",
		},
		{
			name: "ErrTokenExpired",
			req: &ssov1.RefreshTokenRequest{
				RefreshToken: oldToken,
			},

			serviceError: repo.ErrTokenExpired,

			expectedCode: codes.Unauthenticated,
			expectedErr:  "invalid or expired token",
		},
		{
			name: "ErrInternal",
			req: &ssov1.RefreshTokenRequest{
				RefreshToken: oldToken,
			},

			serviceError: authSvc.ErrInternal,

			expectedCode: codes.Internal,
			expectedErr:  "internal service error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := authMocks.NewMockAuthService(t)

			if tc.serviceError != nil || tc.expectedCode == codes.OK {
				mockAuth.EXPECT().
					UpdateToken(context.Background(), tc.req.RefreshToken).
					Return(tc.serviceToken, tc.serviceError)
			}

			srv := auth.NewAuthServer(mockAuth, time.Hour, 24*time.Hour)

			resp, err := srv.RefreshToken(context.Background(), tc.req)

			if tc.expectedCode != codes.OK {
				require.Error(t, err)

				st, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tc.expectedCode, st.Code())

				require.Contains(t, st.Message(), tc.expectedErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedResp, resp)
		})
	}
}

func TestRoleCheck(t *testing.T) {
	token := dummyRefreshToken
	validRole := "admin"

	cases := []struct {
		name string
		req  *ssov1.RoleCheckRequest

		servicePass  bool
		serviceError error

		expectedCode codes.Code
		expectedPass bool
		expectedErr  string
	}{
		{
			name: "SuccessHasRole",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: validRole,
			},

			servicePass:  true,
			serviceError: nil,

			expectedCode: codes.OK,
			expectedPass: true,
		},
		{
			name: "SuccessNoRole",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: validRole,
			},

			servicePass:  false,
			serviceError: nil,

			expectedCode: codes.OK,
			expectedPass: false,
		},
		{
			name: "ErrEmptyToken",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: "",
				RequiredRole: validRole,
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Refresh token is required",
		},
		{
			name: "ErrEmptyRole",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: "",
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Role is required",
		},
		{
			name: "ErrRoleTooShort",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: "a",
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Role must be at least 2 characters",
		},
		{
			name: "ErrRoleTooLong",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: "thisroleiswaytoolongandexceedsfiftycharacterslimit1234567890",
			},

			expectedCode: codes.InvalidArgument,
			expectedErr:  "Role must be at most 50 characters",
		},
		{
			name: "ErrTokenNotFound",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: validRole,
			},

			serviceError: repo.ErrTokenNotFound,

			expectedCode: codes.Unauthenticated,
			expectedErr:  "invalid or expired token",
		},
		{
			name: "ErrTokenExpired",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: validRole,
			},

			serviceError: repo.ErrTokenExpired,

			expectedCode: codes.Unauthenticated,
			expectedErr:  "invalid or expired token",
		},
		{
			name: "ErrForbidden",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: validRole,
			},

			serviceError: repo.ErrForbidden,

			expectedCode: codes.PermissionDenied,
			expectedErr:  "access denied",
		},
		{
			name: "ErrInternal",
			req: &ssov1.RoleCheckRequest{
				RefreshToken: token,
				RequiredRole: validRole,
			},

			serviceError: authSvc.ErrInternal,

			expectedCode: codes.Internal,
			expectedErr:  "internal service error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := authMocks.NewMockAuthService(t)

			if tc.serviceError != nil || tc.expectedCode == codes.OK {
				mockAuth.EXPECT().
					RoleCheck(context.Background(), tc.req.RefreshToken, tc.req.RequiredRole).
					Return(tc.servicePass, tc.serviceError)
			}

			srv := auth.NewAuthServer(mockAuth, time.Hour, 24*time.Hour)

			resp, err := srv.RoleCheck(context.Background(), tc.req)

			if tc.expectedCode != codes.OK {
				require.Error(t, err)

				st, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, tc.expectedCode, st.Code())

				require.Contains(t, st.Message(), tc.expectedErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedPass, resp.PassCheck)
		})
	}
}
