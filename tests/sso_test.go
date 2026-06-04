// Package tests contains integration tests for verifying the complete authentication flow.
//
// ⚠️ IMPORTANT FOR DEVELOPERS:
// Before running these tests, you must spin up the local environment via Docker Compose.
// The tests run on the host machine and strictly rely on the following local addresses:
//   - gRPC Application Server expects port: 50051 (localhost:50051)
//   - PostgreSQL Instance expects port: 5432 (localhost:5432)
//
// If you have modified the ports in your local .env file, make sure to update the constants below accordingly.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	ssov1 "github.com/n0f4ph4mst3r/TokenCraft/protos/gen/go/sso"
)

const grpcHost = "localhost:50051"
const dbURL = "postgres://postgres:test@localhost:5432/main?sslmode=disable"

func setupClient(t *testing.T) (*grpc.ClientConn, ssov1.AuthClient) {
	t.Helper()
	conn, err := grpc.NewClient(grpcHost, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	return conn, ssov1.NewAuthClient(conn)
}

func setupDB(t *testing.T) (*pgx.Conn, int64) {
	t.Helper()

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	require.NoError(t, err, "Failed to connect to database")

	err = conn.Ping(ctx)
	require.NoError(t, err, "Database ping failed - check credentials or port mapping")

	appName := "TestApp_" + gofakeit.Word() + gofakeit.LetterN(5)
	appSecret := gofakeit.Password(true, true, true, true, false, 16)

	var appID int64
	err = conn.QueryRow(ctx, "INSERT INTO apps (name, secret) VALUES ($1, $2) RETURNING id", appName, appSecret).Scan(&appID)
	require.NoError(t, err, "Failed to insert test app")

	_, err = conn.Exec(ctx, "INSERT INTO roles (name, app_id) VALUES ($1, $2)", "user", appID)
	require.NoError(t, err, "Failed to insert 'user' role")

	t.Cleanup(func() {
		_, err := conn.Exec(ctx, "DELETE FROM apps WHERE id = $1", appID)
		require.NoError(t, err, "Failed to cleanup test app")

		err = conn.Close(ctx)
		require.NoError(t, err, "Failed to close db connection")
	})

	return conn, appID
}

func TestAuth_FullFlow(t *testing.T) {
	connRPC, client := setupClient(t)
	defer connRPC.Close()

	dbConn, appID := setupDB(t)

	email := gofakeit.Email()
	pass := "StrongPass123!"
	user := gofakeit.Username()

	testCases := []struct {
		name        string
		email       string
		username    string
		password    string
		expectedErr string
	}{
		{
			name:     "Valid Registration",
			email:    email,
			username: user,
			password: pass,
		},
		{
			name:        "Empty Email",
			email:       "",
			username:    user,
			password:    pass,
			expectedErr: "Email is required",
		},
		{
			name:        "Empty Password",
			email:       gofakeit.Email(),
			username:    user,
			password:    "",
			expectedErr: "Password is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			t.Cleanup(func() {
				if tc.email != "" {
					_, _ = dbConn.Exec(context.Background(), "DELETE FROM users WHERE email = $1", tc.email)
				}
			})

			// 1. Register
			regResp, err := client.RegisterUser(ctx, &ssov1.RegisterRequest{
				Email:    tc.email,
				Username: tc.username,
				Password: tc.password,
			})

			if tc.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr)
				return
			}
			require.NoError(t, err)
			userID := regResp.GetUserId()

			var roleID int64
			err = dbConn.QueryRow(ctx, "SELECT id FROM roles WHERE app_id = $1 AND name = 'user'", appID).Scan(&roleID)
			require.NoError(t, err)

			_, err = dbConn.Exec(ctx, "INSERT INTO user_app_roles (user_id, app_id, role_id) VALUES ($1, $2, $3)", userID, appID, roleID)
			require.NoError(t, err, "Failed to assign 'user' role to user")

			// 2. Login
			loginResp, err := client.Login(ctx, &ssov1.LoginRequest{
				Email:    tc.email,
				Password: tc.password,
				AppId:    appID,
			})
			require.NoError(t, err, "Login failed - verify app exists and credentials match")

			refreshToken := loginResp.GetRefreshToken()

			// 3. RoleCheck
			roleResp, err := client.RoleCheck(ctx, &ssov1.RoleCheckRequest{
				RefreshToken: refreshToken,
				RequiredRole: "user",
			})

			require.NoError(t, err)
			require.NotNil(t, roleResp)
			require.True(t, roleResp.GetPassCheck(), "PassCheck should be true for role 'user'")

			// 4. Logout
			logoutResp, err := client.Logout(ctx, &ssov1.LogoutRequest{
				RefreshToken: refreshToken,
			})
			require.NoError(t, err)
			require.Equal(t, "logout successful", logoutResp.GetMessage())
		})
	}
}
