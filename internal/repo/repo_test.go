package repo_test

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/config"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo"
	cacheMocks "github.com/n0f4ph4mst3r/TokenCraft/internal/repo/mocks/cache"
	dbMocks "github.com/n0f4ph4mst3r/TokenCraft/internal/repo/mocks/storage"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	dummy         = "Dummy"
	dummyEmail    = "dummy@gmail.com"
	dummyPassword = "securePass123"
)

var internalDbErr = errors.New("internal db error")

const (
	cacheVersion = "v1"
	cachePrefix  = "test"
)

func TestUserById(t *testing.T) {
	testUser := models.User{
		ID:       uuid.New(),
		Email:    dummyEmail,
		Username: dummy,
	}

	cases := []struct {
		name string

		setupDB    func(db *dbMocks.MockDbProvider, id uuid.UUID)
		setupCache func(c *cacheMocks.MockCacheProvider, key string)

		expectedResponse models.User
		expectedErr      error
	}{
		{
			name: "SuccessCacheHit",

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.MatchedBy(func(u *models.User) bool { return true })).
					Run(func(args mock.Arguments) {
						ptr := args.Get(2).(*models.User)
						*ptr = testUser
					}).
					Return(true, nil).
					Once()
			},

			expectedResponse: testUser,
		},
		{
			name: "SuccessCacheMiss",

			setupDB: func(db *dbMocks.MockDbProvider, id uuid.UUID) {
				db.On("UserById", mock.Anything, id).
					Return(testUser, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.MatchedBy(func(u *models.User) bool { return true })).
					Return(false, nil).
					Once()

				c.On("Set", mock.Anything, key, testUser, mock.Anything).
					Return(nil).
					Once()
			},

			expectedResponse: testUser,
		},
		{
			name: "ErrCacheGetFallbackToDB",

			setupDB: func(db *dbMocks.MockDbProvider, id uuid.UUID) {
				db.On("UserById", mock.Anything, id).
					Return(testUser, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.MatchedBy(func(u *models.User) bool { return true })).
					Return(false, errors.New("redis down")).
					Once()

				c.On("Set", mock.Anything, key, testUser, mock.Anything).
					Return(nil).
					Once()
			},

			expectedResponse: testUser,
		},
		{
			name: "ErrCacheSetIgnored",

			setupDB: func(db *dbMocks.MockDbProvider, id uuid.UUID) {
				db.On("UserById", mock.Anything, id).
					Return(testUser, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.MatchedBy(func(u *models.User) bool { return true })).
					Return(false, nil).
					Once()

				c.On("Set", mock.Anything, key, testUser, mock.Anything).
					Return(errors.New("set error")).
					Once()
			},

			expectedResponse: testUser,
		},
		{
			name: "ErrUserNotFound",

			setupDB: func(db *dbMocks.MockDbProvider, id uuid.UUID) {
				db.On("UserById", mock.Anything, id).
					Return(models.User{}, repo.ErrUserNotFound).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.MatchedBy(func(u *models.User) bool { return true })).
					Return(false, nil).
					Once()
			},

			expectedErr: repo.ErrUserNotFound,
		},
		{
			name: "ErrDbInternal",

			setupDB: func(db *dbMocks.MockDbProvider, id uuid.UUID) {
				db.On("UserById", mock.Anything, id).
					Return(models.User{}, internalDbErr).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.MatchedBy(func(u *models.User) bool { return true })).
					Return(false, nil).
					Once()
			},

			expectedErr: internalDbErr,
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := dbMocks.NewMockDbProvider(t)
			cache := cacheMocks.NewMockCacheProvider(t)

			if tc.setupDB != nil {
				tc.setupDB(db, testUser.ID)
			}

			if tc.setupCache != nil {
				tc.setupCache(cache, key(cachePrefix, cacheVersion, "user", "id", testUser.ID.String()))
			}

			r := repo.NewRepo(
				slog.Default(),
				db,
				cache,
				&config.CacheConfig{
					Prefix:  cachePrefix,
					Version: cacheVersion,
					TTL:     time.Minute,
				},
			)

			user, err := r.UserById(context.Background(), testUser.ID)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedResponse, user)
		})
	}
}

func TestUserByEmail(t *testing.T) {
	testUser := models.User{
		ID:       uuid.New(),
		Email:    dummyEmail,
		Username: dummy,
	}

	cases := []struct {
		name string

		setupDB    func(db *dbMocks.MockDbProvider, email string)
		setupCache func(c *cacheMocks.MockCacheProvider, key string)

		expectedResponse models.User
		expectedErr      error
	}{
		{
			name: "SuccessCacheHit",

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get",
					mock.Anything,
					key,
					mock.AnythingOfType("*models.User"),
				).
					Run(func(args mock.Arguments) {
						ptr := args.Get(2).(*models.User)
						*ptr = testUser
					}).
					Return(true, nil).
					Once()
			},

			expectedResponse: testUser,
		},
		{
			name: "SuccessCacheMiss",

			setupDB: func(db *dbMocks.MockDbProvider, email string) {
				db.On("UserByEmail", mock.Anything, email).
					Return(testUser, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()

				c.On("Set", mock.Anything, key, testUser, mock.Anything).
					Return(nil).
					Once()
			},

			expectedResponse: testUser,
		},
		{
			name: "ErrCacheGetFallbackToDB",

			setupDB: func(db *dbMocks.MockDbProvider, email string) {
				db.On("UserByEmail", mock.Anything, email).
					Return(testUser, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, errors.New("redis down")).
					Once()

				c.On("Set", mock.Anything, key, testUser, mock.Anything).
					Return(nil).
					Once()
			},

			expectedResponse: testUser,
		},
		{
			name: "ErrCacheSetIgnored",

			setupDB: func(db *dbMocks.MockDbProvider, email string) {
				db.On("UserByEmail", mock.Anything, email).
					Return(testUser, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()

				c.On("Set", mock.Anything, key, testUser, mock.Anything).
					Return(errors.New("set error")).
					Once()
			},

			expectedResponse: testUser,
		},
		{
			name: "ErrUserNotFound",

			setupDB: func(db *dbMocks.MockDbProvider, email string) {
				db.On("UserByEmail", mock.Anything, email).
					Return(models.User{}, repo.ErrUserNotFound).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: repo.ErrUserNotFound,
		},
		{
			name: "ErrDbInternal",

			setupDB: func(db *dbMocks.MockDbProvider, email string) {
				db.On("UserByEmail", mock.Anything, email).
					Return(models.User{}, internalDbErr).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: internalDbErr,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := dbMocks.NewMockDbProvider(t)
			cache := cacheMocks.NewMockCacheProvider(t)

			if tc.setupDB != nil {
				tc.setupDB(db, testUser.Email)
			}
			if tc.setupCache != nil {
				tc.setupCache(cache, key(cachePrefix, cacheVersion, "user", "email", testUser.Email))
			}

			r := repo.NewRepo(
				slog.Default(),
				db,
				cache,
				&config.CacheConfig{
					Prefix:  cachePrefix,
					Version: cacheVersion,
					TTL:     time.Minute,
				},
			)

			user, err := r.UserByEmail(context.Background(), testUser.Email)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedResponse, user)
		})
	}
}

func TestRegisterUser(t *testing.T) {
	testUser := models.User{
		ID:       uuid.New(),
		Email:    dummyEmail,
		Username: dummy,
	}

	cases := []struct {
		name string

		email        string
		username     string
		hashPassword []byte

		setupDB    func(db *dbMocks.MockDbProvider, email string, username string, hashPassword []byte)
		setupCache func(c *cacheMocks.MockCacheProvider, idKey, emailKey string)

		expectedUser models.User
		expectedErr  error
	}{
		{
			name: "Success",

			email:        dummyEmail,
			username:     dummy,
			hashPassword: []byte(dummyPassword),

			setupDB: func(db *dbMocks.MockDbProvider, email string, username string, hashPassword []byte) {
				db.On("RegisterUser", mock.Anything, email, username, hashPassword).
					Return(testUser, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, idKey, emailKey string) {
				c.On("Del", mock.Anything, []string{idKey, emailKey}).
					Return(nil).
					Once()
			},

			expectedUser: testUser,
		},
		{
			name: "SuccessCacheDelErrorIgnored",

			email:        dummyEmail,
			username:     dummy,
			hashPassword: []byte(dummyPassword),

			setupDB: func(db *dbMocks.MockDbProvider, email string, username string, hashPassword []byte) {
				db.On("RegisterUser", mock.Anything, email, username, hashPassword).
					Return(testUser, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, idKey, emailKey string) {
				c.On("Del", mock.Anything, []string{idKey, emailKey}).
					Return(errors.New("redis del error")).
					Once()
			},

			expectedUser: testUser,
		},
		{
			name: "ErrUserExists",

			email:        "existingemail@gmail.com",
			username:     "existingUser",
			hashPassword: []byte(dummyPassword),

			setupDB: func(db *dbMocks.MockDbProvider, email string, username string, hashPassword []byte) {
				db.On("RegisterUser", mock.Anything, email, username, hashPassword).
					Return(models.User{}, repo.ErrUserExists).
					Once()
			},

			expectedErr: repo.ErrUserExists,
		},
		{
			name: "ErrDbInternal",
			setupDB: func(db *dbMocks.MockDbProvider, email string, username string, hashPassword []byte) {
				db.On("RegisterUser", mock.Anything, email, username, hashPassword).
					Return(models.User{}, internalDbErr).
					Once()
			},

			expectedErr: internalDbErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := dbMocks.NewMockDbProvider(t)
			cache := cacheMocks.NewMockCacheProvider(t)

			if tc.setupDB != nil {
				tc.setupDB(db, tc.email, tc.username, tc.hashPassword)
			}

			idKey := key(cachePrefix, cacheVersion, "user", "id", testUser.ID.String())
			emailKey := key(cachePrefix, cacheVersion, "user", "email", testUser.Email)
			if tc.setupCache != nil {
				tc.setupCache(cache, idKey, emailKey)
			}

			r := repo.NewRepo(
				slog.Default(),
				db,
				cache,
				&config.CacheConfig{
					Prefix:  cachePrefix,
					Version: cacheVersion,
					TTL:     time.Minute,
				},
			)

			user, err := r.RegisterUser(context.Background(), tc.email, tc.username, tc.hashPassword)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedUser, user)
		})
	}
}

func TestRoleCheck(t *testing.T) {
	userID := uuid.New()
	appID := int64(1)

	testToken := models.Token{
		UserID:    userID,
		AppID:     appID,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	roles := []string{"user", "admin"}

	cases := []struct {
		name string

		requiredRole string
		tokenHash    string

		setupDB    func(db *dbMocks.MockDbProvider, tokenHash string)
		setupCache func(c *cacheMocks.MockCacheProvider, tokenKey, rolesKey string)

		expectedErr error
	}{
		{
			name: "SuccessCacheHitTokenAndRoles",

			requiredRole: "admin",
			tokenHash:    "test_token_hash",

			setupCache: func(c *cacheMocks.MockCacheProvider, tokenKey, rolesKey string) {
				c.On("Get", mock.Anything, tokenKey, mock.MatchedBy(func(t *models.Token) bool { return true })).
					Run(func(args mock.Arguments) {
						ptr := args.Get(2).(*models.Token)
						*ptr = testToken
					}).
					Return(true, nil).
					Once()

				c.On("Get", mock.Anything, rolesKey, mock.MatchedBy(func(r *[]string) bool { return true })).
					Run(func(args mock.Arguments) {
						ptr := args.Get(2).(*[]string)
						*ptr = roles
					}).
					Return(true, nil).
					Once()
			},
		},
		{
			name: "SuccessCacheMissTokenAndRoles",

			requiredRole: "admin",
			tokenHash:    "test_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(testToken, nil).
					Once()
				db.On("GetUserRoles", mock.Anything, userID, appID).
					Return(roles, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, tokenKey, rolesKey string) {
				c.On("Get", mock.Anything, tokenKey, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, tokenKey, testToken, mock.Anything).
					Return(nil).
					Once()

				c.On("Get", mock.Anything, rolesKey, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, rolesKey, roles, 5*time.Minute).
					Return(nil).
					Once()
			},
		},
		{
			name: "ErrTokenNotFound",

			requiredRole: "admin",
			tokenHash:    "unknown_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(models.Token{}, repo.ErrTokenNotFound).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, tokenKey, rolesKey string) {
				c.On("Get", mock.Anything, tokenKey, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: repo.ErrTokenNotFound,
		},
		{
			name: "ErrForbiddenRoleMissing",

			requiredRole: "admin",
			tokenHash:    "forbidden_user_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(testToken, nil).
					Once()
				db.On("GetUserRoles", mock.Anything, userID, appID).
					Return([]string{"user"}, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, tokenKey, rolesKey string) {
				c.On("Get", mock.Anything, tokenKey, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, tokenKey, testToken, mock.Anything).
					Return(nil).
					Once()

				c.On("Get", mock.Anything, rolesKey, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, rolesKey, []string{"user"}, 5*time.Minute).
					Return(nil).
					Once()
			},

			expectedErr: repo.ErrForbidden,
		},
		{
			name: "ErrGetUserRolesDbError",

			requiredRole: "admin",
			tokenHash:    "wrong_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(testToken, nil).
					Once()
				db.On("GetUserRoles", mock.Anything, userID, appID).
					Return(nil, internalDbErr).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, tokenKey, rolesKey string) {
				c.On("Get", mock.Anything, tokenKey, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, tokenKey, testToken, mock.Anything).
					Return(nil).
					Once()

				c.On("Get", mock.Anything, rolesKey, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: internalDbErr,
		},
		{
			name:         "ErrGetTokenDbError",
			requiredRole: "admin",
			tokenHash:    "test_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(models.Token{}, internalDbErr).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, tokenKey, rolesKey string) {
				c.On("Get", mock.Anything, tokenKey, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: internalDbErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := dbMocks.NewMockDbProvider(t)
			cache := cacheMocks.NewMockCacheProvider(t)

			if tc.setupDB != nil {
				tc.setupDB(db, tc.tokenHash)
			}

			tokenKey := key(cachePrefix, cacheVersion, "token", tc.tokenHash)
			rolesKey := key(cachePrefix, cacheVersion, "roles", userID.String(), strconv.FormatInt(appID, 10))
			if tc.setupCache != nil {
				tc.setupCache(cache, tokenKey, rolesKey)
			}

			r := repo.NewRepo(
				slog.Default(),
				db,
				cache,
				&config.CacheConfig{
					Prefix:  cachePrefix,
					Version: cacheVersion,
					TTL:     time.Minute,
				},
			)

			err := r.RoleCheck(context.Background(), tc.tokenHash, tc.requiredRole)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAppById(t *testing.T) {
	testApp := models.App{
		ID:     1,
		Name:   "TestApp",
		Secret: "app_secret",
	}

	cases := []struct {
		name string

		setupDB    func(db *dbMocks.MockDbProvider, id int64)
		setupCache func(c *cacheMocks.MockCacheProvider, key string)

		expectedApp models.App
		expectedErr error
	}{
		{
			name: "SuccessCacheHit",

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.MatchedBy(func(a *models.App) bool { return true })).
					Run(func(args mock.Arguments) {
						ptr := args.Get(2).(*models.App)
						*ptr = testApp
					}).
					Return(true, nil).
					Once()
			},

			expectedApp: testApp,
		},
		{
			name: "SuccessCacheMiss",

			setupDB: func(db *dbMocks.MockDbProvider, id int64) {
				db.On("AppById", mock.Anything, id).
					Return(testApp, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, key, testApp, mock.Anything).
					Return(nil).
					Once()
			},

			expectedApp: testApp,
		},
		{
			name: "ErrCacheGetFallbackToDB",

			setupDB: func(db *dbMocks.MockDbProvider, id int64) {
				db.On("AppById", mock.Anything, id).
					Return(testApp, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, errors.New("redis down")).
					Once()
				c.On("Set", mock.Anything, key, testApp, mock.Anything).
					Return(nil).
					Once()
			},

			expectedApp: testApp,
		},
		{
			name: "ErrCacheSetIgnored",

			setupDB: func(db *dbMocks.MockDbProvider, id int64) {
				db.On("AppById", mock.Anything, id).
					Return(testApp, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, key, testApp, mock.Anything).
					Return(errors.New("set error")).
					Once()
			},

			expectedApp: testApp,
		},
		{
			name: "ErrAppNotFound",

			setupDB: func(db *dbMocks.MockDbProvider, id int64) {
				db.On("AppById", mock.Anything, id).
					Return(models.App{}, repo.ErrAppNotFound).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: repo.ErrAppNotFound,
		},
		{
			name: "ErrDbInternal",

			setupDB: func(db *dbMocks.MockDbProvider, id int64) {
				db.On("AppById", mock.Anything, id).
					Return(models.App{}, internalDbErr).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: internalDbErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := dbMocks.NewMockDbProvider(t)
			cache := cacheMocks.NewMockCacheProvider(t)

			if tc.setupDB != nil {
				tc.setupDB(db, testApp.ID)
			}

			if tc.setupCache != nil {
				tc.setupCache(cache, key(cachePrefix, cacheVersion, "app", strconv.FormatInt(testApp.ID, 10)))
			}

			r := repo.NewRepo(
				slog.Default(),
				db,
				cache,
				&config.CacheConfig{
					Prefix:  cachePrefix,
					Version: cacheVersion,
					TTL:     time.Minute,
				},
			)

			app, err := r.AppById(context.Background(), testApp.ID)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedApp, app)
		})
	}
}

func TestSaveToken(t *testing.T) {
	userID := uuid.New()
	appID := int64(1)

	tokenHash := "some_token_hash"
	expiresAt := time.Now().Add(time.Hour)

	testToken := models.Token{
		UserID:    userID,
		AppID:     appID,
		ExpiresAt: expiresAt,
	}

	cases := []struct {
		name string

		setupDB    func(db *dbMocks.MockDbProvider)
		setupCache func(c *cacheMocks.MockCacheProvider, key string)

		expectedErr error
	}{
		{
			name: "Success",

			setupDB: func(db *dbMocks.MockDbProvider) {
				db.On("SaveToken", mock.Anything, userID, appID, tokenHash, expiresAt).
					Return(nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Set", mock.Anything, key, testToken, mock.Anything).
					Return(nil).
					Once()
			},
		},
		{
			name: "SuccessCacheSetErrorIgnored",

			setupDB: func(db *dbMocks.MockDbProvider) {
				db.On("SaveToken", mock.Anything, userID, appID, tokenHash, expiresAt).
					Return(nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Set", mock.Anything, key, testToken, mock.Anything).
					Return(errors.New("redis set error")).
					Once()
			},
		},
		{
			name: "ErrDbInternal",

			setupDB: func(db *dbMocks.MockDbProvider) {
				db.On("SaveToken", mock.Anything, userID, appID, tokenHash, expiresAt).
					Return(internalDbErr).
					Once()
			},

			expectedErr: internalDbErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := dbMocks.NewMockDbProvider(t)
			cache := cacheMocks.NewMockCacheProvider(t)

			if tc.setupDB != nil {
				tc.setupDB(db)
			}

			tokenKey := key(cachePrefix, cacheVersion, "token", tokenHash)
			if tc.setupCache != nil {
				tc.setupCache(cache, tokenKey)
			}

			r := repo.NewRepo(
				slog.Default(),
				db,
				cache,
				&config.CacheConfig{
					Prefix:  cachePrefix,
					Version: cacheVersion,
					TTL:     time.Minute,
				},
			)

			err := r.SaveToken(context.Background(), userID, appID, tokenHash, expiresAt)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestGetToken(t *testing.T) {
	testToken := models.Token{
		UserID:    uuid.New(),
		AppID:     1,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	cases := []struct {
		name string

		tokenHash string

		setupDB    func(db *dbMocks.MockDbProvider, tokenHash string)
		setupCache func(c *cacheMocks.MockCacheProvider, key string)

		expectedToken models.Token
		expectedErr   error
	}{
		{
			name: "SuccessCacheHit",

			tokenHash: "some_token_hash",

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.MatchedBy(func(t *models.Token) bool { return true })).
					Run(func(args mock.Arguments) {
						ptr := args.Get(2).(*models.Token)
						*ptr = testToken
					}).
					Return(true, nil).
					Once()
			},

			expectedToken: testToken,
		},
		{
			name: "SuccessCacheMiss",

			tokenHash: "some_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(testToken, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, key, testToken, mock.Anything).
					Return(nil).
					Once()
			},

			expectedToken: testToken,
		},
		{
			name: "ErrCacheGetFallbackToDB",

			tokenHash: "some_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(testToken, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, errors.New("redis down")).
					Once()
				c.On("Set", mock.Anything, key, testToken, mock.Anything).
					Return(nil).
					Once()
			},

			expectedToken: testToken,
		},
		{
			name: "ErrCacheSetIgnored",

			tokenHash: "some_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(testToken, nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
				c.On("Set", mock.Anything, key, testToken, mock.Anything).
					Return(errors.New("set error")).
					Once()
			},

			expectedToken: testToken,
		},
		{
			name: "ErrTokenNotFound",

			tokenHash: "unknown_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(models.Token{}, repo.ErrTokenNotFound).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: repo.ErrTokenNotFound,
		},
		{
			name: "ErrDbInternal",

			tokenHash: "some_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("GetToken", mock.Anything, tokenHash).
					Return(models.Token{}, internalDbErr).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Get", mock.Anything, key, mock.Anything).
					Return(false, nil).
					Once()
			},

			expectedErr: internalDbErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := dbMocks.NewMockDbProvider(t)
			cache := cacheMocks.NewMockCacheProvider(t)

			if tc.setupDB != nil {
				tc.setupDB(db, tc.tokenHash)
			}

			tokenKey := key(cachePrefix, cacheVersion, "token", tc.tokenHash)
			if tc.setupCache != nil {
				tc.setupCache(cache, tokenKey)
			}

			r := repo.NewRepo(
				slog.Default(),
				db,
				cache,
				&config.CacheConfig{
					Prefix:  cachePrefix,
					Version: cacheVersion,
					TTL:     time.Minute,
				},
			)

			token, err := r.GetToken(context.Background(), tc.tokenHash)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expectedToken, token)
		})
	}
}

func TestRemoveToken(t *testing.T) {
	cases := []struct {
		name string

		tokenHash string

		setupDB    func(db *dbMocks.MockDbProvider, tokenHash string)
		setupCache func(c *cacheMocks.MockCacheProvider, key string)

		expectedErr error
	}{
		{
			name: "Success",

			tokenHash: "some_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("RemoveToken", mock.Anything, tokenHash).
					Return(nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Del", mock.Anything, []string{key}).
					Return(nil).
					Once()
			},
		},
		{
			name: "SuccessCacheDelErrorIgnored",

			tokenHash: "some_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("RemoveToken", mock.Anything, tokenHash).
					Return(nil).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Del", mock.Anything, []string{key}).
					Return(errors.New("redis del error")).
					Once()
			},
		},
		{
			name: "ErrTokenNotFound",

			tokenHash: "unknown_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("RemoveToken", mock.Anything, tokenHash).
					Return(repo.ErrTokenNotFound).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Del", mock.Anything, []string{key}).
					Return(nil).
					Once()
			},

			expectedErr: repo.ErrTokenNotFound,
		},
		{
			name: "ErrDbInternal",

			tokenHash: "some_token_hash",

			setupDB: func(db *dbMocks.MockDbProvider, tokenHash string) {
				db.On("RemoveToken", mock.Anything, tokenHash).
					Return(internalDbErr).
					Once()
			},

			setupCache: func(c *cacheMocks.MockCacheProvider, key string) {
				c.On("Del", mock.Anything, []string{key}).
					Return(nil).
					Once()
			},

			expectedErr: internalDbErr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := dbMocks.NewMockDbProvider(t)
			cache := cacheMocks.NewMockCacheProvider(t)

			if tc.setupDB != nil {
				tc.setupDB(db, tc.tokenHash)
			}

			tokenKey := key(cachePrefix, cacheVersion, "token", tc.tokenHash)
			if tc.setupCache != nil {
				tc.setupCache(cache, tokenKey)
			}

			r := repo.NewRepo(
				slog.Default(),
				db,
				cache,
				&config.CacheConfig{
					Prefix:  cachePrefix,
					Version: cacheVersion,
					TTL:     time.Minute,
				},
			)

			err := r.RemoveToken(context.Background(), tc.tokenHash)

			if tc.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func key(parts ...string) string {
	all := []string{}
	all = append(all, parts...)
	return strings.Join(all, ":")
}
