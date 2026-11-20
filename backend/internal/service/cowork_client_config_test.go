//go:build unit

package service

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
	"testing"
)

type coworkModelsAccountRepo struct {
	AccountRepository
	accounts []Account
	err      error
}

func (r coworkModelsAccountRepo) ListSchedulableByGroupID(context.Context, int64) ([]Account, error) {
	return r.accounts, r.err
}

func TestCoworkPortalClientScopeRequiresCompleteExplicitIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	svc := NewProvisioningService(db, nil, nil)
	identity := portalTestIdentity()
	for _, ids := range [][]int64{nil, {0}, {-1}, {11, 11}, make([]int64, 101)} {
		identity.APIKeyIDs = ids
		_, err := svc.PortalClientKeyIDs(context.Background(), identity)
		require.ErrorIs(t, err, ErrPortalInvalid)
	}
	identity.APIKeyIDs = []int64{11, 12}
	mock.ExpectQuery("SELECT k.id FROM api_keys k").WithArgs(int64(10), "{11,12}").WillReturnError(errors.New("unavailable"))
	_, err = svc.PortalClientKeyIDs(context.Background(), identity)
	require.ErrorIs(t, err, ErrPortalUnavailable)
	mock.ExpectQuery("SELECT k.id FROM api_keys k").WithArgs(int64(10), "{11,12}").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(12))
	ids, err := svc.PortalClientKeyIDs(context.Background(), identity)
	require.NoError(t, err)
	require.Equal(t, []int64{12}, ids)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCoworkPortalModelsUseLiveAccountAdmissionAndExpandWildcard(t *testing.T) {
	ctx := context.Background()
	svc := &GatewayService{accountRepo: coworkModelsAccountRepo{err: errors.New("read failure")}}
	_, err := svc.DiscoverCoworkModels(ctx, 101, PlatformOpenAI, []string{"gpt-test"})
	require.ErrorIs(t, err, ErrPortalUnavailable)
	svc.accountRepo = coworkModelsAccountRepo{}
	models, err := svc.DiscoverCoworkModels(ctx, 101, PlatformOpenAI, []string{"gpt-test"})
	require.NoError(t, err)
	require.Empty(t, models)
	svc.accountRepo = coworkModelsAccountRepo{accounts: []Account{
		{Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{"model_mapping": map[string]any{"gpt-*": "gpt-*", "custom": "upstream"}}},
		{Platform: PlatformGemini, Type: AccountTypeAPIKey},
	}}
	models, err = svc.DiscoverCoworkModels(ctx, 101, PlatformOpenAI, []string{"gpt-test", "foreign", "gpt-*"})
	require.NoError(t, err)
	require.Equal(t, []string{"custom", "gpt-test"}, models)
}
