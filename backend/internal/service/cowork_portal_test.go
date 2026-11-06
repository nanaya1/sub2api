//go:build unit

package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

func portalTestIdentity() CoworkPortalIdentity {
	return CoworkPortalIdentity{Source: "cowork", ExternalUserID: "7", TenantKey: "8", ExternalGroupID: "9", UserID: 10}
}

func TestCoworkPortalIdentityAndKeyIsolation(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	svc := NewProvisioningService(db, nil, nil)
	identity := portalTestIdentity()
	mock.ExpectQuery("FROM provisioning_user_bindings").WithArgs("cowork", "7").WillReturnError(sql.ErrNoRows)
	require.ErrorIs(t, svc.ResolvePortalIdentity(context.Background(), &identity), ErrPortalNotReady)
	mock.ExpectQuery("FROM api_keys k").WithArgs(int64(11), int64(10), "cowork", "8").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	require.ErrorIs(t, svc.PortalOwnsKey(context.Background(), identity, 11), ErrPortalNotFound)
	mock.ExpectQuery("FROM provisioning_group_bindings").WithArgs("cowork", "8", "9", int64(10)).WillReturnError(sql.ErrNoRows)
	_, err = svc.PortalCurrentGroup(context.Background(), identity)
	require.ErrorIs(t, err, ErrPortalNotReady)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCoworkPortalClaimNeverReplaysUnknownOrChangedRequest(t *testing.T) {
	for _, status := range []string{"PENDING", "UNCONFIRMED", "COMPLETED", "REJECTED", "changed"} {
		t.Run(status, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			svc := NewProvisioningService(db, nil, nil)
			identity := portalTestIdentity()
			requestID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			mock.ExpectQuery("INSERT INTO cowork_portal_operations").WithArgs("cowork", "7", "key.add", requestID, sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"request_id"}).AddRow(requestID))
			owner, _, err := svc.ClaimPortalOperation(context.Background(), identity, "key.add", requestID, map[string]string{"name": "key"})
			require.NoError(t, err)
			require.True(t, owner)
			// 摘要取自真实规范序列化，重复领取只查已有状态
			raw, _ := json.Marshal(map[string]string{"name": "key"})
			digest := sha256.Sum256(raw)
			fingerprint := hex.EncodeToString(digest[:])
			if status == "changed" {
				fingerprint = "different"
			}
			mock.ExpectQuery("INSERT INTO cowork_portal_operations").WillReturnError(sql.ErrNoRows)
			mock.ExpectQuery("SELECT fingerprint, status").WithArgs("cowork", "7", "key.add", requestID).WillReturnRows(sqlmock.NewRows([]string{"fingerprint", "status", "resource_id", "payment_result"}).AddRow(fingerprint, status, 11, nil))
			owner, result, err := svc.ClaimPortalOperation(context.Background(), identity, "key.add", requestID, map[string]string{"name": "key"})
			require.False(t, owner)
			switch status {
			case "changed":
				require.ErrorIs(t, err, ErrPortalConflict)
			case "COMPLETED":
				require.NoError(t, err)
				require.Equal(t, int64(11), *result.ResourceID)
			case "REJECTED":
				require.ErrorIs(t, err, ErrPortalRejected)
			default:
				require.ErrorIs(t, err, ErrPortalUnconfirmed)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestCoworkPortalCompletionCannotOverwriteTerminalState(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	svc := NewProvisioningService(db, nil, nil)
	mock.ExpectExec("UPDATE cowork_portal_operations SET status = 'COMPLETED'").WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, svc.CompletePortalOperation(context.Background(), portalTestIdentity(), "key.add", "a", 11, nil), ErrPortalUnconfirmed)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCoworkPortalKnownRejectionIsExplicit(t *testing.T) {
	require.True(t, PortalKnownRejection("recharge.add", infraerrors.BadRequest("INVALID_AMOUNT", "ignored")))
	require.True(t, PortalKnownRejection("recharge.redeem", ErrRedeemRateLimited))
	require.False(t, PortalKnownRejection("recharge.add", infraerrors.BadRequest("PAYMENT_GATEWAY_ERROR", "ignored")))
	require.False(t, PortalKnownRejection("key.add", errors.New("commit outcome unknown")))
}

func TestCoworkPortalBalanceRedeemKeepsFailureCounter(t *testing.T) {
	cache := &redeemRateLimitCacheStub{}
	svc := &RedeemService{redeemRepo: &redeemRejectRepo{code: RedeemCode{Code: "subscription", Type: RedeemTypeSubscription, Status: StatusUnused}}, cache: cache}
	_, err := svc.RedeemBalanceForPortal(context.Background(), 42, "subscription")
	require.Equal(t, "REDEEM_CODE_UNSUPPORTED_TYPE", infraerrors.Reason(err))
	require.Equal(t, 1, cache.incrementCalls)
	_, err = svc.RedeemBalanceForPortal(context.Background(), 42, "missing")
	require.ErrorIs(t, err, ErrRedeemCodeNotFound)
	require.Equal(t, 2, cache.incrementCalls)
}
