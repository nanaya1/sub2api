//go:build unit

package service

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/payment"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

// TestPaymentSandboxDatabase 只使用显式指定的全新回环临时库，不连接商户或真实支付
func TestPaymentSandboxDatabase(t *testing.T) {
	dsn := os.Getenv("PAYMENT_SANDBOX_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable payment sandbox database")
	}
	address, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", address.Hostname())
	require.True(t, strings.HasPrefix(strings.TrimPrefix(address.Path, "/"), "alipay_test_"))
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var existing int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&existing))
	require.Zero(t, existing, "只允许全新临时数据库")
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer client.Close()
	require.NoError(t, client.Schema.Create(ctx))
	migration, err := migrations.FS.ReadFile("243_cowork_portal_operations.sql")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, string(migration))
	require.NoError(t, err)
	ensurePaymentAuditOrderActionUniqueIndex(t, ctx, client)
	user, err := client.User.Create().SetEmail("pg@test.local").SetPasswordHash("controlled").Save(ctx)
	require.NoError(t, err)
	order := sandboxTestOrder(t, client, user.ID, "postgres")

	t.Run("cross_replica_check_rate_limit", func(t *testing.T) {
		var accepted atomic.Int64
		var workers sync.WaitGroup
		for i := 0; i < 8; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				svc := &PaymentService{entClient: client}
				if svc.claimPortalPaymentCheck(ctx, order.ID, user.ID) == nil {
					accepted.Add(1)
				}
			}()
		}
		workers.Wait()
		require.EqualValues(t, 1, accepted.Load())
	})

	t.Run("notification_and_query_credit_once", func(t *testing.T) {
		instance, err := client.PaymentProviderInstance.Create().SetName("controlled sandbox").SetProviderKey(payment.TypeAlipay).
			SetConfig(`{"environment":"sandbox","appId":"app","sellerId":"seller"}`).SetSupportedTypes("alipay").Save(ctx)
		require.NoError(t, err)
		snapshot := buildPaymentOrderProviderSnapshot(&payment.InstanceSelection{InstanceID: fmt.Sprint(instance.ID), ProviderKey: payment.TypeAlipay,
			Config: map[string]string{"environment": "sandbox", "appId": "app", "sellerId": "seller"}}, CreateOrderRequest{})
		order, err = client.PaymentOrder.UpdateOneID(order.ID).SetProviderInstanceID(fmt.Sprint(instance.ID)).SetProviderSnapshot(snapshot).Save(ctx)
		require.NoError(t, err)
		var credits atomic.Int64
		repo := &mockUserRepo{getByIDUser: &User{ID: user.ID, Email: user.Email}}
		repo.updateBalanceFn = func(ctx context.Context, id int64, amount float64) error {
			credits.Add(1)
			_, err := client.User.UpdateOneID(id).AddBalance(amount).Save(ctx)
			return err
		}
		redeemRepo := &paymentFulfillmentRedeemRepo{}
		redeemService := NewRedeemService(redeemRepo, repo, nil, nil, nil, client, nil, nil)
		svc := &PaymentService{entClient: client, userRepo: repo, redeemService: redeemService, registry: payment.NewRegistry(), configService: &PaymentConfigService{environment: payment.EnvironmentSandbox}}
		var workers sync.WaitGroup
		for i := 0; i < 8; i++ {
			workers.Add(1)
			go func(index int) {
				defer workers.Done()
				metadata := map[string]string{"confirmation_source": "notification", "app_id": "app", "seller_id": "seller", "out_trade_no": order.OutTradeNo, "total_amount": "10.00", "payment_environment": "sandbox"}
				if index%2 == 0 {
					metadata["confirmation_source"] = "query"
					metadata["authenticated_app_id"] = "app"
					delete(metadata, "app_id")
					delete(metadata, "seller_id")
				}
				err := svc.HandlePaymentNotification(ctx, &payment.PaymentNotification{OrderID: order.OutTradeNo, TradeNo: "verified-trade", Amount: 10, Status: payment.NotificationStatusSuccess, Metadata: metadata}, payment.TypeAlipay)
				// 其他领取者尚在履约时返回明确冲突，通知稍后重试；不能再次领取并入账
				if err != nil && infraerrors.Reason(err) != "CONFLICT" {
					t.Errorf("payment confirmation failed: %v", err)
				}
			}(i)
		}
		workers.Wait()
		require.EqualValues(t, 1, credits.Load())
		current, err := client.PaymentOrder.Get(ctx, order.ID)
		require.NoError(t, err)
		require.Equal(t, OrderStatusCompleted, current.Status)
		wallet, err := client.User.Get(ctx, user.ID)
		require.NoError(t, err)
		require.Equal(t, 1.0, wallet.Balance)
	})
}
