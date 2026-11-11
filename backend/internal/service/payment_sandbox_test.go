//go:build unit

package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/payment"
	"github.com/stretchr/testify/require"
)

func TestPaymentSandboxEnvironmentIsolation(t *testing.T) {
	sandbox := &PaymentConfigService{environment: payment.EnvironmentSandbox}
	production := &PaymentConfigService{}
	require.NoError(t, production.validateProviderEnvironment(payment.TypeAlipay, nil))
	require.NoError(t, sandbox.validateProviderEnvironment(payment.TypeAlipay, map[string]string{"environment": "sandbox"}))
	require.Error(t, sandbox.validateProviderEnvironment(payment.TypeAlipay, nil))
	require.Error(t, production.validateProviderEnvironment(payment.TypeAlipay, map[string]string{"environment": "sandbox"}))
	for _, key := range []string{payment.TypeEasyPay, payment.TypeWxpay, payment.TypeStripe, payment.TypeAirwallex} {
		require.Error(t, sandbox.validateProviderEnvironment(key, nil))
	}
	order := &dbent.PaymentOrder{OutTradeNo: "original", ProviderSnapshot: buildPaymentOrderProviderSnapshot(&payment.InstanceSelection{
		ProviderKey: payment.TypeAlipay, Config: map[string]string{"appId": "app", "sellerId": "seller", "environment": "sandbox"},
	}, CreateOrderRequest{})}
	svc := &PaymentService{configService: sandbox}
	require.Equal(t, "sandbox", PaymentOrderEnvironment(order))
	require.NoError(t, svc.validateOrderInstanceEnvironment(map[string]string{"appId": "app", "sellerId": "seller", "environment": "sandbox"}, order, payment.TypeAlipay))
	require.Error(t, svc.validateOrderInstanceEnvironment(map[string]string{"appId": "other", "sellerId": "seller", "environment": "sandbox"}, order, payment.TypeAlipay))
	for _, source := range []string{"query", "notification"} {
		metadata := map[string]string{"confirmation_source": source, "payment_environment": "sandbox", "out_trade_no": "original", "total_amount": "10.00", "app_id": "app", "seller_id": "seller", "authenticated_app_id": "app"}
		require.NoError(t, validateProviderNotificationMetadata(order, payment.TypeAlipay, metadata))
		if source == "query" {
			delete(metadata, "app_id")
			delete(metadata, "seller_id")
			require.NoError(t, validateProviderNotificationMetadata(order, payment.TypeAlipay, metadata))
		}
		metadata["payment_environment"] = "production"
		require.Error(t, validateProviderNotificationMetadata(order, payment.TypeAlipay, metadata))
	}
	require.Error(t, validateProviderNotificationMetadata(order, payment.TypeAlipay, nil))
	require.Error(t, (&PaymentService{configService: production}).validateOrderEnvironment(order))
}

func sandboxTestOrder(t *testing.T, client *dbent.Client, userID int64, suffix string) *dbent.PaymentOrder {
	t.Helper()
	order, err := client.PaymentOrder.Create().SetUserID(userID).SetUserEmail("sandbox@test.local").SetUserName("sandbox").
		SetAmount(1).SetPayAmount(10).SetFeeRate(0).SetRechargeCode("sandbox-" + suffix).SetOutTradeNo("sandbox-" + suffix).
		SetPaymentType(payment.TypeAlipay).SetPaymentTradeNo("").SetOrderType(payment.OrderTypeBalance).SetStatus(OrderStatusPending).
		SetExpiresAt(time.Now().Add(time.Hour)).SetClientIP("127.0.0.1").SetSrcHost("controlled.local").Save(context.Background())
	require.NoError(t, err)
	return order
}

func TestPaymentSandboxExactCentsBeforeWritingTrade(t *testing.T) {
	ctx := context.Background()
	client := newPaymentOrderLifecycleTestClient(t)
	user, err := client.User.Create().SetEmail("cents@test.local").SetPasswordHash("test").Save(ctx)
	require.NoError(t, err)
	order := sandboxTestOrder(t, client, user.ID, "cents")
	svc := &PaymentService{entClient: client, registry: payment.NewRegistry()}
	for _, paid := range []float64{9.99, 10.01, 9.999, 0} {
		require.Error(t, svc.confirmPayment(ctx, order.ID, "untrusted-trade", paid, payment.TypeAlipay, map[string]string{"total_amount": "10.00"}))
		current, err := client.PaymentOrder.Get(ctx, order.ID)
		require.NoError(t, err)
		require.Equal(t, OrderStatusPending, current.Status)
		require.Empty(t, current.PaymentTradeNo)
		require.Nil(t, current.PaidAt)
	}
}

type paymentSandboxCancelProvider struct {
	*paymentOrderLifecycleQueryProvider
	queryErr     error
	cancelErr    error
	beforeCancel func()
}

func (p *paymentSandboxCancelProvider) QueryOrder(ctx context.Context, ref string) (*payment.QueryOrderResponse, error) {
	if p.queryErr != nil {
		p.queryCalls++
		return nil, p.queryErr
	}
	return p.paymentOrderLifecycleQueryProvider.QueryOrder(ctx, ref)
}

func (p *paymentSandboxCancelProvider) CancelPayment(ctx context.Context, ref string) error {
	_ = p.paymentOrderLifecycleQueryProvider.CancelPayment(ctx, ref)
	if p.beforeCancel != nil {
		p.beforeCancel()
	}
	return p.cancelErr
}

func TestPaymentSandboxCancelKeepsUnknownResultPending(t *testing.T) {
	for _, scenario := range []string{"query-error", "query-empty", "close-error"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			client := newPaymentOrderLifecycleTestClient(t)
			user, err := client.User.Create().SetEmail(scenario + "@test.local").SetPasswordHash("test").Save(ctx)
			require.NoError(t, err)
			order := sandboxTestOrder(t, client, user.ID, scenario)
			provider := &paymentSandboxCancelProvider{paymentOrderLifecycleQueryProvider: &paymentOrderLifecycleQueryProvider{}}
			if scenario == "query-error" {
				provider.queryErr = errors.New("controlled query timeout")
			}
			if scenario == "close-error" {
				provider.resp = &payment.QueryOrderResponse{Status: payment.ProviderStatusPending}
				provider.cancelErr = errors.New("controlled close conflict")
			}
			registry := payment.NewRegistry()
			registry.Register(provider)
			svc := &PaymentService{entClient: client, registry: registry, providersLoaded: true}
			outcome, err := svc.CancelOrder(ctx, order.ID, user.ID)
			require.Error(t, err)
			require.Empty(t, outcome)
			current, err := client.PaymentOrder.Get(ctx, order.ID)
			require.NoError(t, err)
			require.Equal(t, OrderStatusPending, current.Status)
			if scenario != "close-error" {
				require.Zero(t, provider.cancelCalls, "查单未确认时不能继续关单")
			}
		})
	}
}

func TestPaymentSandboxCancelRaceDoesNotReportPaidOrderCancelled(t *testing.T) {
	ctx := context.Background()
	client := newPaymentOrderLifecycleTestClient(t)
	user, err := client.User.Create().SetEmail("cancel-race@test.local").SetPasswordHash("test").Save(ctx)
	require.NoError(t, err)
	order := sandboxTestOrder(t, client, user.ID, "cancel-race")
	provider := &paymentSandboxCancelProvider{paymentOrderLifecycleQueryProvider: &paymentOrderLifecycleQueryProvider{
		resp: &payment.QueryOrderResponse{Status: payment.ProviderStatusPending},
	}}
	// 模拟回调在查单之后推进本地状态，取消条件更新必须尊重并发结果
	provider.beforeCancel = func() {
		_, err := client.PaymentOrder.UpdateOneID(order.ID).SetStatus(OrderStatusCompleted).Save(ctx)
		require.NoError(t, err)
	}
	registry := payment.NewRegistry()
	registry.Register(provider)
	svc := &PaymentService{entClient: client, registry: registry, providersLoaded: true}
	outcome, err := svc.CancelOrder(ctx, order.ID, user.ID)
	require.NoError(t, err)
	require.Equal(t, checkPaidResultAlreadyPaid, outcome)
	current, err := client.PaymentOrder.Get(ctx, order.ID)
	require.NoError(t, err)
	require.Equal(t, OrderStatusCompleted, current.Status)
}

func TestPaymentPortalCheckOwnershipAndPersistentRateLimit(t *testing.T) {
	ctx := context.Background()
	client := newPaymentOrderLifecycleTestClient(t)
	ensurePaymentAuditOrderActionUniqueIndex(t, ctx, client)
	user, err := client.User.Create().SetEmail("check@test.local").SetPasswordHash("test").Save(ctx)
	require.NoError(t, err)
	order := sandboxTestOrder(t, client, user.ID, "check")
	provider := &paymentOrderLifecycleQueryProvider{resp: &payment.QueryOrderResponse{Status: payment.ProviderStatusPending}}
	registry := payment.NewRegistry()
	registry.Register(provider)
	svc := &PaymentService{entClient: client, registry: registry, providersLoaded: true}
	_, err = svc.CheckPortalPaymentOrder(ctx, order.ID, user.ID+100)
	require.ErrorIs(t, err, ErrPortalNotFound)
	got, err := svc.CheckPortalPaymentOrder(ctx, order.ID, user.ID)
	require.NoError(t, err)
	require.Equal(t, OrderStatusPending, got.Status)
	require.Equal(t, 1, provider.queryCalls)
	// 第二个Service模拟另一副本，共享持久化频控，不能重置为进程内计数
	other := &PaymentService{entClient: client, registry: registry, providersLoaded: true}
	_, err = other.CheckPortalPaymentOrder(ctx, order.ID, user.ID)
	require.ErrorIs(t, err, ErrPortalRejected)
	require.Equal(t, 1, provider.queryCalls)
	require.Empty(t, got.PaymentTradeNo)
	var updated sql.Result
	require.NoError(t, client.Driver().Exec(ctx, `UPDATE payment_audit_logs SET created_at=$1 WHERE operator=$2`, []any{time.Now().Add(-11 * time.Second), fmt.Sprintf("user:%d", user.ID)}, &updated))
	_, err = other.CheckPortalPaymentOrder(ctx, order.ID, user.ID)
	require.NoError(t, err)
	require.Equal(t, 2, provider.queryCalls, "同一订单冷却后应可再次核查，不与履约幂等索引冲突")
}

func TestPaymentPortalOrderReferenceCommitsAndRollsBackTogether(t *testing.T) {
	ctx := context.Background()
	client := newPaymentOrderLifecycleTestClient(t)
	exec := func(query string, args ...any) {
		var result sql.Result
		require.NoError(t, client.Driver().Exec(ctx, query, args, &result))
	}
	exec(`CREATE TABLE cowork_portal_operations(source TEXT,external_user_id TEXT,operation TEXT,request_id TEXT,status TEXT,resource_id BIGINT,updated_at TIMESTAMP)`)
	user, err := client.User.Create().SetEmail("bind@test.local").SetPasswordHash("test").Save(ctx)
	require.NoError(t, err)
	op := &PaymentPortalOperation{Source: "cowork", ExternalUserID: "7", RequestID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	exec(`INSERT INTO cowork_portal_operations(source,external_user_id,operation,request_id,status) VALUES('cowork','7','recharge.add',$1,'PENDING')`, op.RequestID)
	svc := &PaymentService{entClient: client}
	req := CreateOrderRequest{UserID: user.ID, PaymentType: payment.TypeAlipay, OrderType: payment.OrderTypeBalance, PortalOperation: op}
	cfg := &PaymentConfig{MaxPendingOrders: 10}
	order, err := svc.createOrderInTx(ctx, req, &User{ID: user.ID, Email: user.Email}, nil, cfg, 1, 10, 0, 10, nil)
	require.NoError(t, err)
	var result sql.Result
	require.NoError(t, client.Driver().Exec(ctx, `UPDATE cowork_portal_operations SET status='UNCONFIRMED' WHERE resource_id=$1`, []any{order.ID}, &result))
	count, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	before, err := client.PaymentOrder.Query().Count(ctx)
	require.NoError(t, err)
	// 已关联的操作或不存在的操作不可创建第二张订单，订单插入也必须回滚
	_, err = svc.createOrderInTx(ctx, req, &User{ID: user.ID, Email: user.Email}, nil, cfg, 1, 10, 0, 10, nil)
	require.Error(t, err)
	after, err := client.PaymentOrder.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after, fmt.Sprint(order.ID))
}
