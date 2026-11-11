package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/paymentauditlog"
	"github.com/Wei-Shaw/sub2api/internal/payment"
)

// PaymentPortalOperation 由可信内部入口绑定，客户端不能指定来源身份
type PaymentPortalOperation struct {
	Source         string
	ExternalUserID string
	RequestID      string
}

// bindPortalPaymentOrder 在下单事务提交前保存恢复引用，网络响应丢失后仍能找到原订单
func bindPortalPaymentOrder(ctx context.Context, tx *dbent.Tx, op *PaymentPortalOperation, orderID int64) error {
	if op == nil {
		return nil
	}
	if op.Source == "" || op.ExternalUserID == "" || op.RequestID == "" {
		return ErrPortalInvalid
	}
	var result sql.Result
	err := tx.Client().Driver().Exec(ctx, `UPDATE cowork_portal_operations SET resource_id=$1, updated_at=CURRENT_TIMESTAMP
        WHERE source=$2 AND external_user_id=$3 AND operation='recharge.add'
        AND request_id=$4 AND status='PENDING' AND resource_id IS NULL`,
		[]any{orderID, op.Source, op.ExternalUserID, op.RequestID}, &result)
	if err != nil {
		return ErrPortalUnconfirmed
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrPortalUnconfirmed
	}
	return nil
}

// CheckPortalPaymentOrder 只核查本人余额订单，不重新下单、不重放未知履约
func (s *PaymentService) CheckPortalPaymentOrder(ctx context.Context, orderID, userID int64) (*dbent.PaymentOrder, error) {
	order, err := s.GetOrder(ctx, orderID, userID)
	if err != nil || order.OrderType != payment.OrderTypeBalance {
		return nil, ErrPortalNotFound
	}
	if err := s.validateOrderEnvironment(order); err != nil {
		return nil, ErrPortalUnconfirmed
	}
	if order.Status != OrderStatusPending && order.Status != OrderStatusExpired && order.Status != OrderStatusCancelled {
		return order, nil
	}
	if err := s.claimPortalPaymentCheck(ctx, orderID, userID); err != nil {
		return nil, err
	}
	// 频控事务已结束，禁止持有用户行锁访问支付网络
	prov, err := s.getOrderProvider(ctx, order)
	if err != nil || prov.ProviderKey() != payment.TypeAlipay {
		return nil, ErrPortalUnconfirmed
	}
	result, err := prov.QueryOrder(ctx, order.OutTradeNo)
	if err != nil || result == nil {
		return nil, ErrPortalUnconfirmed
	}
	if result.Status == payment.ProviderStatusPaid {
		err = s.HandlePaymentNotification(ctx, &payment.PaymentNotification{
			OrderID: order.OutTradeNo, TradeNo: result.TradeNo, Amount: result.Amount,
			Status: payment.NotificationStatusSuccess, Metadata: result.Metadata,
		}, prov.ProviderKey())
		if err != nil {
			return nil, ErrPortalUnconfirmed
		}
	}
	return s.GetOrder(ctx, orderID, userID)
}

func (s *PaymentService) claimPortalPaymentCheck(ctx context.Context, orderID, userID int64) error {
	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return ErrPortalUnconfirmed
	}
	defer func() { _ = tx.Rollback() }()
	query := "SELECT id FROM users WHERE id=$1"
	if tx.Client().Driver().Dialect() == dialect.Postgres {
		query += " FOR UPDATE"
	}
	var rows entsql.Rows
	if err := tx.Client().Driver().Query(ctx, query, []any{userID}, &rows); err != nil {
		return ErrPortalUnconfirmed
	}
	exists := rows.Next()
	rowsErr := rows.Err()
	_ = rows.Close()
	if rowsErr != nil || !exists {
		return ErrPortalNotFound
	}
	operator := fmt.Sprintf("user:%d", userID)
	now := time.Now().UTC()
	recent, err := tx.PaymentAuditLog.Query().Where(
		paymentauditlog.ActionHasPrefix("PORTAL_ORDER_CHECK:"), paymentauditlog.OperatorEQ(operator),
		paymentauditlog.CreatedAtGTE(now.Add(-10*time.Second)),
	).Exist(ctx)
	if err != nil {
		return ErrPortalUnconfirmed
	}
	if recent {
		return ErrPortalRejected
	}
	// 既有(order_id,action)唯一索引用于履约幂等；查单是可重复事件，后缀区分每次核查且保留不可变记录
	_, err = tx.PaymentAuditLog.Create().SetOrderID(fmt.Sprint(orderID)).SetAction(fmt.Sprintf("PORTAL_ORDER_CHECK:%d", now.UnixNano())).
		SetOperator(operator).SetCreatedAt(now).SetDetail(`{"result":"REQUESTED"}`).Save(ctx)
	if err != nil {
		return ErrPortalUnconfirmed
	}
	if err := tx.Commit(); err != nil {
		return ErrPortalUnconfirmed
	}
	return nil
}
