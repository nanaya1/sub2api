package handler

import (
	"context"
	"math"
	"net/url"
	"slices"
	"strings"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *CoworkPortalHandler) payment(ctx context.Context, r *coworkPortalRequest, c *gin.Context) (any, error) {
	p := r.Parameters
	payments := h.handlers.Payment.paymentService
	config := h.handlers.Payment.configService
	redeem := h.handlers.Redeem.redeemService
	switch r.Operation {
	case "wallet.detail":
		user, err := h.handlers.User.userService.GetByID(ctx, r.UserID)
		if err != nil {
			return nil, service.ErrPortalNotReady
		}
		return map[string]any{"balance": user.Balance, "frozenBalance": user.FrozenBalance, "totalRecharged": user.TotalRecharged}, nil
	case "recharge.options":
		cfg, err := config.GetPaymentConfig(ctx)
		if err != nil {
			return nil, service.ErrPortalUnavailable
		}
		limits, err := config.GetAvailableMethodLimits(ctx)
		if err != nil {
			return nil, service.ErrPortalUnavailable
		}
		methods := []map[string]any{}
		if cfg.Enabled && !cfg.BalanceDisabled {
			for _, m := range limits.Methods {
				if !slices.Contains(cfg.EnabledTypes, m.PaymentType) {
					continue
				}
				methods = append(methods, map[string]any{"paymentType": m.PaymentType, "displayName": m.DisplayName, "currency": m.Currency, "feeRate": m.FeeRate, "singleMin": m.SingleMin, "singleMax": m.SingleMax})
			}
		}
		return map[string]any{"enabled": cfg.Enabled && !cfg.BalanceDisabled && len(methods) > 0, "methods": methods, "minAmount": cfg.MinAmount, "maxAmount": cfg.MaxAmount, "balanceRechargeMultiplier": cfg.BalanceRechargeMultiplier, "feeRate": cfg.RechargeFeeRate, "stripePublishableKey": cfg.StripePublishableKey}, nil
	case "recharge.add":
		if p.Amount <= 0 || p.Amount >= 1e9 || math.IsNaN(p.Amount) || math.IsInf(p.Amount, 0) || p.PaymentType == "" || len(p.PaymentType) > 50 {
			return nil, service.ErrPortalInvalid
		}
		if r.ReturnURL != "" {
			u, err := url.Parse(r.ReturnURL)
			if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
				return nil, service.ErrPortalInvalid
			}
		}
		cfg, err := config.GetPaymentConfig(ctx)
		if err != nil {
			return nil, service.ErrPortalUnavailable
		}
		limits, err := config.GetAvailableMethodLimits(ctx)
		if err != nil {
			return nil, service.ErrPortalUnavailable
		}
		if _, available := limits.Methods[p.PaymentType]; !available || !cfg.Enabled || cfg.BalanceDisabled || !slices.Contains(cfg.EnabledTypes, p.PaymentType) {
			return nil, service.ErrPortalRejected
		}
		return h.once(ctx, r, func() (int64, any, error) {
			// 仅创建个人余额订单，不允许借助套餐购买改变主系统同步授权
			result, err := payments.CreateOrder(ctx, service.CreateOrderRequest{UserID: r.UserID, Amount: p.Amount, PaymentType: p.PaymentType, ReturnURL: r.ReturnURL, OrderType: "balance", ClientIP: c.ClientIP(), SrcHost: c.Request.Host, PaymentSource: "cowork", Locale: "zh"})
			if err != nil {
				return 0, nil, err
			}
			if result.OrderID <= 0 {
				return 0, nil, service.ErrPortalUnconfirmed
			}
			// 二维码及跳转渠道可能不回传币种，始终从已创建订单的正式快照补齐
			if result.Currency == "" {
				order, err := payments.GetOrder(ctx, result.OrderID, r.UserID)
				if err != nil {
					return 0, nil, service.ErrPortalUnconfirmed
				}
				result.Currency = service.PaymentOrderCurrency(order)
			}
			// 持久化仅经过白名单的支付发起结果，避免保存完整订单或商户配置
			data := map[string]any{"orderId": result.OrderID, "outTradeNo": result.OutTradeNo, "status": result.Status, "resultType": result.ResultType, "payUrl": result.PayURL, "qrCode": result.QRCode, "clientSecret": result.ClientSecret, "intentId": result.IntentID, "currency": result.Currency, "paymentType": result.PaymentType, "countryCode": result.CountryCode, "paymentEnv": result.PaymentEnv, "paymentMode": result.PaymentMode, "alipayMobilePrecreateDeepLink": result.AlipayMobilePrecreateDeepLink, "amount": result.Amount, "payAmount": result.PayAmount, "feeRate": result.FeeRate, "expiresAt": result.ExpiresAt}
			return result.OrderID, data, nil
		})
	case "recharge.redeem":
		if strings.TrimSpace(p.Code) == "" || len(p.Code) > 64 {
			return nil, service.ErrPortalInvalid
		}
		return h.once(ctx, r, func() (int64, any, error) {
			result, err := redeem.RedeemBalanceForPortal(ctx, r.UserID, p.Code)
			if err != nil {
				return 0, nil, err
			}
			return result.ID, map[string]any{}, nil
		})
	case "recharge.history":
		codes, err := redeem.GetUserHistory(ctx, r.UserID, 25)
		if err != nil {
			return nil, service.ErrPortalUnavailable
		}
		result := []map[string]any{}
		for _, code := range codes {
			if code.Type == service.RedeemTypeBalance || code.Type == "admin_balance" || code.Type == "affiliate_balance" {
				result = append(result, map[string]any{"id": code.ID, "type": code.Type, "value": code.Value, "createTime": code.CreatedAt})
			}
		}
		return result, nil
	case "order.page":
		if !validPortalOrderStatus(p.Status) {
			return nil, service.ErrPortalInvalid
		}
		orders, total, err := payments.GetUserOrders(ctx, r.UserID, service.OrderListParams{Page: p.Page, PageSize: p.PageSize, Status: p.Status, OrderType: "balance"})
		if err != nil {
			return nil, service.ErrPortalUnavailable
		}
		result := []map[string]any{}
		for _, order := range orders {
			result = append(result, coworkPortalOrder(order))
		}
		return service.CoworkPortalPage(result, int64(total), p.Page, p.PageSize), nil
	case "order.detail", "order.cancel":
		if p.ID <= 0 {
			return nil, service.ErrPortalInvalid
		}
		order, err := payments.GetOrder(ctx, p.ID, r.UserID)
		if err != nil || order.OrderType != "balance" {
			return nil, service.ErrPortalNotFound
		}
		if r.Operation == "order.cancel" {
			if _, err = payments.CancelOrder(ctx, p.ID, r.UserID); err != nil {
				return nil, portalMutationError(err)
			}
			return map[string]any{}, nil
		}
		return coworkPortalOrder(order), nil
	}
	return nil, service.ErrPortalInvalid
}

func coworkPortalOrder(o *dbent.PaymentOrder) map[string]any {
	return map[string]any{"id": o.ID, "outTradeNo": o.OutTradeNo, "status": o.Status, "amount": o.Amount, "payAmount": o.PayAmount, "feeRate": o.FeeRate, "currency": service.PaymentOrderCurrency(o), "paymentType": o.PaymentType, "refundAmount": o.RefundAmount, "createTime": o.CreatedAt, "paidAt": o.PaidAt, "completedAt": o.CompletedAt, "expiresAt": o.ExpiresAt}
}

func validPortalOrderStatus(status string) bool {
	switch status {
	case "", "PENDING", "PAID", "RECHARGING", "COMPLETED", "EXPIRED", "CANCELLED", "FAILED", "REFUND_REQUESTED", "REFUNDING", "REFUND_PENDING", "PARTIALLY_REFUNDED", "REFUNDED", "REFUND_FAILED":
		return true
	}
	return false
}
