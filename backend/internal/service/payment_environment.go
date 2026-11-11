package service

import (
	"fmt"
	"strings"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/payment"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

func (s *PaymentConfigService) paymentEnvironment() string {
	if s == nil || s.environment == "" {
		return payment.EnvironmentProduction
	}
	return s.environment
}

// validateProviderEnvironment 同时约束保存、路由和历史核查，沙箱进程不能回落其他真实收款渠道
func (s *PaymentConfigService) validateProviderEnvironment(key string, cfg map[string]string) error {
	deployment, err := payment.NormalizeEnvironment(s.paymentEnvironment())
	if err != nil {
		return err
	}
	if key != payment.TypeAlipay {
		if deployment == payment.EnvironmentSandbox {
			return infraerrors.BadRequest("PAYMENT_ENVIRONMENT_MISMATCH", "sandbox only supports official alipay")
		}
		return nil
	}
	env, err := payment.NormalizeEnvironment(cfg["environment"])
	if err != nil || env != deployment {
		return infraerrors.BadRequest("PAYMENT_ENVIRONMENT_MISMATCH", "payment instance environment does not match deployment")
	}
	return nil
}

func (s *PaymentConfigService) filterPaymentEnvironment(instances []*dbent.PaymentProviderInstance) []*dbent.PaymentProviderInstance {
	filtered := make([]*dbent.PaymentProviderInstance, 0, len(instances))
	for _, inst := range instances {
		cfg, err := s.decryptConfig(inst.Config)
		if err == nil && s.validateProviderEnvironment(inst.ProviderKey, cfg) == nil {
			filtered = append(filtered, inst)
		}
	}
	return filtered
}

// PaymentOrderEnvironment 只读取订单创建时的环境，历史订单沿用正式环境，不以当前配置改写历史
func PaymentOrderEnvironment(order *dbent.PaymentOrder) string {
	if order == nil {
		return payment.EnvironmentProduction
	}
	if value, exists := order.ProviderSnapshot["payment_environment"]; exists {
		raw, ok := value.(string)
		if !ok {
			return "unconfirmed"
		}
		env, err := payment.NormalizeEnvironment(raw)
		if err != nil {
			return "unconfirmed"
		}
		return env
	}
	return payment.EnvironmentProduction
}

func (s *PaymentService) validateOrderEnvironment(order *dbent.PaymentOrder) error {
	if PaymentOrderEnvironment(order) != s.configService.paymentEnvironment() {
		return fmt.Errorf("order payment environment does not match deployment")
	}
	return nil
}

func (s *PaymentService) validateOrderInstanceEnvironment(ctxConfig map[string]string, order *dbent.PaymentOrder, key string) error {
	if err := s.configService.validateProviderEnvironment(key, ctxConfig); err != nil {
		return err
	}
	if err := s.validateOrderEnvironment(order); err != nil {
		return err
	}
	if key == payment.TypeAlipay {
		env, err := payment.NormalizeEnvironment(strings.TrimSpace(ctxConfig["environment"]))
		if err != nil || env != PaymentOrderEnvironment(order) {
			return fmt.Errorf("order and provider environment mismatch")
		}
		if snapshot := psOrderProviderSnapshot(order); snapshot != nil {
			if snapshot.MerchantAppID != "" && snapshot.MerchantAppID != strings.TrimSpace(ctxConfig["appId"]) {
				return fmt.Errorf("alipay app_id mismatch")
			}
			if snapshot.MerchantID != "" && snapshot.MerchantID != strings.TrimSpace(ctxConfig["sellerId"]) {
				return fmt.Errorf("order seller identity mismatch")
			}
		}
	}
	return nil
}
