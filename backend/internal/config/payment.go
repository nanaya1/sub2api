package config

import (
	"fmt"
	"strings"
)

const PaymentEnvironmentProduction = "production"
const PaymentEnvironmentSandbox = "sandbox"

// PaymentConfig 固定本进程允许使用的支付宝环境，不能由业务请求改变
type PaymentConfig struct {
	Environment string `mapstructure:"environment"`
}

// NormalizePaymentEnvironment 兼容历史正式配置，非法值不能回落正式网关
func NormalizePaymentEnvironment(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "", PaymentEnvironmentProduction:
		return PaymentEnvironmentProduction, nil
	case PaymentEnvironmentSandbox:
		return PaymentEnvironmentSandbox, nil
	default:
		return "", fmt.Errorf("payment environment must be production or sandbox")
	}
}
