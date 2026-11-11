package payment

import (
	"fmt"
	"regexp"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

const EnvironmentProduction = config.PaymentEnvironmentProduction
const EnvironmentSandbox = config.PaymentEnvironmentSandbox

// NormalizeEnvironment 对历史空配置按正式环境解释，对非法值显式拒绝
func NormalizeEnvironment(raw string) (string, error) {
	return config.NormalizePaymentEnvironment(raw)
}

var alipayAmountPattern = regexp.MustCompile(`^[0-9]{1,12}(\.[0-9]{1,2})?$`)

// AlipayAmountCents 严格读取支付宝订单总金额，不接受科学计数、负数或超出分的精度
func AlipayAmountCents(raw string) (int64, error) {
	if !alipayAmountPattern.MatchString(raw) {
		return 0, fmt.Errorf("invalid alipay total amount")
	}
	value, err := AmountToMinorUnit(raw, DefaultPaymentCurrency)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid alipay total amount")
	}
	return value, nil
}
