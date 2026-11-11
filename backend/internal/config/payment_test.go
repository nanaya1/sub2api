package config

import "testing"

func TestPaymentEnvironment(t *testing.T) {
	for raw, want := range map[string]string{"": "production", "production": "production", "sandbox": "sandbox", " sandbox ": "sandbox"} {
		got, err := NormalizePaymentEnvironment(raw)
		if err != nil || got != want {
			t.Fatal("environment normalization failed")
		}
	}
	for _, raw := range []string{"prod", "demo", "Sandbox", "invalid"} {
		cfg := &Config{Payment: PaymentConfig{Environment: raw}}
		if cfg.Validate() == nil {
			t.Fatal("invalid payment environment accepted")
		}
	}
}
