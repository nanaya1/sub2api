package payment

import "testing"

func TestAlipayAmountCents(t *testing.T) {
	for raw, want := range map[string]int64{"10": 1000, "0.01": 1, "10.10": 1010, "999999999.99": 99999999999} {
		got, err := AlipayAmountCents(raw)
		if err != nil || got != want {
			t.Fatalf("valid amount failed")
		}
	}
	for _, raw := range []string{"", "0", "-1", "NaN", "1e2", "1.001", " 10.00", "10.00 ", "+1", ".01"} {
		if _, err := AlipayAmountCents(raw); err == nil {
			t.Fatalf("invalid amount accepted")
		}
	}
}
