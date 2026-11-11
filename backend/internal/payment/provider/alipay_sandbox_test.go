//go:build unit

package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/payment"
	"github.com/smartwalle/alipay/v3"
	"github.com/stretchr/testify/require"
)

func sandboxAlipayTestProvider(t *testing.T) (*Alipay, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	cfg := map[string]string{
		"appId": "test-app", "sellerId": "test-seller", "environment": "sandbox", "paymentMode": "redirect",
		"privateKey": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"publicKey":  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})),
	}
	provider, err := NewAlipay("1", cfg)
	require.NoError(t, err)
	return provider, key
}

func signSandboxBytes(t *testing.T, key *rsa.PrivateKey, raw string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(raw))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(signature)
}

func signSandboxNotification(t *testing.T, key *rsa.PrivateKey, values url.Values) string {
	t.Helper()
	pairs := []string{}
	for k, v := range values {
		if k != "sign" && k != "sign_type" {
			for _, value := range v {
				pairs = append(pairs, k+"="+value)
			}
		}
	}
	sort.Strings(pairs)
	values.Set("sign", signSandboxBytes(t, key, strings.Join(pairs, "&")))
	return values.Encode()
}

func TestAlipaySandboxNotificationStrictVerification(t *testing.T) {
	provider, key := sandboxAlipayTestProvider(t)
	valid := func() url.Values {
		return url.Values{
			"app_id": {"test-app"}, "seller_id": {"test-seller"}, "out_trade_no": {"original-order"},
			"trade_no": {"upstream-trade"}, "trade_status": {"TRADE_SUCCESS"}, "total_amount": {"10.00"}, "sign_type": {"RSA2"},
			"receipt_amount": {"9.00"}, "buyer_pay_amount": {"8.00"},
		}
	}
	notification, err := provider.VerifyNotification(context.Background(), signSandboxNotification(t, key, valid()), nil)
	require.NoError(t, err)
	require.Equal(t, 10.0, notification.Amount)
	require.Equal(t, "10.00", notification.Metadata["total_amount"])
	require.Equal(t, "sandbox", notification.Metadata["payment_environment"])
	require.Empty(t, notification.RawData)
	for _, name := range []string{"app_id", "seller_id", "out_trade_no", "trade_no", "total_amount", "sign_type"} {
		t.Run("missing_"+name, func(t *testing.T) {
			v := valid()
			v.Del(name)
			_, err := provider.VerifyNotification(context.Background(), signSandboxNotification(t, key, v), nil)
			require.Error(t, err)
		})
		t.Run("duplicate_"+name, func(t *testing.T) {
			v := valid()
			v.Add(name, v.Get(name))
			_, err := provider.VerifyNotification(context.Background(), signSandboxNotification(t, key, v), nil)
			require.Error(t, err)
		})
	}
	for _, field := range []string{"app_id", "seller_id", "sign_type", "total_amount"} {
		t.Run("wrong_"+field, func(t *testing.T) {
			v := valid()
			v.Set(field, "wrong")
			_, err := provider.VerifyNotification(context.Background(), signSandboxNotification(t, key, v), nil)
			require.Error(t, err)
		})
	}
	v := valid()
	signed := signSandboxNotification(t, key, v)
	signed = strings.Replace(signed, "total_amount=10.00", "total_amount=11.00", 1)
	_, err = provider.VerifyNotification(context.Background(), signed, nil)
	require.Error(t, err)
}

func TestAlipaySandboxGatewayAndSignedQuery(t *testing.T) {
	provider, key := sandboxAlipayTestProvider(t)
	result, err := provider.CreatePayment(context.Background(), payment.CreatePaymentRequest{OrderID: "original-order", Amount: "10.00", Subject: "controlled test"})
	require.NoError(t, err)
	checkout, err := url.Parse(result.PayURL)
	require.NoError(t, err)
	require.Equal(t, "openapi-sandbox.dl.alipaydev.com", checkout.Hostname())
	require.Equal(t, "alipay.trade.page.pay", checkout.Query().Get("method"))
	require.Empty(t, result.QRCode)

	raw := `{"code":"10000","msg":"Success","out_trade_no":"original-order","trade_no":"query-trade","trade_status":"TRADE_SUCCESS","total_amount":"10.00","receipt_amount":"9.00"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "alipay.trade.query", r.Form.Get("method"))
		_ = json.NewEncoder(w).Encode(map[string]any{"alipay_trade_query_response": json.RawMessage(raw), "sign": signSandboxBytes(t, key, raw)})
	}))
	defer server.Close()
	client, err := alipay.New(provider.config["appId"], provider.config["privateKey"], false, alipay.WithSandboxGateway(server.URL), alipay.WithHTTPClient(server.Client()))
	require.NoError(t, err)
	require.NoError(t, client.LoadAliPayPublicKey(provider.config["publicKey"]))
	provider.client = client
	response, err := provider.QueryOrder(context.Background(), "original-order")
	require.NoError(t, err)
	require.Equal(t, 10.0, response.Amount)
	require.Equal(t, "test-app", response.Metadata["authenticated_app_id"])
	require.NotContains(t, response.Metadata, "app_id")
	require.NotContains(t, response.Metadata, "seller_id")
	_, err = provider.QueryOrder(context.Background(), "different-order")
	require.Error(t, err)
	raw = `{"code":"10000","out_trade_no":"original-order","trade_no":"query-trade","trade_status":"TRADE_SUCCESS","total_amount":""}`
	_, err = provider.QueryOrder(context.Background(), "original-order")
	require.Error(t, err)
}
