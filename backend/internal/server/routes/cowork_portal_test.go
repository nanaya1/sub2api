package routes

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestCoworkPortalCredentialIsIndependentAndFailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, scenario := range []struct {
		enabled                  bool
		secret, provided, header string
		status                   int
	}{
		{false, strings.Repeat("a", 32), "", "", 503},
		{true, "short", "short", "X-Cowork-Portal-Key", 503},
		{true, strings.Repeat("a", 32), strings.Repeat("b", 32), "X-Cowork-Portal-Key", 401},
		{true, strings.Repeat("a", 32), strings.Repeat("a", 32), "X-Provisioning-Key", 401},
	} {
		r := gin.New()
		RegisterCoworkPortalRoutes(r, nil, scenario.enabled, scenario.secret, nil)
		request := httptest.NewRequest("POST", "/internal/v1/cowork/portal", strings.NewReader(`{}`))
		request.Header.Set(scenario.header, scenario.provided)
		response := httptest.NewRecorder()
		r.ServeHTTP(response, request)
		require.Equal(t, scenario.status, response.Code)
	}
}
