package handler

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestCoworkPortalRejectsInvalidEnvelopeBeforeIdentityLookup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, body := range []string{`{"unexpected":true}`, `{} {}`, `{"parameters":{"amount":"bad"}}`, strings.Repeat(" ", 65537) + `{}`} {
		r := gin.New()
		h := NewCoworkPortalHandler(&Handlers{})
		r.POST("/portal", h.Authenticate, h.Handle)
		request := httptest.NewRequest("POST", "/portal", strings.NewReader(body))
		response := httptest.NewRecorder()
		r.ServeHTTP(response, request)
		require.Equal(t, 400, response.Code)
		require.Contains(t, response.Body.String(), "PORTAL_INVALID_ARGUMENT")
	}
}

func TestCoworkPortalKeySecretIsExplicitAndMasked(t *testing.T) {
	key := &service.APIKey{ID: 1, Key: "sk-controlled-long-test-secret", Name: "test"}
	hidden, _ := json.Marshal(coworkPortalKey(key, false))
	require.NotContains(t, string(hidden), key.Key)
	revealed, _ := json.Marshal(coworkPortalKey(key, true))
	require.Contains(t, string(revealed), key.Key)
}

func TestCoworkPortalMutationFailureKeepsUnknownCommitOutcome(t *testing.T) {
	require.ErrorIs(t, portalMutationError(errors.New("unknown commit")), service.ErrPortalUnconfirmed)
	require.ErrorIs(t, portalMutationError(infraerrors.BadRequest("INVALID_STATUS", "ignored")), service.ErrPortalRejected)
}
