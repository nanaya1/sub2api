package handler

import (
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCoworkPortalClientKeyRejectsInactiveExpiredExhaustedAndUnauthorized(t *testing.T) {
	groupID := int64(101)
	valid := func() *service.APIKey {
		return &service.APIKey{UserID: 7, Status: "active", GroupID: &groupID,
			User:  &service.User{ID: 7, Status: "active", RestrictPublicGroups: true, AllowedGroups: []int64{101}},
			Group: &service.Group{ID: 101, Status: "active", Platform: "openai"}}
	}
	require.True(t, clientKeyUsable(valid(), 7))
	for _, change := range []func(*service.APIKey){
		func(k *service.APIKey) { k.UserID = 8 },
		func(k *service.APIKey) { k.Status = "inactive" },
		func(k *service.APIKey) { past := time.Now().Add(-time.Second); k.ExpiresAt = &past },
		func(k *service.APIKey) { k.Quota = 1; k.QuotaUsed = 1 },
		func(k *service.APIKey) { k.User.Status = "inactive" },
		func(k *service.APIKey) { k.User.RestrictPublicGroups = false },
		func(k *service.APIKey) { k.Group.Status = "inactive" },
		func(k *service.APIKey) { k.Group = nil },
	} {
		key := valid()
		change(key)
		require.False(t, clientKeyUsable(key, 7))
	}
	require.False(t, clientKeyUsable(nil, 7))
}
