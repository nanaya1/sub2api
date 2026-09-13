package service

import (
	"context"
	"errors"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type managedLookupStub struct {
	record *OAuthManagedKeyRecord
	err    error
}

func (s managedLookupStub) FindManagedKey(context.Context, int64, int64) (*OAuthManagedKeyRecord, error) {
	return s.record, s.err
}
func (s managedLookupStub) CreateManagedKey(context.Context, int64, int64, *APIKey) (*OAuthManagedKeyRecord, error) {
	panic("must not create")
}
func TestOAuthManagedLookupFailsClosed(t *testing.T) {
	failure := errors.New("database unavailable")
	s := &OAuthResourceService{Managed: managedLookupStub{err: failure}}
	_, err := s.GetOrCreateManagedKey(context.Background(), 7, 9)
	require.ErrorIs(t, err, failure)
	s.Managed = managedLookupStub{record: &OAuthManagedKeyRecord{UserID: 7, ClientID: 9, Key: "healthy", Status: StatusActive}}
	key, err := s.GetOrCreateManagedKey(context.Background(), 7, 9)
	require.Error(t, err, "缺少事务依赖不能绕过订阅校验")
	require.Empty(t, key)
	now := time.Now()
	for _, record := range []*OAuthManagedKeyRecord{
		{UserID: 7, ClientID: 9, Key: "secret", RevokedAt: &now},
		{UserID: 7, ClientID: 9, Key: "disabled", Status: "disabled"},
		{UserID: 7, ClientID: 9, Key: "expired", Status: StatusActive, ExpiresAt: &now},
		{UserID: 7, ClientID: 9, Key: "deleted", Status: StatusActive, DeletedAt: &now},
		{UserID: 7, ClientID: 9, Key: "quota", Status: StatusActive, Quota: 1, QuotaUsed: 1},
		{UserID: 8, ClientID: 9, Key: "other-user"},
		{UserID: 7, ClientID: 10, Key: "other-client"},
	} {
		s.Managed = managedLookupStub{record: record}
		key, err := s.GetOrCreateManagedKey(context.Background(), 7, 9)
		require.Error(t, err)
		require.Empty(t, key)
	}
}
