//go:build unit

package service

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/migrations"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// TestCoworkPortalDatabase 只允许显式提供的回环临时数据库，验证真实SQL及并发领取
func TestCoworkPortalDatabase(t *testing.T) {
	dsn := os.Getenv("COWORK_PORTAL_TEST_DSN")
	if dsn == "" {
		t.Skip("requires a disposable loopback PostgreSQL database")
	}
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", parsed.Hostname())
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(12)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema, err := migrations.FS.ReadFile("243_cowork_portal_operations.sql")
	require.NoError(t, err)
	// 临时数据库只建该读取投影需要的列，历史已删除分组映射保留
	_, err = db.ExecContext(ctx, `CREATE TABLE users(id BIGINT PRIMARY KEY,status TEXT,deleted_at TIMESTAMPTZ,restrict_public_groups BOOLEAN);
      CREATE TABLE provisioning_user_bindings(source TEXT,external_user_id TEXT,local_user_id BIGINT,status TEXT);
      CREATE TABLE groups(id BIGINT PRIMARY KEY,status TEXT,deleted_at TIMESTAMPTZ);
      CREATE TABLE user_allowed_groups(user_id BIGINT,group_id BIGINT);
      CREATE TABLE provisioning_group_bindings(source TEXT,tenant_key TEXT,external_group_id TEXT,local_group_id BIGINT,status TEXT);
      CREATE TABLE api_keys(id BIGINT PRIMARY KEY,user_id BIGINT,group_id BIGINT,status TEXT,name TEXT,created_at TIMESTAMPTZ,deleted_at TIMESTAMPTZ);
      CREATE TABLE usage_logs(id BIGINT PRIMARY KEY,user_id BIGINT,group_id BIGINT,api_key_id BIGINT,model TEXT,requested_model TEXT,input_tokens BIGINT,output_tokens BIGINT,cache_creation_tokens BIGINT,cache_read_tokens BIGINT,total_cost NUMERIC,actual_cost NUMERIC,created_at TIMESTAMPTZ);`+string(schema))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO users VALUES(10,'active',NULL,true),(20,'active',NULL,true);
      INSERT INTO provisioning_user_bindings VALUES('cowork','7',10,'active');
      INSERT INTO groups VALUES(30,'active',NULL),(31,'inactive',NOW()),(40,'active',NULL);
      INSERT INTO user_allowed_groups VALUES(10,30);
      INSERT INTO provisioning_group_bindings VALUES('cowork','8','9',30,'active'),('cowork','8','old',31,'deleted'),('cowork','other','9',40,'active');
      INSERT INTO api_keys VALUES(1,10,30,'active','mine',NOW(),NULL),(2,20,30,'active','other user',NOW(),NULL),(3,10,40,'active','other tenant',NOW(),NULL),(4,10,31,'inactive','old group',NOW(),NULL);
      INSERT INTO usage_logs VALUES(1,10,30,1,'fallback','requested',2,3,0,0,5,4,'2026-11-05T02:00Z'),(2,20,30,2,'fallback','requested',20,30,0,0,50,40,'2026-11-05T02:00Z'),(3,10,40,3,'fallback','requested',20,30,0,0,50,40,'2026-11-05T02:00Z'),(4,10,31,4,'fallback','requested',1,1,0,0,2,1,'2026-11-05T02:00Z');`)
	require.NoError(t, err)
	svc := NewProvisioningService(db, nil, nil)
	identity := portalTestIdentity()
	require.NoError(t, svc.ResolvePortalIdentity(ctx, &identity))
	require.Equal(t, int64(10), identity.UserID)
	group, err := svc.PortalCurrentGroup(ctx, identity)
	require.NoError(t, err)
	require.Equal(t, int64(30), group)
	for _, id := range []int64{2, 3} {
		require.ErrorIs(t, svc.PortalOwnsKey(ctx, identity, id), ErrPortalNotFound)
	}
	require.NoError(t, svc.PortalOwnsKey(ctx, identity, 4))
	ids, total, err := svc.PortalKeyIDs(ctx, identity, 1, 1, "", "active")
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Equal(t, []int64{1}, ids)
	start, _ := time.Parse(time.RFC3339, "2026-11-05T00:00:00Z")
	filter := CoworkPortalUsageFilter{Start: start, End: start.Add(24 * time.Hour), Page: 1, PageSize: 1}
	summary, err := svc.PortalUsage(ctx, identity, filter, "usage.summary")
	require.NoError(t, err)
	require.Equal(t, int64(2), summary.(map[string]any)["requests"])
	require.Equal(t, float64(5), summary.(map[string]any)["actualCost"])
	trend, err := svc.PortalUsage(ctx, identity, filter, "usage.trend")
	require.NoError(t, err)
	require.Len(t, trend, 1)
	page, err := svc.PortalUsage(ctx, identity, filter, "usage.page")
	require.NoError(t, err)
	require.Equal(t, int64(2), page.(map[string]any)["total"])
	require.Len(t, page.(map[string]any)["items"], 1)
	filter.Model = "unmatched"
	summary, err = svc.PortalUsage(ctx, identity, filter, "usage.summary")
	require.NoError(t, err)
	require.Equal(t, int64(0), summary.(map[string]any)["requests"])
	// 并发相同操作只有一个领取者，其他请求只能看到未确认或完成记录
	var owners atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner, _, err := svc.ClaimPortalOperation(ctx, identity, "key.add", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]any{"name": "key"})
			if owner {
				owners.Add(1)
			}
			if err != nil && err != ErrPortalUnconfirmed {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), owners.Load())
	require.NoError(t, svc.CompletePortalOperation(ctx, identity, "key.add", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, nil))
	owner, op, err := svc.ClaimPortalOperation(ctx, identity, "key.add", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]any{"name": "key"})
	require.NoError(t, err)
	require.False(t, owner)
	require.Equal(t, int64(1), *op.ResourceID)
	_, _, err = svc.ClaimPortalOperation(ctx, identity, "key.add", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]any{"name": "changed"})
	require.ErrorIs(t, err, ErrPortalConflict)
	require.ErrorIs(t, svc.CompletePortalOperation(ctx, identity, "key.add", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 2, nil), ErrPortalUnconfirmed)
}
