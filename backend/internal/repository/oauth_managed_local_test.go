package repository

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// 仅显式启用独立本地测试库，不迁移、不清空任何现有数据。
func TestOAuthManagedLocalPostgres(t *testing.T) {
	if os.Getenv("OAUTH_LOCAL_TEST") != "1" {
		t.Skip("需显式启用独立测试库")
	}
	ctx := context.Background()
	db, err := sql.Open("postgres", "host=127.0.0.1 port=5432 user=sub2api dbname=sub2api_oauth_local sslmode=disable")
	require.NoError(t, err)
	defer db.Close()
	var name string
	require.NoError(t, db.QueryRow("SELECT current_database()").Scan(&name))
	require.Equal(t, "sub2api_oauth_local", name)
	ent := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	stamp := time.Now().Format("150405.000000000")
	var uid, cid, gid int64
	require.NoError(t, db.QueryRow("INSERT INTO users(email,password_hash) VALUES($1,'test-not-login') RETURNING id", "oauth-test-"+stamp+"@localhost").Scan(&uid))
	require.NoError(t, db.QueryRow("INSERT INTO groups(name,subscription_type) VALUES($1,'subscription') RETURNING id", "oauth-test-"+stamp).Scan(&gid))
	require.NoError(t, db.QueryRow(`INSERT INTO oauth_clients(client_id,name,redirect_uris,allowed_grant_types,allowed_scopes) VALUES($1,'local test','["meacowork://oauth/callback"]','["authorization_code","refresh_token"]','["tokens:read","tokens:write"]') RETURNING id`, "oauth-test-"+stamp).Scan(&cid))
	_, err = db.Exec("INSERT INTO user_subscriptions(user_id,group_id,starts_at,expires_at) VALUES($1,$2,NOW()-INTERVAL '1 hour',NOW()+INTERVAL '1 day')", uid, gid)
	require.NoError(t, err)
	api := service.NewAPIKeyService(NewAPIKeyRepository(ent, db), NewUserRepository(ent, db), NewGroupRepository(ent, db), NewUserSubscriptionRepository(ent), nil, nil, &config.Config{})
	svc := &service.OAuthResourceService{Managed: NewOAuthManagedKeyRepository(db), APIKeys: api, Ent: ent}
	_, err = svc.GetOrCreateManagedKey(ctx, uid, cid, false)
	require.ErrorIs(t, err, service.ErrOAuthManagedWriteRequired)
	// 首次创建当次即必须绑定订阅 Group，不能靠下次领取修复。
	firstKey, err := svc.GetOrCreateManagedKey(ctx, uid, cid, true)
	require.NoError(t, err)
	var firstGroup sql.NullInt64
	require.NoError(t, db.QueryRow("SELECT group_id FROM api_keys WHERE key=$1", firstKey).Scan(&firstGroup))
	require.True(t, firstGroup.Valid, "首次创建必须绑定 Group")
	require.Equal(t, gid, firstGroup.Int64)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	keys := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); k, e := svc.GetOrCreateManagedKey(ctx, uid, cid, true); errs <- e; keys <- k }()
	}
	wg.Wait()
	close(errs)
	close(keys)
	for e := range errs {
		require.NoError(t, e)
	}
	first := ""
	for k := range keys {
		if first == "" {
			first = k
		}
		require.True(t, k == first, "并发领取必须返回同一 Key")
	}
	var count int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM api_keys WHERE user_id=$1", uid).Scan(&count))
	require.Equal(t, 1, count)
	var actualGroup int64
	require.NoError(t, db.QueryRow("SELECT group_id FROM api_keys WHERE user_id=$1", uid).Scan(&actualGroup))
	require.Equal(t, gid, actualGroup)
	_, err = svc.GetOrCreateManagedKey(ctx, uid, cid, false)
	require.NoError(t, err)
	// 不存在的 client 触发外键错误，Key 必须同事务回滚。
	_, err = svc.GetOrCreateManagedKey(ctx, uid, 9223372036854775807, true)
	require.Error(t, err)
	require.NoError(t, db.QueryRow("SELECT count(*) FROM api_keys WHERE user_id=$1", uid).Scan(&count))
	require.Equal(t, 1, count)
	prevKey := first
	for _, update := range []string{"status='disabled'", "expires_at=NOW()-INTERVAL '1 second'", "deleted_at=NOW()", "quota=1,quota_used=1"} {
		_, err = db.Exec("UPDATE api_keys SET "+update+" WHERE user_id=$1", uid)
		require.NoError(t, err)
		// 失效 Key：只读调用方仍被拒绝。
		_, e := svc.GetOrCreateManagedKey(ctx, uid, cid, false)
		require.ErrorIs(t, e, service.ErrOAuthManagedKeyUnavailable)
		// 持 tokens:write 的调用方自动重建新 Key 并迁移绑定（管理员删 Key 后不再永久锁死）。
		newKey, e := svc.GetOrCreateManagedKey(ctx, uid, cid, true)
		require.NoError(t, e)
		require.NotEqual(t, prevKey, newKey, "失效 Key 必须重建而不是返回旧 Key")
		prevKey = newKey
		// 幂等：绑定迁移后再取仍是同一把新 Key。
		again, e := svc.GetOrCreateManagedKey(ctx, uid, cid, true)
		require.NoError(t, e)
		require.Equal(t, prevKey, again)
		var bindKey string
		require.NoError(t, db.QueryRow("SELECT k.key FROM oauth_managed_api_keys m JOIN api_keys k ON k.id=m.api_key_id WHERE m.user_id=$1 AND m.client_id=$2", uid, cid).Scan(&bindKey))
		require.Equal(t, prevKey, bindKey, "绑定行必须迁移到新 Key")
	}
	// 旧 Key 只软删不物理删：1 把初始 + 4 次重建。
	require.NoError(t, db.QueryRow("SELECT count(*) FROM api_keys WHERE user_id=$1", uid).Scan(&count))
	require.Equal(t, 5, count)
	// 订阅过期且没有任何可绑定 standard 分组：回退失败 → NO_ELIGIBLE_GROUP。
	_, err = db.Exec("UPDATE user_subscriptions SET expires_at=NOW()-INTERVAL '1 second' WHERE user_id=$1", uid)
	require.NoError(t, err)
	// 本地测试库是持久共享库：禁用所有 active standard 分组，保证「无可回退分组」前提确定成立。
	_, err = db.Exec("UPDATE groups SET status='disabled' WHERE subscription_type='standard' AND status='active'")
	require.NoError(t, err)
	_, err = svc.GetOrCreateManagedKey(ctx, uid, cid, true)
	require.ErrorIs(t, err, service.ErrOAuthNoEligibleGroup)
}

// 无订阅用户回退到可绑定的标准分组；完全没有可绑定分组时才拒绝。
func TestOAuthManagedLocalPostgres_FallbackStandardGroup(t *testing.T) {
	if os.Getenv("OAUTH_LOCAL_TEST") != "1" {
		t.Skip("需显式启用独立测试库")
	}
	ctx := context.Background()
	db, err := sql.Open("postgres", "host=127.0.0.1 port=5432 user=sub2api dbname=sub2api_oauth_local sslmode=disable")
	require.NoError(t, err)
	defer db.Close()
	var dbName string
	require.NoError(t, db.QueryRow("SELECT current_database()").Scan(&dbName))
	require.Equal(t, "sub2api_oauth_local", dbName)
	ent := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	stamp := time.Now().Format("150405.000000000")
	var uid, cid, fallbackGid, exclusiveGid int64
	require.NoError(t, db.QueryRow("INSERT INTO users(email,password_hash) VALUES($1,'test-not-login') RETURNING id", "oauth-fb-"+stamp+"@localhost").Scan(&uid))
	require.NoError(t, db.QueryRow("INSERT INTO groups(name,subscription_type) VALUES($1,'standard') RETURNING id", "oauth-fb-"+stamp).Scan(&fallbackGid))
	require.NoError(t, db.QueryRow("INSERT INTO groups(name,subscription_type,is_exclusive) VALUES($1,'standard',true) RETURNING id", "oauth-fb-x-"+stamp).Scan(&exclusiveGid))
	require.NoError(t, db.QueryRow(`INSERT INTO oauth_clients(client_id,name,redirect_uris,allowed_grant_types,allowed_scopes) VALUES($1,'local test','["meacowork://oauth/callback"]','["authorization_code","refresh_token"]','["tokens:read","tokens:write"]') RETURNING id`, "oauth-fb-"+stamp).Scan(&cid))
	api := service.NewAPIKeyService(NewAPIKeyRepository(ent, db), NewUserRepository(ent, db), NewGroupRepository(ent, db), NewUserSubscriptionRepository(ent), nil, nil, &config.Config{})
	svc := &service.OAuthResourceService{Managed: NewOAuthManagedKeyRepository(db), APIKeys: api, Ent: ent}
	// 无订阅但有公开 standard 分组：应回退成功并绑定该分组。
	key, err := svc.GetOrCreateManagedKey(ctx, uid, cid, true)
	require.NoError(t, err)
	var gotGroup sql.NullInt64
	require.NoError(t, db.QueryRow("SELECT group_id FROM api_keys WHERE key=$1", key).Scan(&gotGroup))
	require.True(t, gotGroup.Valid && gotGroup.Int64 == fallbackGid, "无订阅应绑定首个可绑定 standard 分组")
	// 排他分组不应被选中（未被 allowed）。
	var exclusiveCount int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM api_keys WHERE user_id=$1 AND group_id=$2", uid, exclusiveGid).Scan(&exclusiveCount))
	require.Equal(t, 0, exclusiveCount)
	// 重复领取仍返回同一把 Key（幂等）。
	again, err := svc.GetOrCreateManagedKey(ctx, uid, cid, true)
	require.NoError(t, err)
	require.Equal(t, key, again)
	// 只读 tokens:read 也能读取健康 Key。
	_, err = svc.GetOrCreateManagedKey(ctx, uid, cid, false)
	require.NoError(t, err)
	// 禁用该分组后重新领取：fallback 分组不可用且无可绑定分组 → NO_ELIGIBLE_GROUP。
	// 共享持久库：必须禁用所有 active standard 分组（含库自带的 default），前提才确定成立。
	_, err = db.Exec("UPDATE groups SET status='disabled' WHERE subscription_type='standard' AND status='active'")
	require.NoError(t, err)
	_, err = db.Exec("DELETE FROM oauth_managed_api_keys WHERE user_id=$1", uid)
	require.NoError(t, err)
	_, err = db.Exec("DELETE FROM api_keys WHERE user_id=$1", uid)
	require.NoError(t, err)
	_, err = svc.GetOrCreateManagedKey(ctx, uid, cid, true)
	require.ErrorIs(t, err, service.ErrOAuthNoEligibleGroup)
}
