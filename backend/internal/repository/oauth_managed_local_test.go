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
	for _, update := range []string{"status='disabled'", "expires_at=NOW()-INTERVAL '1 second'", "deleted_at=NOW()", "quota=1,quota_used=1"} {
		_, err = db.Exec("UPDATE api_keys SET "+update+" WHERE user_id=$1", uid)
		require.NoError(t, err)
		k, e := svc.GetOrCreateManagedKey(ctx, uid, cid, true)
		require.ErrorIs(t, e, service.ErrOAuthManagedKeyUnavailable)
		require.Empty(t, k)
		_, err = db.Exec("UPDATE api_keys SET status='active',expires_at=NULL,deleted_at=NULL,quota=0,quota_used=0 WHERE user_id=$1", uid)
		require.NoError(t, err)
	}
	_, err = db.Exec("UPDATE user_subscriptions SET expires_at=NOW()-INTERVAL '1 second' WHERE user_id=$1", uid)
	require.NoError(t, err)
	_, err = svc.GetOrCreateManagedKey(ctx, uid, cid, true)
	require.ErrorIs(t, err, service.ErrOAuthNoActiveSubscription)
}
