package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOAuthRemoveOpenIDMigration(t *testing.T) {
	content, err := FS.ReadFile("239_remove_openid_from_oauth_server_clients.sql")
	require.NoError(t, err)
	sql := strings.Join(strings.Fields(string(content)), " ")
	require.Contains(t, sql, "UPDATE oauth_clients")
	require.Contains(t, sql, "allowed_scopes = allowed_scopes - 'openid'")
	require.Contains(t, sql, "WHERE allowed_scopes ? 'openid'")
}
