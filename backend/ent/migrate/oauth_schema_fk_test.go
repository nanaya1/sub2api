package migrate

import (
	"testing"

	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
	"github.com/stretchr/testify/require"
)

// TestOAuthServerMigrateSchema verifies the Batch 1 OAuth tables as represented
// by the generated ent/migrate schema: table names, foreign keys (including
// on-delete policy and referenced table), uniqueness, the external-string vs
// internal-FK distinction for client_id, and the absence of plaintext
// credential columns. This is a static schema test; it does not touch a database.
func TestOAuthServerMigrateSchema(t *testing.T) {
	// Table names.
	require.Equal(t, "oauth_clients", OauthClientsTable.Name)
	require.Equal(t, "oauth_authorization_transactions", OauthAuthorizationTransactionsTable.Name)
	require.Equal(t, "oauth_authorization_codes", OauthAuthorizationCodesTable.Name)
	require.Equal(t, "oauth_consents", OauthConsentsTable.Name)
	require.Equal(t, "oauth_access_tokens", OauthAccessTokensTable.Name)
	require.Equal(t, "oauth_refresh_tokens", OauthRefreshTokensTable.Name)
	require.Equal(t, "oauth_managed_api_keys", OauthManagedAPIKeysTable.Name)

	// External client_id (string) lives on oauth_clients; child tables reference
	// the internal bigint primary key via a column also named client_id.
	requireColumnType(t, OauthClientsTable, "client_id", field.TypeString)
	requireColumnType(t, OauthAuthorizationTransactionsTable, "client_id", field.TypeInt64)
	requireColumnType(t, OauthAuthorizationCodesTable, "client_id", field.TypeInt64)
	requireColumnType(t, OauthConsentsTable, "client_id", field.TypeInt64)
	requireColumnType(t, OauthAccessTokensTable, "client_id", field.TypeInt64)
	requireColumnType(t, OauthRefreshTokensTable, "client_id", field.TypeInt64)
	requireColumnType(t, OauthManagedAPIKeysTable, "client_id", field.TypeInt64)

	// No plaintext credential columns anywhere.
	requireNoPlaintextColumns(t, OauthAuthorizationCodesTable)
	requireNoPlaintextColumns(t, OauthAccessTokensTable)
	requireNoPlaintextColumns(t, OauthRefreshTokensTable)

	// family_id ties tokens together for rotation / reuse detection.
	requireColumnExists(t, OauthAccessTokensTable, "family_id")
	requireColumnExists(t, OauthRefreshTokensTable, "family_id")

	// HMAC rotation version column on hashed credentials.
	requireColumnExists(t, OauthAuthorizationCodesTable, "hash_key_version")

	// Authorization transaction stores state verbatim + browser session binding.
	requireColumnExists(t, OauthAuthorizationTransactionsTable, "state")
	requireColumnExists(t, OauthAuthorizationTransactionsTable, "browser_session_hash")
	requireColumnExists(t, OauthAuthorizationTransactionsTable, "csrf_token_hash")

	// ---- Foreign keys: client (cascade) ----
	requireFKOnDelete(t, OauthAuthorizationTransactionsTable,
		"oauth_authorization_transactions_oauth_clients_oauth_authorization_transactions", schema.Cascade, "oauth_clients")
	requireFKOnDelete(t, OauthAuthorizationCodesTable,
		"oauth_authorization_codes_oauth_clients_oauth_authorization_codes", schema.Cascade, "oauth_clients")
	requireFKOnDelete(t, OauthConsentsTable,
		"oauth_consents_oauth_clients_oauth_consents", schema.Cascade, "oauth_clients")
	requireFKOnDelete(t, OauthAccessTokensTable,
		"oauth_access_tokens_oauth_clients_oauth_access_tokens", schema.Cascade, "oauth_clients")
	requireFKOnDelete(t, OauthRefreshTokensTable,
		"oauth_refresh_tokens_oauth_clients_oauth_refresh_tokens", schema.Cascade, "oauth_clients")
	requireFKOnDelete(t, OauthManagedAPIKeysTable,
		"oauth_managed_api_keys_oauth_clients_oauth_managed_api_keys", schema.Cascade, "oauth_clients")

	// ---- Foreign keys: user (cascade) ----
	requireFKOnDelete(t, OauthAuthorizationTransactionsTable,
		"oauth_authorization_transactions_users_oauth_authorization_transactions", schema.Cascade, "users")
	requireFKOnDelete(t, OauthAuthorizationCodesTable,
		"oauth_authorization_codes_users_oauth_authorization_codes", schema.Cascade, "users")
	requireFKOnDelete(t, OauthConsentsTable,
		"oauth_consents_users_oauth_consents", schema.Cascade, "users")
	requireFKOnDelete(t, OauthAccessTokensTable,
		"oauth_access_tokens_users_oauth_access_tokens", schema.Cascade, "users")
	requireFKOnDelete(t, OauthRefreshTokensTable,
		"oauth_refresh_tokens_users_oauth_refresh_tokens", schema.Cascade, "users")
	requireFKOnDelete(t, OauthManagedAPIKeysTable,
		"oauth_managed_api_keys_users_oauth_managed_api_keys", schema.Cascade, "users")

	// ---- Foreign keys: api_key (cascade) on managed keys ----
	requireFKOnDelete(t, OauthManagedAPIKeysTable,
		"oauth_managed_api_keys_api_keys_oauth_managed_api_keys", schema.Cascade, "api_keys")

	// ---- Refresh token rotation lineage: self-references with SET NULL ----
	requireFKOnDelete(t, OauthRefreshTokensTable,
		"oauth_refresh_tokens_oauth_refresh_tokens_child_tokens", schema.SetNull, "oauth_refresh_tokens")
	requireFKOnDelete(t, OauthRefreshTokensTable,
		"oauth_refresh_tokens_oauth_refresh_tokens_replaced_tokens", schema.SetNull, "oauth_refresh_tokens")

	// ---- Uniqueness ----
	requireUniqueIndexColumns(t, OauthClientsTable, "client_id")
	requireUniqueIndexColumns(t, OauthAuthorizationTransactionsTable, "transaction_id")
	requireUniqueIndexColumns(t, OauthAuthorizationCodesTable, "code_hash")
	requireUniqueIndexColumns(t, OauthAccessTokensTable, "token_hash")
	requireUniqueIndexColumns(t, OauthRefreshTokensTable, "token_hash")
	requireUniqueIndexColumns(t, OauthConsentsTable, "user_id", "client_id")
	requireUniqueIndexColumns(t, OauthManagedAPIKeysTable, "user_id", "client_id")
	requireUniqueIndexColumns(t, OauthManagedAPIKeysTable, "api_key_id")
}

func requireColumnExists(t *testing.T, table *schema.Table, name string) {
	t.Helper()
	require.NotNil(t, findColumn(t, table, name), "table %s should include column %s", table.Name, name)
}

func findColumn(t *testing.T, table *schema.Table, name string) *schema.Column {
	t.Helper()
	for _, col := range table.Columns {
		if col.Name == name {
			return col
		}
	}
	return nil
}

func requireColumnType(t *testing.T, table *schema.Table, name string, typ field.Type) {
	t.Helper()
	col := findColumn(t, table, name)
	require.NotNil(t, col, "table %s should include column %s", table.Name, name)
	require.Equal(t, typ, col.Type, "column %s.%s type", table.Name, name)
}

func requireNoPlaintextColumns(t *testing.T, table *schema.Table) {
	t.Helper()

	plaintext := map[string]struct{}{
		"code":                   {},
		"authorization_code":     {},
		"token":                  {},
		"access_token":           {},
		"refresh_token":          {},
		"encrypted_key_material": {},
		"encryption_key_version": {},
	}
	for _, col := range table.Columns {
		_, bad := plaintext[col.Name]
		require.Falsef(t, bad, "table %s must not store plaintext column %q", table.Name, col.Name)
	}
}

func requireFKOnDelete(t *testing.T, table *schema.Table, symbol string, onDelete schema.ReferenceOption, refTableName string) {
	t.Helper()

	fk := findForeignKeyBySymbol(t, table, symbol)
	require.Equal(t, onDelete, fk.OnDelete, "fk %s on delete", symbol)
	require.NotNil(t, fk.RefTable, "fk %s should reference a table", symbol)
	require.Equal(t, refTableName, fk.RefTable.Name, "fk %s referenced table", symbol)
}

func requireUniqueIndexColumns(t *testing.T, table *schema.Table, columns ...string) {
	t.Helper()

	for _, idx := range table.Indexes {
		if !idx.Unique {
			continue
		}
		if len(idx.Columns) != len(columns) {
			continue
		}
		match := true
		for i := range columns {
			if idx.Columns[i].Name != columns[i] {
				match = false
				break
			}
		}
		if match {
			return
		}
	}

	require.Failf(t, "missing unique index", "table %s should include unique index on %v", table.Name, columns)
}
