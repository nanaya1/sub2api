package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOAuthAuthorizationServerMigration verifies the Batch 1 OAuth schema
// migration file: it must create all seven tables, declare the required unique
// constraints and foreign keys, enforce PKCE S256 and a public-only client type,
// use timestamptz, and must NOT introduce a second copy of any API key
// ciphertext (encrypted_key_material).
//
// This is a static SQL-content test only; it does NOT apply the migration to a
// real database (no Postgres is started in this batch).
func TestOAuthAuthorizationServerMigration(t *testing.T) {
	const filename = "238_oauth_authorization_server.sql"

	contentBytes, err := FS.ReadFile(filename)
	require.NoError(t, err, "migration file %s must exist", filename)

	sql := strings.Join(strings.Fields(string(contentBytes)), " ")

	// Seven tables must be created.
	for _, table := range []string{
		"oauth_clients",
		"oauth_authorization_transactions",
		"oauth_authorization_codes",
		"oauth_consents",
		"oauth_access_tokens",
		"oauth_refresh_tokens",
		"oauth_managed_api_keys",
	} {
		require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS "+table+" (",
			"migration must create table %s", table)
	}

	// External client_id uniqueness on oauth_clients.
	require.Contains(t, sql, "client_id VARCHAR(128) NOT NULL UNIQUE")

	// Authorization-code / token hashes are unique; only hashes are stored.
	require.Contains(t, sql, "code_hash VARCHAR(255) NOT NULL UNIQUE")
	require.Contains(t, sql, "token_hash VARCHAR(255) NOT NULL UNIQUE")

	// Consent and managed key uniqueness.
	require.Contains(t, sql, "UNIQUE (user_id, client_id)")
	require.Contains(t, sql, "UNIQUE (api_key_id)")

	// Foreign keys to clients, users and api_keys, plus self-reference for tokens.
	require.Contains(t, sql, "REFERENCES oauth_clients(id)")
	require.Contains(t, sql, "REFERENCES users(id)")
	require.Contains(t, sql, "REFERENCES api_keys(id)")
	require.Contains(t, sql, "REFERENCES oauth_refresh_tokens(id)")

	// PKCE is restricted to S256.
	require.Contains(t, sql, "CHECK (code_challenge_method = 'S256')")

	// First phase only supports public clients.
	require.Contains(t, sql, "CHECK (client_type = 'public')")

	// JSON arrays must be non-empty.
	require.Contains(t, sql, "CHECK (jsonb_array_length(redirect_uris) > 0)")
	require.Contains(t, sql, "CHECK (jsonb_array_length(allowed_grant_types) > 0)")
	require.Contains(t, sql, "CHECK (jsonb_array_length(allowed_scopes) > 0)")

	// HMAC rotation key version column exists on hashed credential tables.
	require.Contains(t, sql, "hash_key_version INTEGER NOT NULL DEFAULT 1")

	// Timestamps use timestamptz.
	require.Contains(t, sql, "TIMESTAMPTZ")

	// Authorization transaction stores state verbatim (for OAuth state echo)
	// plus a separate browser session binding hash.
	require.Contains(t, sql, "state TEXT NOT NULL")
	require.Contains(t, sql, "browser_session_hash TEXT NOT NULL")

	// Security guard: do NOT add a second copy of the API key ciphertext in
	// this batch. Managed keys are stored as bindings (user+client+api_key) only.
	require.NotContains(t, sql, "encrypted_key_material",
		"batch 1 must not introduce a second API key ciphertext copy")
	require.NotContains(t, sql, "encryption_key_version",
		"batch 1 must not introduce key-encryption versioning without ciphertext")

	// No plaintext token/code columns.
	require.NotContains(t, sql, "access_token VARCHAR")
	require.NotContains(t, sql, "refresh_token VARCHAR")
	require.NotContains(t, sql, "authorization_code VARCHAR")
}
