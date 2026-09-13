package schema

import (
	"testing"

	"entgo.io/ent/entc/load"
	"github.com/stretchr/testify/require"
)

// TestOAuthServerSchemas verifies the Batch 1 OAuth Authorization Server Ent
// schemas exist with the required fields, uniqueness constraints, PKCE
// constraints and that no plaintext token/code columns are present.
//
// This file intentionally lives in package `schema` and uses entc/load so it
// can run without any generated ent/migrate code and without a database.
func TestOAuthServerSchemas(t *testing.T) {
	spec, err := (&load.Config{Path: "."}).Load()
	require.NoError(t, err)

	schemas := map[string]*load.Schema{}
	for _, schema := range spec.Schemas {
		schemas[schema.Name] = schema
	}

	requireSchema(t, schemas, "OAuthClient")
	requireSchema(t, schemas, "OAuthAuthorizationTransaction")
	requireSchema(t, schemas, "OAuthAuthorizationCode")
	requireSchema(t, schemas, "OAuthConsent")
	requireSchema(t, schemas, "OAuthAccessToken")
	requireSchema(t, schemas, "OAuthRefreshToken")
	requireSchema(t, schemas, "OAuthManagedAPIKey")

	// ---- OAuthClient ----
	client := requireSchema(t, schemas, "OAuthClient")
	requireSchemaFields(t, client,
		"client_id", "name", "client_type",
		"redirect_uris", "allowed_grant_types", "allowed_scopes",
		"require_pkce", "status",
	)
	// External client_id is a string; internal FKs live on child tables.
	requireFieldType(t, client, "client_id", "string")
	requireSchemaFieldUnique(t, client, "client_id")
	// First phase only supports public clients: do not pretend confidential.
	requireFieldHasValidator(t, client, "client_type")

	// ---- OAuthAuthorizationTransaction ----
	txn := requireSchema(t, schemas, "OAuthAuthorizationTransaction")
	requireSchemaFields(t, txn,
		"transaction_id", "redirect_uri", "requested_scopes",
		"state", "code_challenge", "code_challenge_method",
		"browser_session_hash", "csrf_token_hash",
		"user_id", "status", "expires_at", "consumed_at", "client_id",
	)
	requireSchemaFieldUnique(t, txn, "transaction_id")
	// state must be stored verbatim (echoed back to the client), NOT a hash.
	requireFieldType(t, txn, "state", "string")
	// Separate browser binding hash.
	requireFieldType(t, txn, "browser_session_hash", "string")
	// PKCE method is restricted to S256.
	requireFieldHasValidator(t, txn, "code_challenge_method")

	// ---- OAuthAuthorizationCode ----
	code := requireSchema(t, schemas, "OAuthAuthorizationCode")
	requireSchemaFields(t, code,
		"code_hash", "redirect_uri", "scopes",
		"code_challenge", "code_challenge_method",
		"hash_key_version", "expires_at", "consumed_at",
		"user_id", "client_id",
	)
	requireSchemaFieldUnique(t, code, "code_hash")
	// Hash key version enables HMAC rotation of stored hashes.
	requireFieldType(t, code, "hash_key_version", "int")
	requireFieldHasValidator(t, code, "code_challenge_method")

	// ---- OAuthConsent ----
	consent := requireSchema(t, schemas, "OAuthConsent")
	requireSchemaFields(t, consent,
		"user_id", "client_id", "scopes", "revoked_at",
	)
	requireHasUniqueIndex(t, consent, "user_id", "client_id")

	// ---- OAuthAccessToken ----
	access := requireSchema(t, schemas, "OAuthAccessToken")
	requireSchemaFields(t, access,
		"token_hash", "hash_key_version", "family_id", "scopes",
		"issued_at", "expires_at", "revoked_at", "last_used_at",
		"user_id", "client_id",
	)
	requireSchemaFieldUnique(t, access, "token_hash")
	requireFieldType(t, access, "hash_key_version", "int")

	// ---- OAuthRefreshToken ----
	refresh := requireSchema(t, schemas, "OAuthRefreshToken")
	requireSchemaFields(t, refresh,
		"token_hash", "hash_key_version", "family_id",
		"parent_token_id", "replaced_by_token_id",
		"scopes", "issued_at", "expires_at", "idle_expires_at",
		"last_used_at", "revoked_at",
		"user_id", "client_id",
	)
	requireSchemaFieldUnique(t, refresh, "token_hash")
	requireFieldType(t, refresh, "hash_key_version", "int")

	// ---- OAuthManagedAPIKey ----
	managed := requireSchema(t, schemas, "OAuthManagedAPIKey")
	requireSchemaFields(t, managed,
		"user_id", "client_id", "api_key_id", "revoked_at",
	)
	requireHasUniqueIndex(t, managed, "user_id", "client_id")
	requireHasUniqueIndex(t, managed, "api_key_id")

	// ---- No plaintext token/code columns anywhere ----
	requireNoPlaintextCredentialColumns(t, schemas)
}

// requireFieldType asserts the schema field has the expected underlying type name.
func requireFieldType(t *testing.T, schema *load.Schema, name, typ string) {
	t.Helper()

	f := requireSchemaField(t, schema, name)
	require.NotNil(t, f.Info, "field %s.%s should have type info", schema.Name, name)
	require.Equal(t, typ, f.Info.Type.String(), "field %s.%s type", schema.Name, name)
}

// requireFieldHasValidator asserts a field declares at least one validator.
func requireFieldHasValidator(t *testing.T, schema *load.Schema, name string) {
	t.Helper()

	f := requireSchemaField(t, schema, name)
	require.Greater(t, f.Validators, 0, "field %s.%s should declare a validator", schema.Name, name)
}

// requireSchemaFieldUnique asserts the named field carries a unique constraint.
func requireSchemaFieldUnique(t *testing.T, schema *load.Schema, name string) {
	t.Helper()

	for _, f := range schema.Fields {
		if f.Name == name {
			require.True(t, f.Unique, "field %s.%s should be unique", schema.Name, name)
			return
		}
	}
	require.Failf(t, "missing schema field", "schema %s should include field %s", schema.Name, name)
}

// requireNoPlaintextCredentialColumns ensures sensitive objects only store
// hashes and never the raw code/token.
func requireNoPlaintextCredentialColumns(t *testing.T, schemas map[string]*load.Schema) {
	t.Helper()

	plaintext := map[string][]string{
		"OAuthAuthorizationCode": {"code", "authorization_code", "code_plain"},
		"OAuthAccessToken":       {"token", "access_token", "access_token_plain"},
		"OAuthRefreshToken":      {"token", "refresh_token", "refresh_token_plain"},
	}
	for schemaName, badFields := range plaintext {
		schema, ok := schemas[schemaName]
		require.True(t, ok, "schema %s must exist", schemaName)
		for _, f := range schema.Fields {
			for _, bad := range badFields {
				require.NotEqual(t, bad, f.Name,
					"%s must not store plaintext column %q (use a hash column instead)", schemaName, bad)
			}
		}
	}
}
