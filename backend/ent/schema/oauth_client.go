package schema

import (
	"fmt"

	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthClient stores the OAuth 2.0 Authorization Server client registration.
//
// The externally visible client identifier is `client_id` (a stable string
// issued by the server). All other OAuth tables reference this row through the
// internal bigint primary key, never by copying the external string. This keeps
// the external string and the internal foreign key clearly distinct.
//
// Batch 1 only supports public clients (PKCE S256, no client secret), so the
// `client_type` column is constrained to 'public' and must not pretend to
// support confidential clients.
type OAuthClient struct {
	ent.Schema
}

func (OAuthClient) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "oauth_clients"},
	}
}

func (OAuthClient) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (OAuthClient) Fields() []ent.Field {
	return []ent.Field{
		// External client identifier (stable string issued by the server).
		field.String("client_id").
			MaxLen(128).
			NotEmpty().
			Unique().
			Comment("External OAuth client identifier; distinct from the internal bigint primary key referenced by foreign keys."),
		field.String("name").
			MaxLen(128).
			NotEmpty(),
		// First phase only supports public clients; see file-level doc comment.
		field.String("client_type").
			MaxLen(16).
			Default("public").
			Validate(validateOAuthClientType).
			Comment("OAuth client type. Batch 1 only allows 'public'."),
		field.JSON("redirect_uris", []string{}).
			Default(func() []string { return []string{} }).
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}).
			Comment("Allowed redirect URIs (exact string match required at runtime)."),
		field.JSON("allowed_grant_types", []string{}).
			Default(func() []string { return []string{} }).
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}),
		field.JSON("allowed_scopes", []string{}).
			Default(func() []string { return []string{} }).
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}),
		// Public clients cannot hold a secret, so PKCE is mandatory.
		field.Bool("require_pkce").
			Default(true).
			Comment("Public clients must use PKCE; always true in batch 1."),
		field.String("status").
			MaxLen(16).
			Default("active").
			Validate(validateOAuthClientStatus),
	}
}

func (OAuthClient) Edges() []ent.Edge {
	// Inverse edges for the foreign keys owned by the other OAuth tables.
	return []ent.Edge{
		edge.To("oauth_authorization_transactions", OAuthAuthorizationTransaction.Type).
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("oauth_authorization_codes", OAuthAuthorizationCode.Type).
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("oauth_consents", OAuthConsent.Type).
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("oauth_access_tokens", OAuthAccessToken.Type).
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("oauth_refresh_tokens", OAuthRefreshToken.Type).
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.To("oauth_managed_api_keys", OAuthManagedAPIKey.Type).
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}

func (OAuthClient) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_id").Unique(),
		index.Fields("status"),
	}
}

func validateOAuthClientType(value string) error {
	if value != "public" {
		return fmt.Errorf("oauth client_type %q is not supported in batch 1 (only 'public' is allowed)", value)
	}
	return nil
}

func validateOAuthClientStatus(value string) error {
	switch value {
	case "active", "disabled":
		return nil
	default:
		return fmt.Errorf("invalid oauth client status %q", value)
	}
}
