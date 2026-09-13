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

// OAuthAuthorizationTransaction is the server-side, tamper-resistant record of a
// browser authorization flow. It is independent of the authorization code and is
// never revealed to the client except for its opaque `transaction_id` reference.
//
// The original OAuth `state` MUST be stored verbatim and echoed back to the
// client unchanged. It is NOT a secret, but it must never be written to logs.
// A separate `browser_session_hash` binds the transaction to the user's browser
// session so a transaction cannot be resumed from a different browser.
type OAuthAuthorizationTransaction struct {
	ent.Schema
}

func (OAuthAuthorizationTransaction) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "oauth_authorization_transactions"},
	}
}

func (OAuthAuthorizationTransaction) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (OAuthAuthorizationTransaction) Fields() []ent.Field {
	return []ent.Field{
		// Opaque, unpredictable reference handed to the browser. At least 256-bit entropy.
		field.String("transaction_id").
			MaxLen(128).
			NotEmpty().
			Unique(),
		field.String("redirect_uri").
			SchemaType(map[string]string{dialect.Postgres: "text"}).
			NotEmpty(),
		field.JSON("requested_scopes", []string{}).
			Default(func() []string { return []string{} }).
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}),
		// Original OAuth state, stored verbatim and echoed back to the client.
		// NOT a hash: the client needs the exact value. Never log this field.
		field.String("state").
			SchemaType(map[string]string{dialect.Postgres: "text"}).
			NotEmpty().
			Comment("Original OAuth state echoed back to the client; never logged."),
		field.String("code_challenge").
			SchemaType(map[string]string{dialect.Postgres: "text"}).
			NotEmpty(),
		field.String("code_challenge_method").
			MaxLen(16).
			NotEmpty().
			Validate(validatePKCEChallengeMethod),
		// Binds the transaction to the browser session; distinct from OAuth state.
		field.String("browser_session_hash").
			SchemaType(map[string]string{dialect.Postgres: "text"}).
			NotEmpty(),
		// Server-side CSRF token hash protecting the consent confirmation POST.
		field.String("csrf_token_hash").
			SchemaType(map[string]string{dialect.Postgres: "text"}).
			NotEmpty(),
		field.Int64("user_id").
			Optional().
			Nillable().
			Comment("Populated after the user authenticates; nullable until login completes."),
		field.String("status").
			MaxLen(16).
			Default("pending_login").
			Validate(validateOAuthTransactionStatus),
		field.Time("expires_at").
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("consumed_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Int64("client_id").
			Comment("Internal FK to oauth_clients.id, not the external client_id string."),
	}
}

func (OAuthAuthorizationTransaction) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("oauth_authorization_transactions").
			Field("user_id").
			Unique().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.From("client", OAuthClient.Type).
			Ref("oauth_authorization_transactions").
			Field("client_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}

func (OAuthAuthorizationTransaction) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("transaction_id").Unique(),
		index.Fields("status", "expires_at"),
		index.Fields("client_id", "created_at"),
		index.Fields("user_id", "client_id"),
	}
}

func validatePKCEChallengeMethod(value string) error {
	if value != "S256" {
		return fmt.Errorf("only PKCE method S256 is supported, got %q", value)
	}
	return nil
}

func validateOAuthTransactionStatus(value string) error {
	switch value {
	case "pending_login", "pending_consent", "approved", "denied", "consumed", "expired":
		return nil
	default:
		return fmt.Errorf("invalid oauth authorization transaction status %q", value)
	}
}
