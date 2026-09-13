package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthAuthorizationCode is a single-use authorization code issued after the user
// approves consent. Only the HMAC hash of the code is persisted; the raw code is
// never stored. `hash_key_version` records which HMAC key version produced the
// hash so it can be rotated without invalidating all outstanding codes.
type OAuthAuthorizationCode struct {
	ent.Schema
}

func (OAuthAuthorizationCode) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "oauth_authorization_codes"},
	}
}

func (OAuthAuthorizationCode) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (OAuthAuthorizationCode) Fields() []ent.Field {
	return []ent.Field{
		// HMAC hash of the authorization code. Raw code is never persisted.
		field.String("code_hash").
			MaxLen(255).
			NotEmpty().
			Unique(),
		field.String("redirect_uri").
			SchemaType(map[string]string{dialect.Postgres: "text"}).
			NotEmpty(),
		field.JSON("scopes", []string{}).
			Default(func() []string { return []string{} }).
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}),
		field.String("code_challenge").
			SchemaType(map[string]string{dialect.Postgres: "text"}).
			NotEmpty(),
		field.String("code_challenge_method").
			MaxLen(16).
			NotEmpty().
			Validate(validatePKCEChallengeMethod),
		// HMAC key version used to compute code_hash, enabling key rotation.
		field.Int("hash_key_version").
			Default(1),
		field.Time("expires_at").
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("consumed_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Int64("user_id"),
		field.Int64("client_id").
			Comment("Internal FK to oauth_clients.id."),
	}
}

func (OAuthAuthorizationCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("oauth_authorization_codes").
			Field("user_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.From("client", OAuthClient.Type).
			Ref("oauth_authorization_codes").
			Field("client_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}

func (OAuthAuthorizationCode) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code_hash").Unique(),
		index.Fields("user_id", "client_id"),
		index.Fields("expires_at"),
	}
}
