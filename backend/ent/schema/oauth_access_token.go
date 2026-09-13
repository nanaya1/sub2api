package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"
	"github.com/google/uuid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuthAccessToken is an opaque bearer token. Only the HMAC hash of the token is
// persisted; the raw token is never stored. Tokens belong to a refresh-token
// `family_id` so that reuse detection can revoke an entire family at once.
type OAuthAccessToken struct {
	ent.Schema
}

func (OAuthAccessToken) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "oauth_access_tokens"},
	}
}

func (OAuthAccessToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (OAuthAccessToken) Fields() []ent.Field {
	return []ent.Field{
		// HMAC hash of the access token. Raw token is never persisted.
		field.String("token_hash").
			MaxLen(255).
			NotEmpty().
			Unique(),
		// HMAC key version used to compute token_hash, enabling key rotation.
		field.Int("hash_key_version").
			Default(1),
		field.UUID("family_id", uuid.UUID{}).
			Comment("Refresh-token family this access token belongs to."),
		field.JSON("scopes", []string{}).
			Default(func() []string { return []string{} }).
			SchemaType(map[string]string{dialect.Postgres: "jsonb"}),
		field.Time("issued_at").
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("expires_at").
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("revoked_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Time("last_used_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.Int64("user_id"),
		field.Int64("client_id").
			Comment("Internal FK to oauth_clients.id."),
	}
}

func (OAuthAccessToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("oauth_access_tokens").
			Field("user_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
		edge.From("client", OAuthClient.Type).
			Ref("oauth_access_tokens").
			Field("client_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}

func (OAuthAccessToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("token_hash").Unique(),
		index.Fields("user_id", "client_id"),
		index.Fields("family_id"),
		index.Fields("expires_at"),
	}
}
